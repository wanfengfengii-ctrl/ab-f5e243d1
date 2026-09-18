package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"telemetry/internal/canonical"
	"telemetry/internal/envelope"
	"telemetry/internal/render"
	"telemetry/internal/store"
)

// ingestRequestWire is the batch endpoint request body.
type ingestRequestWire struct {
	RequestID string            `json:"requestId"`
	Events    []ingestEventWire `json:"events"`
}

type ingestEventWire struct {
	DeviceID   string          `json:"deviceId"`
	Sequence   int64           `json:"sequence"`
	EventID    string          `json:"eventId"`
	OccurredAt string          `json:"occurredAt"`
	KeyVersion int             `json:"keyVersion"`
	PrevDigest string          `json:"prevDigest"`
	Payload    json.RawMessage `json:"payload"`
	Signature  string          `json:"signature"`
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	var req ingestRequestWire
	if !decodeJSONBody(w, r, s.Cfg.MaxBodyBytes, &req) {
		return
	}
	if req.RequestID == "" || len(req.RequestID) > 200 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"requestId is required and must be at most 200 characters")
		return
	}
	if len(req.Events) < 1 || len(req.Events) > 500 {
		writePlainError(w, http.StatusBadRequest, store.CodeBatchInvalid,
			"a batch must contain between 1 and 500 events")
		return
	}

	in := &store.IngestInput{RequestID: req.RequestID, DeviceID: deviceID}
	in.Events = make([]store.IngestEvent, 0, len(req.Events))
	seenSeq := map[int64]struct{}{}

	// Phase A: deterministic, side-effect-free parsing and normalization. Any
	// failure here is a property of the document itself and reproduces
	// identically on retry; nothing has been persisted.
	parts := make([]contentPart, 0, len(req.Events))

	for i, we := range req.Events {
		if we.DeviceID != deviceID {
			writePlainError(w, http.StatusBadRequest, store.CodeBatchMixedDevices,
				"event at index "+strconv.Itoa(i)+" has deviceId "+we.DeviceID+
					", which does not match the URL deviceId "+deviceID)
			return
		}
		if we.Sequence < 1 {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"sequence must be >= 1 at index "+strconv.Itoa(i))
			return
		}
		if _, dup := seenSeq[we.Sequence]; dup {
			writePlainError(w, http.StatusBadRequest, store.CodeBatchDuplicate,
				"duplicate sequence "+strconv.FormatInt(we.Sequence, 10)+" within the batch")
			return
		}
		seenSeq[we.Sequence] = struct{}{}
		if we.EventID == "" || len(we.EventID) > 200 {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"eventId is required and must be at most 200 characters at index "+strconv.Itoa(i))
			return
		}
		if we.KeyVersion < 1 {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"keyVersion must be >= 1 at index "+strconv.Itoa(i))
			return
		}
		if we.PrevDigest == "" {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"prevDigest is required at index "+strconv.Itoa(i))
			return
		}
		occ, err := time.Parse(time.RFC3339Nano, we.OccurredAt)
		if err != nil {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"occurredAt must be RFC 3339 date-time at index "+strconv.Itoa(i)+": "+err.Error())
			return
		}
		occ = occ.UTC()
		payloadCanon, err := envelope.CanonicalPayload(we.Payload)
		if err != nil {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"invalid payload at index "+strconv.Itoa(i)+": "+err.Error())
			return
		}
		sig, err := b64decode(we.Signature)
		if err != nil || len(sig) != 64 {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"signature must be base64 of 64 bytes at index "+strconv.Itoa(i))
			return
		}
		ev := &envelope.Event{
			DeviceID:   we.DeviceID,
			Sequence:   we.Sequence,
			EventID:    we.EventID,
			OccurredAt: occ,
			KeyVersion: we.KeyVersion,
			PrevDigest: we.PrevDigest,
			Payload:    we.Payload,
		}
		dg, err := envelope.ComputeDigest(ev, payloadCanon)
		if err != nil {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"digest computation failed at index "+strconv.Itoa(i)+": "+err.Error())
			return
		}
		signingBytes, err := envelope.SigningBytes(ev, payloadCanon)
		if err != nil {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"signing envelope failed at index "+strconv.Itoa(i)+": "+err.Error())
			return
		}
		in.Events = append(in.Events, store.IngestEvent{
			Event: store.Event{
				DeviceID:   we.DeviceID,
				Sequence:   we.Sequence,
				EventID:    we.EventID,
				KeyVersion: we.KeyVersion,
				PrevDigest: we.PrevDigest,
				Signature:  sig,
			},
			PayloadCanonical: payloadCanon,
			Digest:           dg.String(),
			OccurredAtCanon:  occ.Format(time.RFC3339Nano),
			SigningInput:     signingBytes,
		})
		parts = append(parts, contentPart{digest: dg.String(), sig: sig})
	}

	// Phase B: content hash is over the deviceId plus the order-independent
	// multiset of (digest, signature) pairs, canonically encoded. It does not
	// depend on JSON whitespace, member order, or the order events appear in
	// the request array.
	in.ContentHash = requestContentHash(deviceID, parts)

	build := func(res *store.IngestResult, se *store.Error) store.Terminal {
		if se != nil {
			return store.Terminal{Status: render.HTTPStatusFor(se), Body: render.MustRenderError(se)}
		}
		body := map[string]any{
			"requestId":               in.RequestID,
			"deviceId":                deviceID,
			"contiguousHighWatermark": res.HighWatermark,
			"conflictRevision":        res.ConflictRev,
			"storedSequences":         res.Stored,
			"duplicateSequences":      res.Duplicates,
			"advancedSequences":       res.Advanced,
			"conflicts":               conflictsToAPI(res.Conflicts),
		}
		raw, _ := json.Marshal(body)
		return store.Terminal{Status: http.StatusOK, Body: raw}
	}

	term, _, err := s.Store.Ingest(r.Context(), in, build)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(term.Status)
	_, _ = w.Write(term.Body)
}

// contentPart is one event's contribution to the request content hash.
type contentPart struct {
	digest string
	sig    []byte
}

// requestContentHash derives the stable content hash of an ingest request.
func requestContentHash(deviceID string, parts []contentPart) [32]byte {
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].digest != parts[j].digest {
			return parts[i].digest < parts[j].digest
		}
		return string(parts[i].sig) < string(parts[j].sig)
	})
	members := make([]canonical.Member, 0, len(parts)+1)
	members = append(members, canonical.Member{Key: "deviceId", Value: deviceID})
	arr := make([]any, 0, len(parts))
	for _, p := range parts {
		arr = append(arr, &canonical.Object{Members: []canonical.Member{
			{Key: "digest", Value: p.digest},
			{Key: "signature", Value: base64.StdEncoding.EncodeToString(p.sig)},
		}})
	}
	members = append(members, canonical.Member{Key: "events", Value: arr})
	doc := canonical.MustEncode(&canonical.Object{Members: members})
	return sha256.Sum256(doc)
}
