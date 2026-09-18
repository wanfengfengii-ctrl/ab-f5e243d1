package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"telemetry/internal/cursor"
	"telemetry/internal/store"
)

// eventWire is the reader-facing event projection.
func eventToAPI(e store.EventRecord) map[string]any {
	var payload any
	if err := json.Unmarshal(e.PayloadCanonical, &payload); err != nil {
		payload = json.RawMessage(e.PayloadCanonical)
	}
	return map[string]any{
		"deviceId":   e.DeviceID,
		"sequence":   e.Sequence,
		"digest":     e.Digest,
		"eventId":    e.EventID,
		"occurredAt": e.OccurredAt,
		"keyVersion": e.KeyVersion,
		"prevDigest": e.PrevDigest,
		"payload":    payload,
		"signature":  base64.StdEncoding.EncodeToString(e.Signature),
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	limit := s.Cfg.DefaultPageSize
	if ls := r.URL.Query().Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > s.Cfg.MaxPageSize {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"limit must be between 1 and "+strconv.Itoa(s.Cfg.MaxPageSize))
			return
		}
		limit = n
	}

	tok := r.URL.Query().Get("cursor")
	if tok == "" {
		// Open a fresh fixed view, optionally at a start position.
		var startAfter int64
		if sp := r.URL.Query().Get("startAfterSequence"); sp != "" {
			n, err := strconv.ParseInt(sp, 10, 64)
			if err != nil || n < 0 {
				writePlainError(w, http.StatusBadRequest, store.CodeValidation,
					"startAfterSequence must be a non-negative integer")
				return
			}
			startAfter = n
		}
		v, err := s.Store.CreateView(r.Context(), deviceID, startAfter, s.Cfg.ViewTTL)
		if err != nil {
			s.writeReadError(w, r, deviceID, err)
			return
		}
		s.servePage(w, r, deviceID, v.ID, startAfter, limit)
		return
	}

	cl, err := s.Cursors.Open(tok)
	if err != nil {
		writePlainError(w, http.StatusBadRequest, store.CodeCursorInvalid,
			"invalid or tampered cursor: "+err.Error())
		return
	}
	if cl.DeviceID != deviceID {
		writePlainError(w, http.StatusBadRequest, store.CodeCursorInvalid,
			"cursor is bound to a different device")
		return
	}
	if sp := r.URL.Query().Get("startAfterSequence"); sp != "" {
		writePlainError(w, http.StatusBadRequest, store.CodeCursorInvalid,
			"startAfterSequence cannot be combined with a cursor")
		return
	}
	s.servePage(w, r, deviceID, cl.ViewID, cl.Position, limit)
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request,
	deviceID, viewID string, position int64, limit int) {
	page, err := s.Store.ReadPage(r.Context(), viewID, deviceID, position, limit)
	if err != nil {
		s.writeReadError(w, r, deviceID, err)
		return
	}
	events := make([]map[string]any, 0, len(page.Events))
	for _, e := range page.Events {
		events = append(events, eventToAPI(e))
	}
	resp := map[string]any{
		"deviceId":          deviceID,
		"viewId":            viewID,
		"viewHighWatermark": page.View.HighWatermark,
		"events":            events,
	}
	if page.HasNext {
		next, err := s.Cursors.Seal(cursor.Claims{
			DeviceID: deviceID, ViewID: viewID, Position: page.NextPosition,
			IssuedAtMS: time.Now().UnixMilli(),
		})
		if err != nil {
			writeStoreError(w, r, s.Logger, err)
			return
		}
		resp["nextCursor"] = next
	} else {
		resp["nextCursor"] = nil
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeReadError enriches 410 responses with the verifiable checkpoint and a
// concrete resume point.
func (s *Server) writeReadError(w http.ResponseWriter, r *http.Request, deviceID string, err error) {
	var se *store.Error
	if !asStoreError(err, &se) || (se.Code != store.CodeBeforeCheckpoint &&
		se.Code != store.CodeCursorStale && se.Code != store.CodeViewExpired) {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	cp, cerr := s.Store.GetCheckpoint(r.Context(), deviceID)
	if cerr != nil || cp == nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	se.Code = store.CodeBeforeCheckpoint
	se.Message = "cursor is behind the durable checkpoint; verify the supplied checkpoint and resume from resumeFromSequence"
	se.Details = map[string]any{
		"resumeFromSequence": cp.Sequence + 1,
		"checkpoint":         checkpointToAPI(cp),
	}
	writeErrorBody(w, http.StatusGone, se)
}

func (s *Server) handleWait(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	after, err := strconv.ParseInt(r.URL.Query().Get("afterSequence"), 10, 64)
	if err != nil || after < 0 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"afterSequence must be a non-negative integer")
		return
	}
	timeoutSec := 30
	if ts := r.URL.Query().Get("timeoutSeconds"); ts != "" {
		n, err := strconv.Atoi(ts)
		if err != nil || n < 0 || n > s.Cfg.WaitMaxSeconds {
			writePlainError(w, http.StatusBadRequest, store.CodeTimeoutInvalid,
				"timeoutSeconds must be between 0 and "+strconv.Itoa(s.Cfg.WaitMaxSeconds))
			return
		}
		timeoutSec = n
	}
	limit := s.Cfg.DefaultPageSize
	if ls := r.URL.Query().Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > s.Cfg.MaxPageSize {
			writePlainError(w, http.StatusBadRequest, store.CodeValidation,
				"limit must be between 1 and "+strconv.Itoa(s.Cfg.MaxPageSize))
			return
		}
		limit = n
	}

	// Bound waiting by both the client timeout and the server request
	// context: a disconnect cancels r.Context() (the parent of ctx), which
	// interrupts WaitForNotification and releases the DB connection.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	res, notified, err := s.Store.WaitForEvents(ctx, deviceID, after, time.Now().Add(
		time.Duration(timeoutSec)*time.Second), limit)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	events := make([]map[string]any, 0, len(res.Events))
	for _, e := range res.Events {
		events = append(events, eventToAPI(e))
	}
	status := http.StatusOK
	if !notified {
		status = http.StatusOK // timeout: empty events, still 200
	}
	writeJSON(w, status, map[string]any{
		"deviceId":                deviceID,
		"afterSequence":           after,
		"contiguousHighWatermark": res.HighWatermark,
		"timedOut":                !notified,
		"events":                  events,
	})
}

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	cp, err := s.Store.GetCheckpoint(r.Context(), deviceID)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	if cp == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"deviceId":   deviceID,
			"checkpoint": nil,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":   deviceID,
		"checkpoint": checkpointToAPI(cp),
	})
}

func (s *Server) handleCheckpointKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keyVersion": 1,
		"algorithm":  "Ed25519",
		"publicKey":  base64.StdEncoding.EncodeToString(s.SrvKey.Public()),
	})
}

// handleCompactNow triggers one immediate compaction pass for a device.
func (s *Server) handleCompactNow(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	var req struct {
		KeepRecent         *int64 `json:"keepRecent"`
		MinEventAgeSeconds *int64 `json:"minEventAgeSeconds"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, s.Cfg.MaxBodyBytes))
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writePlainError(w, http.StatusBadRequest, store.CodeInvalidJSON, err.Error())
			return
		}
	}
	keepRecent := s.Cfg.CompactionCutoff
	if req.KeepRecent != nil {
		keepRecent = *req.KeepRecent
	}
	minEventAge := s.Cfg.CompactionMinAge
	if req.MinEventAgeSeconds != nil {
		minEventAge = time.Duration(*req.MinEventAgeSeconds) * time.Second
	}
	res, err := s.Store.CompactDevice(r.Context(), deviceID, store.CompactionPolicy{
		KeepRecent:  keepRecent,
		MinEventAge: minEventAge,
	}, func(doc store.CheckpointDoc) (string, error) {
		payload, err := store.CheckpointSignPayload(doc)
		if err != nil {
			return "", err
		}
		return s.SrvKey.Sign(payload), nil
	})
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	respBody := map[string]any{
		"deviceId":           deviceID,
		"compacted":          res.Compacted,
		"previousCheckpoint": res.PreviousSeq,
		"checkpointSequence": res.CutoffSequence,
		"checkpointDigest":   res.CutoffDigest,
		"deletedEvents":      res.DeletedRows,
	}
	writeJSON(w, http.StatusOK, respBody)
}
