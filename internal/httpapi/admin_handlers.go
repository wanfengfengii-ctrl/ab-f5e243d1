package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strconv"

	"telemetry/internal/canonical"
	"telemetry/internal/store"
)

// rotateRequest is the key rotation command body.
type rotateRequest struct {
	CommandID               string `json:"commandId"`
	KeyVersion              int    `json:"keyVersion"`
	PublicKey               string `json:"publicKey"`
	EffectiveSequence       int64  `json:"effectiveSequence"`
	ExpectedControlRevision int64  `json:"expectedControlRevision"`
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	var req rotateRequest
	if !decodeJSONBody(w, r, s.Cfg.MaxBodyBytes, &req) {
		return
	}
	if req.CommandID == "" || len(req.CommandID) > 200 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation, "commandId is required")
		return
	}
	if req.KeyVersion < 2 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"keyVersion must be >= 2 (version 1 is the registration key)")
		return
	}
	if req.EffectiveSequence < 1 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"effectiveSequence must be >= 1")
		return
	}
	pub, err := decodePublicKey(req.PublicKey)
	if err != nil {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"publicKey must be base64 of 32 Ed25519 public key bytes: "+err.Error())
		return
	}
	hash := commandContentHash("rotate_key", map[string]any{
		"deviceId":                deviceID,
		"keyVersion":              req.KeyVersion,
		"publicKey":               req.PublicKey,
		"effectiveSequence":       req.EffectiveSequence,
		"expectedControlRevision": req.ExpectedControlRevision,
	})

	out, err := s.Store.RotateKeyAdmin(r.Context(), req.CommandID, deviceID, hash,
		req.KeyVersion, pub, req.EffectiveSequence, req.ExpectedControlRevision,
		func(res *store.RotateKeyResult) (int, json.RawMessage, *store.Error) {
			body, _ := json.Marshal(map[string]any{
				"commandId":       req.CommandID,
				"deviceId":        deviceID,
				"controlRevision": res.Device.ControlRevision,
				"key": keyResponse{
					KeyVersion:        res.Key.KeyVersion,
					PublicKey:         encodeKey(res.Key.PublicKey),
					EffectiveSequence: res.Key.EffectiveSequence,
				},
			})
			return http.StatusOK, body, nil
		})
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(out.Status)
	_, _ = w.Write(out.Body)
}

// adjudicateRequest is the conflict resolution command body.
type adjudicateRequest struct {
	CommandID                string `json:"commandId"`
	ExpectedConflictRevision int64  `json:"expectedConflictRevision"`
	Decision                 string `json:"decision"`
	CandidateDigest          string `json:"candidateDigest"`
}

func (s *Server) handleAdjudicate(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || seq < 1 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation, "sequence must be >= 1")
		return
	}
	var req adjudicateRequest
	if !decodeJSONBody(w, r, s.Cfg.MaxBodyBytes, &req) {
		return
	}
	if req.CommandID == "" || len(req.CommandID) > 200 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation, "commandId is required")
		return
	}
	if req.Decision != store.DecisionChooseCandidate && req.Decision != store.DecisionRejectAll {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"decision must be choose_candidate or reject_all")
		return
	}
	hash := commandContentHash("adjudicate", map[string]any{
		"deviceId":                 deviceID,
		"sequence":                 seq,
		"expectedConflictRevision": req.ExpectedConflictRevision,
		"decision":                 req.Decision,
		"candidateDigest":          req.CandidateDigest,
	})

	out, err := s.Store.Adjudicate(r.Context(), req.CommandID, deviceID, hash,
		seq, req.ExpectedConflictRevision, req.Decision, req.CandidateDigest,
		func(res *store.AdjudicationResult) (int, json.RawMessage, *store.Error) {
			body, _ := json.Marshal(map[string]any{
				"commandId":               req.CommandID,
				"deviceId":                deviceID,
				"sequence":                seq,
				"decision":                req.Decision,
				"chosenDigest":            res.ChosenDigest,
				"advancedSequences":       res.Advanced,
				"contiguousHighWatermark": res.HighWatermark,
				"conflictRevision":        res.ConflictRev,
				"reopenedAs":              res.ConflictReopener,
			})
			return http.StatusOK, body, nil
		})
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(out.Status)
	_, _ = w.Write(out.Body)
}

func (s *Server) handleListConflicts(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	cs, err := s.Store.ListOpenConflicts(r.Context(), deviceID)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":  deviceID,
		"conflicts": conflictsToAPI(cs),
	})
}

func (s *Server) handleGetConflict(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || seq < 1 {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation, "sequence must be >= 1")
		return
	}
	c, err := s.Store.GetConflict(r.Context(), deviceID, seq)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId": deviceID,
		"conflict": conflictToAPI(*c),
	})
}

// commandContentHash hashes the canonical command document, prefixed by its
// type so commandIds cannot be borrowed across command kinds.
func commandContentHash(commandType string, doc map[string]any) [32]byte {
	members := make([]canonical.Member, 0, len(doc)+1)
	members = append(members, canonical.Member{Key: "commandType", Value: commandType})
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		members = append(members, canonical.Member{Key: k, Value: canonicalizeValue(doc[k])})
	}
	return sha256.Sum256(canonical.MustEncode(&canonical.Object{Members: members}))
}

func canonicalizeValue(v any) any {
	raw, _ := json.Marshal(v)
	out, err := canonicalFromJSON(raw)
	if err != nil {
		panic(err)
	}
	return out
}
