package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"

	"telemetry/internal/store"
)

// registerRequest is the device registration body.
type registerRequest struct {
	DeviceID  string `json:"deviceId"`
	PublicKey string `json:"publicKey"` // base64 of 32 raw Ed25519 bytes
}

// keyResponse renders one key generation.
type keyResponse struct {
	KeyVersion        int    `json:"keyVersion"`
	PublicKey         string `json:"publicKey"`
	EffectiveSequence int64  `json:"effectiveSequence"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSONBody(w, r, s.Cfg.MaxBodyBytes, &req) {
		return
	}
	if req.DeviceID == "" {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation, "deviceId is required")
		return
	}
	pub, err := decodePublicKey(req.PublicKey)
	if err != nil {
		writePlainError(w, http.StatusBadRequest, store.CodeValidation,
			"publicKey must be base64 of 32 Ed25519 public key bytes: "+err.Error())
		return
	}
	d, k, err := s.Store.RegisterDevice(r.Context(), req.DeviceID, pub)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"deviceId":                d.ID,
		"controlRevision":         d.ControlRevision,
		"conflictRevision":        d.ConflictRevision,
		"contiguousHighWatermark": d.HWM,
		"checkpointSequence":      d.CheckpointSeq,
		"createdAt":               d.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"keys": []keyResponse{{
			KeyVersion:        k.KeyVersion,
			PublicKey:         encodeKey(k.PublicKey),
			EffectiveSequence: k.EffectiveSequence,
		}},
	})
}

func (s *Server) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	st, err := s.Store.DeviceStatus(r.Context(), deviceID)
	if err != nil {
		writeStoreError(w, r, s.Logger, err)
		return
	}
	keys := make([]keyResponse, 0, len(st.Keys))
	for _, k := range st.Keys {
		keys = append(keys, keyResponse{
			KeyVersion:        k.KeyVersion,
			PublicKey:         encodeKey(k.PublicKey),
			EffectiveSequence: k.EffectiveSequence,
		})
	}
	resp := map[string]any{
		"deviceId":                st.Device.ID,
		"controlRevision":         st.Device.ControlRevision,
		"conflictRevision":        st.Device.ConflictRevision,
		"contiguousHighWatermark": st.Device.HWM,
		"checkpointSequence":      st.Device.CheckpointSeq,
		"createdAt":               st.Device.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"keys":                    keys,
		"openConflictCount":       len(st.OpenConflicts),
		"openConflicts":           conflictsToAPI(st.OpenConflicts),
	}
	if st.Checkpoint != nil {
		resp["checkpoint"] = checkpointToAPI(st.Checkpoint)
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := b64decode(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("decoded key must be 32 bytes")
	}
	return ed25519.PublicKey(raw), nil
}

func b64decode(encoded string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

func encodeKey(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }
