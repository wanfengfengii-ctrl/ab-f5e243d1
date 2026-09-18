package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"telemetry/internal/render"
	"telemetry/internal/store"
)

// httpStatus maps store errors to HTTP status codes.
func httpStatus(se *store.Error) int { return render.HTTPStatusFor(se) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":{"code":"internal_error","message":"response encoding failed"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeErrorBody(w http.ResponseWriter, status int, se *store.Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(render.MustRenderError(se))
}

func writePlainError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]any{"error": map[string]string{
		"code": code, "message": message,
	}})
	_, _ = w.Write(body)
}

// decodeJSONBody reads a bounded, content-type-checked JSON request body.
// Unknown fields and trailing JSON values are rejected. The boolean "ok" is
// false when an error response has already been written.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		media := strings.TrimSpace(strings.ToLower(strings.Split(ct, ";")[0]))
		if media != "application/json" {
			writeErrorBody(w, http.StatusUnsupportedMediaType, &store.Error{
				Code:    store.CodeUnsupportedMediaType,
				Message: "Content-Type must be application/json"})
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeErrorBody(w, http.StatusBadRequest, &store.Error{
			Code:    store.CodeInvalidJSON,
			Message: "request body must contain exactly one JSON value"})
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErrorBody(w, http.StatusRequestEntityTooLarge, &store.Error{
			Code:    store.CodeRequestBodyTooLarge,
			Message: "request body exceeds the configured size limit"})
		return
	}
	writeErrorBody(w, http.StatusBadRequest, &store.Error{
		Code: store.CodeInvalidJSON, Message: err.Error()})
}
