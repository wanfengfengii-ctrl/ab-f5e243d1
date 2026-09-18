// Package httpapi implements the versioned HTTP JSON API.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"telemetry/internal/config"
	"telemetry/internal/cursor"
	"telemetry/internal/serverkey"
	"telemetry/internal/store"
)

// Server bundles dependencies shared by handlers.
type Server struct {
	Store   *store.Store
	Cfg     config.Config
	Logger  *slog.Logger
	Cursors *cursor.Coder
	SrvKey  *serverkey.Key
}

// NewServer constructs the API dependency bundle.
func NewServer(st *store.Store, cfg config.Config, logger *slog.Logger, skey *serverkey.Key) *Server {
	return &Server{
		Store:   st,
		Cfg:     cfg,
		Logger:  logger,
		Cursors: cursor.NewCoder(append(append([]byte{}, skey.Public()...), []byte(cfg.AdminToken)...)),
		SrvKey:  skey,
	}
}

// Handler returns the fully wired router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)

	mux.HandleFunc("POST /api/v1/devices", s.handleRegister)
	mux.HandleFunc("GET /api/v1/devices/{deviceId}", s.handleDeviceStatus)
	mux.HandleFunc("POST /api/v1/devices/{deviceId}/keys", s.requireAdmin(s.handleRotateKey))
	mux.HandleFunc("POST /api/v1/devices/{deviceId}/ingest", s.handleIngest)
	mux.HandleFunc("GET /api/v1/devices/{deviceId}/conflicts", s.handleListConflicts)
	mux.HandleFunc("GET /api/v1/devices/{deviceId}/conflicts/{seq}", s.handleGetConflict)
	mux.HandleFunc("POST /api/v1/devices/{deviceId}/conflicts/{seq}/adjudicate",
		s.requireAdmin(s.handleAdjudicate))
	mux.HandleFunc("GET /api/v1/devices/{deviceId}/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/devices/{deviceId}/wait", s.handleWait)
	mux.HandleFunc("GET /api/v1/devices/{deviceId}/checkpoint", s.handleCheckpoint)
	mux.HandleFunc("POST /api/v1/devices/{deviceId}/compaction/run",
		s.requireAdmin(s.handleCompactNow))
	mux.HandleFunc("GET /api/v1/server/checkpoint-key", s.handleCheckpointKey)

	return s.recoverer(s.requestLogger(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		writePlainError(w, http.StatusServiceUnavailable, "database_unavailable", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// middleware ----------------------------------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Logger.Error("panic recovered",
					"error", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				writePlainError(w, http.StatusInternalServerError,
					"internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		s.Logger.Log(r.Context(), slog.LevelInfo, "http",
			"method", r.Method, "path", r.URL.Path,
			"status", sw.status, "durationMs", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr)
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const p = "Bearer "
		if !strings.HasPrefix(h, p) || !constantTimeEqual(strings.TrimPrefix(h, p), s.Cfg.AdminToken) {
			writePlainError(w, http.StatusUnauthorized, store.CodeUnauthorized,
				"management endpoint requires a valid bearer token")
			return
		}
		next(w, r)
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// writeStoreError maps a store error onto the wire.
func writeStoreError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	var se *store.Error
	if errors.As(err, &se) {
		status := httpStatus(se)
		if status >= 500 {
			logger.ErrorContext(r.Context(), "store error", "code", se.Code, "error", se.Error())
		}
		writeErrorBody(w, status, se)
		return
	}
	logger.ErrorContext(r.Context(), "unexpected error", "error", err)
	writePlainError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}
