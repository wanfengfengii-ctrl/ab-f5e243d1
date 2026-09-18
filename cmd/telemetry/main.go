// Command telemetry runs the API server, background worker or reverse proxy
// depending on ROLE.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"telemetry/internal/config"
	"telemetry/internal/gateway"
	"telemetry/internal/httpapi"
	"telemetry/internal/serverkey"
	"telemetry/internal/store"
	"telemetry/internal/worker"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel)

	skey, err := serverkey.FromSeed(cfg.ServerSigningKey)
	if err != nil {
		return err
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch cfg.Role {
	case "api":
		return runAPI(rootCtx, cfg, skey, logger)
	case "worker":
		return runWorker(rootCtx, cfg, skey, logger)
	case "gateway":
		return runGateway(rootCtx, cfg, logger)
	default:
		return errors.New("ROLE must be one of: api, worker, gateway")
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func openStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (*store.Store, error) {
	// Retry briefly: in Compose the database may start a moment after the app.
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		st, err := store.New(context.Background(), cfg.DatabaseURL)
		if err == nil {
			if err := st.Migrate(context.Background()); err != nil {
				st.Close()
				return nil, err
			}
			return st, nil
		}
		lastErr = err
		logger.Warn("waiting for database", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, lastErr
}

func runAPI(ctx context.Context, cfg config.Config, skey *serverkey.Key, logger *slog.Logger) error {
	st, err := openStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := httpapi.NewServer(st, cfg, logger, skey)
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No blanket WriteTimeout: /wait long-polls up to WaitMaxSeconds.
		IdleTimeout: 75 * time.Second,
	}
	return serveUntilStopped(ctx, httpServer, cfg.ShutdownTimeout, logger)
}

func runWorker(ctx context.Context, cfg config.Config, skey *serverkey.Key, logger *slog.Logger) error {
	st, err := openStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer st.Close()
	w := worker.New(st, cfg, skey, logger)
	w.Run(ctx)
	return nil
}

func runGateway(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	proxy, err := gateway.New(cfg.UpstreamURL, logger)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	return serveUntilStopped(ctx, httpServer, cfg.ShutdownTimeout, logger)
}

func serveUntilStopped(ctx context.Context, httpServer *http.Server,
	shutdownTimeout time.Duration, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			return err
		}
		logger.Info("stopped cleanly")
		return nil
	case err := <-errCh:
		return err
	}
}
