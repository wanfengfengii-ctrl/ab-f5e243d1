// Package worker runs the independent background compaction task.
package worker

import (
	"context"
	"log/slog"
	"time"

	"telemetry/internal/config"
	"telemetry/internal/serverkey"
	"telemetry/internal/store"
)

// Worker owns the periodic compaction sweep.
type Worker struct {
	store *store.Store
	cfg   config.Config
	key   *serverkey.Key
	log   *slog.Logger
}

// New constructs a worker.
func New(st *store.Store, cfg config.Config, key *serverkey.Key, log *slog.Logger) *Worker {
	return &Worker{store: st, cfg: cfg, key: key, log: log}
}

// Run executes sweeps until ctx is canceled. A failure on one device never
// aborts the sweep; every pass is independently retryable because checkpoint
// publication and deletion commit atomically.
func (w *Worker) Run(ctx context.Context) {
	w.log.Info("worker starting",
		"interval", w.cfg.CompactionInterval,
		"keepRecent", w.cfg.CompactionCutoff,
		"minEventAge", w.cfg.CompactionMinAge,
		"viewTTL", w.cfg.ViewTTL)
	t := time.NewTicker(w.cfg.CompactionInterval)
	defer t.Stop()
	w.once(ctx) // run immediately after startup (also covers crash-restart)
	for {
		select {
		case <-ctx.Done():
			w.log.Info("worker stopping")
			return
		case <-t.C:
			w.once(ctx)
		}
	}
}

func (w *Worker) once(ctx context.Context) {
	if n, err := w.store.ExpireViews(ctx); err != nil {
		w.log.Error("view expiry failed", "error", err)
	} else if n > 0 {
		w.log.Info("expired read views", "count", n)
	}
	// Crash-recovery: advance any device whose watermark lagged because a
	// process died between staging and advancement.
	if n, err := w.store.AdvanceAllDevices(ctx); err != nil {
		w.log.Error("recovery advancement failed", "error", err)
	} else if n > 0 {
		w.log.Info("recovered watermark advancement", "devices", n)
	}
	ids, err := w.store.ListDeviceIDs(ctx)
	if err != nil {
		w.log.Error("cannot list devices for compaction", "error", err)
		return
	}
	policy := store.CompactionPolicy{
		KeepRecent:  w.cfg.CompactionCutoff,
		MinEventAge: w.cfg.CompactionMinAge,
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		res, err := w.store.CompactDevice(ctx, id, policy, w.sign)
		if err != nil {
			w.log.Error("compaction failed", "deviceId", id, "error", err)
			continue
		}
		if res.Compacted {
			w.log.Info("compacted device",
				"deviceId", id, "cutoff", res.CutoffSequence,
				"previousCheckpoint", res.PreviousSeq, "deleted", res.DeletedRows)
		}
	}
}

func (w *Worker) sign(doc store.CheckpointDoc) (string, error) {
	payload, err := store.CheckpointSignPayload(doc)
	if err != nil {
		return "", err
	}
	return w.key.Sign(payload), nil
}
