// Package store implements all persistence behind PostgreSQL, which is the
// sole arbiter across API instances and background workers.
package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations_sql/*.sql
var migrationFS embed.FS

// Store wraps the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New connects and verifies reachability.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 20
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping verifies database reachability.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool exposes the pool (used by the LISTEN/NOTIFY waiter).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate applies every embedded migration not yet recorded. Concurrent
// processes serialize on a transaction-scoped advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrationFS.ReadDir("migrations_sql")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(911177331)"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, name := range names {
		var ok bool
		if err := tx.QueryRow(ctx,
			"SELECT true FROM schema_migrations WHERE name=$1", name).Scan(&ok); err == nil {
			continue
		} else if err != pgx.ErrNoRows {
			return err
		}
		sqlBytes, err := migrationFS.ReadFile("migrations_sql/" + name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(name) VALUES ($1)", name); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Device is the devices-row projection.
type Device struct {
	ID               string
	ControlRevision  int64
	ConflictRevision int64
	HWM              int64
	CheckpointSeq    int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// KeyGen is one stored Ed25519 key generation.
type KeyGen struct {
	KeyVersion        int
	PublicKey         []byte
	EffectiveSequence int64
	CreatedAt         time.Time
}

const scanDeviceCols = `device_id, control_revision, conflict_revision,
	contiguous_high_watermark, checkpoint_seq, created_at, updated_at`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	if err := row.Scan(&d.ID, &d.ControlRevision, &d.ConflictRevision,
		&d.HWM, &d.CheckpointSeq, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return &d, nil
}
