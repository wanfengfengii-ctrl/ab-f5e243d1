package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"telemetry/internal/canonical"
)

// errNoRowsSentinel re-exports pgx.ErrNoRows for readability in store code.
var errNoRowsSentinel = pgx.ErrNoRows

func pgxTxWrite() pgx.TxOptions { return pgx.TxOptions{} }

// canonicalBytes parses and re-encodes JSON with the canonical scheme.
func canonicalBytes(raw []byte) ([]byte, error) {
	v, err := canonical.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(v)
}

// pgSleep waits inside a cancellable statement; it returns promptly on ctx
// cancellation.
func pgSleep(ctx context.Context, pool *pgxpool.Pool, d time.Duration) error {
	_, err := pool.Exec(ctx, "SELECT pg_sleep($1)", d.Seconds())
	return err
}

var _ = errors.Is
