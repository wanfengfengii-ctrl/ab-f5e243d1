package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RegisterDevice creates a device with its first Ed25519 key generation
// (keyVersion=1, effectiveSequence=1). It is atomic: a duplicate deviceId
// leaves nothing behind.
func (s *Store) RegisterDevice(ctx context.Context, deviceID string, firstPublicKey ed25519.PublicKey) (*Device, *KeyGen, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	d, err := insertDevice(tx, ctx, deviceID)
	if err != nil {
		return nil, nil, err
	}
	k := KeyGen{KeyVersion: 1, PublicKey: append([]byte(nil), firstPublicKey...), EffectiveSequence: 1}
	if _, err := tx.Exec(ctx,
		`INSERT INTO device_keys(device_id,key_version,public_key,effective_sequence)
		 VALUES ($1,1,$2,1)`, deviceID, []byte(firstPublicKey)); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return d, &k, nil
}

func insertDevice(tx pgx.Tx, ctx context.Context, deviceID string) (*Device, error) {
	row := tx.QueryRow(ctx,
		`INSERT INTO devices(device_id) VALUES ($1)
		 RETURNING `+scanDeviceCols, deviceID)
	d, err := scanDevice(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errf(CodeDeviceExists, "device %q already registered", deviceID)
		}
		return nil, err
	}
	return d, nil
}

// GetDevice fetches a device or returns CodeDeviceNotFound.
func (s *Store) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scanDeviceCols+` FROM devices WHERE device_id=$1`, deviceID)
	d, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeDeviceNotFound, "device %q not found", deviceID)
	}
	return d, err
}

// ListKeyGenerations returns key generations ordered by key_version ascending.
func (s *Store) ListKeyGenerations(ctx context.Context, deviceID string) ([]KeyGen, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key_version,public_key,effective_sequence,created_at
		 FROM device_keys WHERE device_id=$1 ORDER BY key_version`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyGen
	for rows.Next() {
		var k KeyGen
		if err := rows.Scan(&k.KeyVersion, &k.PublicKey, &k.EffectiveSequence, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RotateKeyResult reports the outcome of an idempotent rotation.
type RotateKeyResult struct {
	Device  *Device
	Key     *KeyGen
	Created bool // false when this commandId had already applied the same rotation
}

func lockDevice(tx pgx.Tx, ctx context.Context, deviceID string) (*Device, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+scanDeviceCols+` FROM devices WHERE device_id=$1 FOR UPDATE`, deviceID)
	d, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeDeviceNotFound, "device %q not found", deviceID)
	}
	return d, err
}

func queryKeys(tx pgx.Tx, ctx context.Context, deviceID string) ([]KeyGen, error) {
	rows, err := tx.Query(ctx,
		`SELECT key_version,public_key,effective_sequence FROM device_keys
		 WHERE device_id=$1 ORDER BY key_version`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyGen
	for rows.Next() {
		var k KeyGen
		if err := rows.Scan(&k.KeyVersion, &k.PublicKey, &k.EffectiveSequence); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("store: device %q has no key generations", deviceID)
	}
	return out, nil
}

func bumpControlRevision(tx pgx.Tx, ctx context.Context, deviceID string) (*Device, error) {
	row := tx.QueryRow(ctx,
		`UPDATE devices SET control_revision=control_revision+1, updated_at=now()
		 WHERE device_id=$1 RETURNING `+scanDeviceCols, deviceID)
	return scanDevice(row)
}
