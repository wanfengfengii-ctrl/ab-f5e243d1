package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// CheckpointDoc is the canonical document covered by the server signature.
type CheckpointDoc struct {
	DeviceID    string `json:"deviceId"`
	Sequence    int64  `json:"sequence"`
	Digest      string `json:"digest"`
	GeneratedAt string `json:"generatedAt"`
}

// CheckpointSignPayload returns the exact bytes signed for a checkpoint:
// "TELEMETRY-CHECKPOINT-V1\n" followed by the canonical JSON of
// CheckpointDoc.
func CheckpointSignPayload(doc CheckpointDoc) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	cb, err := canonicalBytes(raw)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len("TELEMETRY-CHECKPOINT-V1\n")+len(cb))
	out = append(out, []byte("TELEMETRY-CHECKPOINT-V1\n")...)
	out = append(out, cb...)
	return out, nil
}

// CompactionPolicy controls how aggressively the worker compacts.
type CompactionPolicy struct {
	// KeepRecent events newest than the cutoff are always retained.
	KeepRecent int64
	// MinEventAge prevents compacting events younger than this.
	MinEventAge time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// CompactionResult reports one device's compaction outcome.
type CompactionResult struct {
	DeviceID       string
	Compacted      bool
	PreviousSeq    int64
	CutoffSequence int64
	CutoffDigest   string
	DeletedRows    int64
}

// CompactDevice performs one safe compaction pass for a device.
//
// The cutoff is the minimum of:
//   - hwm minus KeepRecent,
//   - the highest sequence accepted at least MinEventAge ago,
//   - one less than the earliest event still needed by any unexpired view
//     (min(last_position) across active views; absence of views imposes none).
//
// Deleting events, advancing devices.checkpoint_seq and upserting the signed
// checkpoint commit in one transaction while holding the device row update
// lock (view creation and page reads take the shared lock, so they cannot
// interleave with this decision).
func (s *Store) CompactDevice(ctx context.Context, deviceID string,
	policy CompactionPolicy, signer func(CheckpointDoc) (string, error)) (*CompactionResult, error) {

	if policy.Now == nil {
		policy.Now = time.Now
	}
	tx, err := s.pool.BeginTx(ctx, pgxTxWrite())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Block compaction until every in-flight staging transaction completes,
	// then take the device row update lock. Lock order is always barrier ->
	// device, matching ingest advancement, rotation and adjudication.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", deviceBarrierKey(deviceID)); err != nil {
		return nil, err
	}
	d, gerr := lockDevice(tx, ctx, deviceID)
	if gerr != nil {
		return nil, gerr
	}
	res := &CompactionResult{DeviceID: deviceID, PreviousSeq: d.CheckpointSeq}
	if d.HWM == 0 || d.HWM <= d.CheckpointSeq {
		return res, tx.Commit(ctx)
	}

	// Expire views inside the locked section so the floor computation and the
	// delete see the same view set.
	if _, err := tx.Exec(ctx,
		`DELETE FROM views WHERE device_id=$1 AND expires_at <= now()`, deviceID); err != nil {
		return nil, err
	}

	cutoff := d.HWM
	if policy.KeepRecent > 0 && cutoff-policy.KeepRecent < cutoff {
		cutoff = min64(cutoff, d.HWM-policy.KeepRecent)
	}
	if policy.MinEventAge > 0 {
		var ageSeq int64
		err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(sequence),0) FROM events
			 WHERE device_id=$1 AND status='accepted' AND accepted_at <= $2`,
			deviceID, policy.Now().Add(-policy.MinEventAge)).Scan(&ageSeq)
		if err != nil {
			return nil, err
		}
		cutoff = min64(cutoff, ageSeq)
	}
	var viewFloor *int64
	if err := tx.QueryRow(ctx,
		`SELECT MIN(last_position) FROM views
		 WHERE device_id=$1 AND expires_at > now()`, deviceID).Scan(&viewFloor); err != nil {
		return nil, err
	}
	if viewFloor != nil {
		cutoff = min64(cutoff, *viewFloor)
	}
	if cutoff <= d.CheckpointSeq {
		return res, tx.Commit(ctx)
	}

	// The cutoff must be a real accepted event forming part of the prefix,
	// and its recorded predecessor chain must be intact.
	var cutoffDigest string
	var acceptedCount int64
	err = tx.QueryRow(ctx,
		`SELECT digest FROM events WHERE device_id=$1 AND sequence=$2 AND status='accepted'`,
		deviceID, cutoff).Scan(&cutoffDigest)
	if errors.Is(err, errNoRowsSentinel) {
		return nil, errf(CodeCompactionNotPossible,
			"sequence %d is not part of the accepted prefix", cutoff)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM events
		 WHERE device_id=$1 AND sequence BETWEEN $2 AND $3 AND status='accepted'`,
		deviceID, d.CheckpointSeq+1, cutoff).Scan(&acceptedCount); err != nil {
		return nil, err
	}
	if acceptedCount != cutoff-d.CheckpointSeq {
		return nil, errors.New("store invariant: accepted prefix is not dense before compaction")
	}

	// Truncate to microseconds: PostgreSQL's timestamptz has microsecond
	// resolution, so the signed generatedAt must equal the value later read
	// back from the checkpoints row.
	generatedAt := policy.Now().UTC().Truncate(time.Microsecond)
	doc := CheckpointDoc{
		DeviceID:    deviceID,
		Sequence:    cutoff,
		Digest:      cutoffDigest,
		GeneratedAt: generatedAt.Format(time.RFC3339Nano),
	}
	signature, serr := signer(doc)
	if serr != nil {
		return nil, serr
	}

	del, err := tx.Exec(ctx,
		`DELETE FROM events WHERE device_id=$1 AND sequence <= $2 AND status='accepted'`,
		deviceID, cutoff)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM conflicts WHERE device_id=$1 AND sequence <= $2 AND status='resolved'`,
		deviceID, cutoff); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO checkpoints(device_id,sequence,digest,signature,created_at)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (device_id) DO UPDATE
		 SET sequence=EXCLUDED.sequence, digest=EXCLUDED.digest,
		     signature=EXCLUDED.signature, created_at=EXCLUDED.created_at
		 WHERE checkpoints.sequence < EXCLUDED.sequence`,
		deviceID, cutoff, cutoffDigest, signature, generatedAt); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE devices SET checkpoint_seq=$2, updated_at=now()
		 WHERE device_id=$1 AND checkpoint_seq<$2`, deviceID, cutoff); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	res.Compacted = true
	res.CutoffSequence = cutoff
	res.CutoffDigest = cutoffDigest
	res.DeletedRows = del.RowsAffected()
	return res, nil
}

// ListDeviceIDs enumerates devices for the worker sweep.
func (s *Store) ListDeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id FROM devices ORDER BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CheckpointDocCanonical exposes the canonical checkpoint bytes for clients.
func CheckpointDocCanonical(doc CheckpointDoc) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return canonicalBytes(raw)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
