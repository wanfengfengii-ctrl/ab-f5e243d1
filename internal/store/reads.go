package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// View is a fixed read snapshot.
type View struct {
	ID            string
	DeviceID      string
	HighWatermark int64
	LastPosition  int64
	ExpiresAt     time.Time
}

// CreateView opens a fixed snapshot at the device's current watermark.
// startAfter is the sequence just before the first page position (0 when
// reading from the beginning); it seeds the view's compaction floor.
//
// The view row is inserted while holding a shared lock on the device row;
// compaction takes the corresponding update lock, so a checkpoint can never be
// written in the gap between reading the watermark and publishing the view.
func (s *Store) CreateView(ctx context.Context, deviceID string, startAfter int64, ttl time.Duration) (*View, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var hwm, cpSeq int64
	err = tx.QueryRow(ctx,
		`SELECT contiguous_high_watermark, checkpoint_seq
		 FROM devices WHERE device_id=$1 FOR SHARE`,
		deviceID).Scan(&hwm, &cpSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeDeviceNotFound, "device %q not found", deviceID)
	}
	if err != nil {
		return nil, err
	}
	if startAfter < 0 || startAfter > hwm {
		return nil, errf(CodeValidation,
			"start position %d is outside the visible prefix [0,%d]", startAfter, hwm).
			WithDetail("highWatermark", hwm)
	}
	if startAfter < cpSeq {
		return nil, errf(CodeBeforeCheckpoint,
			"start position %d is behind checkpoint %d; resume from sequence %d",
			startAfter, cpSeq, cpSeq+1).
			WithDetail("checkpointSequence", cpSeq).
			WithDetail("resumeFromSequence", cpSeq+1)
	}
	id := newUUID()
	exp := time.Now().Add(ttl)
	if _, err := tx.Exec(ctx,
		`INSERT INTO views(view_id,device_id,high_watermark,last_position,expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		id, deviceID, hwm, startAfter, exp); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &View{ID: formatUUID(id), DeviceID: deviceID, HighWatermark: hwm,
		LastPosition: startAfter, ExpiresAt: exp}, nil
}

// newUUID returns a random RFC 4122 v4 UUID as 16 bytes.
func newUUID() [16]byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return b
}

func formatUUID(b [16]byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, h[b[i]>>4], h[b[i]&0xf])
	}
	return string(out)
}

// parseUUID accepts canonical hyphenated UUID text and returns its 16 bytes;
// pgx encodes [16]byte into the uuid wire type.
func parseUUID(s string) ([16]byte, error) {
	var b [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return b, errors.New("malformed uuid")
	}
	j := 0
	for i := 0; i < 36; i++ {
		if s[i] == '-' {
			continue
		}
		var v byte
		switch {
		case s[i] >= '0' && s[i] <= '9':
			v = s[i] - '0'
		case s[i] >= 'a' && s[i] <= 'f':
			v = s[i] - 'a' + 10
		case s[i] >= 'A' && s[i] <= 'F':
			v = s[i] - 'A' + 10
		default:
			return b, errors.New("malformed uuid")
		}
		if j%2 == 0 {
			b[j/2] = v << 4
		} else {
			b[j/2] |= v
		}
		j++
	}
	if j != 32 {
		return b, errors.New("malformed uuid")
	}
	return b, nil
}

// loadViewForRead fetches and locks a view against concurrent compaction.
func loadViewForRead(tx pgx.Tx, ctx context.Context, viewID, deviceID string) (*View, error) {
	var v View
	uuidID, err := parseUUID(viewID)
	if err != nil {
		return nil, errf(CodeCursorInvalid, "view id is not a valid UUID")
	}
	err = tx.QueryRow(ctx,
		`SELECT view_id,device_id,high_watermark,last_position,expires_at
		 FROM views WHERE view_id=$1 FOR SHARE`, uuidID).
		Scan(&v.ID, &v.DeviceID, &v.HighWatermark, &v.LastPosition, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeViewNotFound, "read view not found; start a new view")
	}
	if err != nil {
		return nil, err
	}
	if v.DeviceID != deviceID {
		return nil, errf(CodeCursorInvalid, "cursor is bound to a different device")
	}
	if time.Now().After(v.ExpiresAt) {
		return nil, errf(CodeViewExpired, "read view expired at %s", v.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	return &v, nil
}

// EventRecord is one accepted event as returned to readers.
type EventRecord struct {
	DeviceID         string
	Sequence         int64
	Digest           string
	EventID          string
	OccurredAt       string
	KeyVersion       int
	PrevDigest       string
	PayloadCanonical []byte
	Signature        []byte
}

// Page is one fixed-view page.
type Page struct {
	View          *View
	Events        []EventRecord
	NextPosition  int64
	HasNext       bool
	CheckpointSeq int64
}

// ReadPage returns events after position within the bound view.
func (s *Store) ReadPage(ctx context.Context, viewID, deviceID string, position int64, limit int) (*Page, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	v, err := loadViewForRead(tx, ctx, viewID, deviceID)
	if err != nil {
		return nil, err
	}
	if position > v.HighWatermark {
		return nil, errf(CodeCursorInvalid,
			"cursor position %d is beyond the view high watermark %d", position, v.HighWatermark)
	}

	var checkpointSeq int64
	if err := tx.QueryRow(ctx,
		`SELECT checkpoint_seq FROM devices WHERE device_id=$1`, deviceID).Scan(&checkpointSeq); err != nil {
		return nil, err
	}
	// Checkpoint staleness wins over the back-within-view check: the events
	// the old cursor needs no longer exist.
	if position < checkpointSeq {
		return nil, errf(CodeCursorStale,
			"cursor is behind checkpoint %d; resume from sequence %d",
			checkpointSeq, checkpointSeq+1).
			WithDetail("checkpointSequence", checkpointSeq).
			WithDetail("resumeFromSequence", checkpointSeq+1)
	}
	if position < v.LastPosition {
		return nil, errf(CodeCursorInvalid,
			"cursor cannot move backwards within a view (cursor position %d, view delivered %d)",
			position, v.LastPosition)
	}

	lo := position + 1
	hi := position + int64(limit)
	if hi > v.HighWatermark {
		hi = v.HighWatermark
	}
	page := &Page{View: v, CheckpointSeq: checkpointSeq}
	if lo <= hi {
		rows, err := tx.Query(ctx,
			`SELECT device_id,sequence,digest,event_id,occurred_at,key_version,prev_digest,
			        payload_canonical,signature
			 FROM events
			 WHERE device_id=$1 AND sequence BETWEEN $2 AND $3 AND status='accepted'
			 ORDER BY sequence`, deviceID, lo, hi)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e EventRecord
			if err := rows.Scan(&e.DeviceID, &e.Sequence, &e.Digest, &e.EventID,
				&e.OccurredAt, &e.KeyVersion, &e.PrevDigest, &e.PayloadCanonical,
				&e.Signature); err != nil {
				rows.Close()
				return nil, err
			}
			page.Events = append(page.Events, e)
		}
		rows.Close()
		if int64(len(page.Events)) != hi-lo+1 {
			return nil, fmt.Errorf("store invariant: missing accepted events in [%d,%d]", lo, hi)
		}
		page.NextPosition = hi
		page.HasNext = hi < v.HighWatermark
	} else {
		page.NextPosition = position
		page.HasNext = false
	}

	if page.NextPosition > v.LastPosition {
		if _, err := tx.Exec(ctx,
			`UPDATE views SET last_position=$2 WHERE view_id=$1 AND last_position<$2`,
			v.ID, page.NextPosition); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return page, nil
}

// Checkpoint is the durable compaction record returned to stale readers.
type Checkpoint struct {
	DeviceID  string    `json:"deviceId"`
	Sequence  int64     `json:"sequence"`
	Digest    string    `json:"digest"`
	Generated time.Time `json:"generatedAt"`
	Signature string    `json:"signature"`
}

// GetCheckpoint returns a device's checkpoint or nil when none exists.
func (s *Store) GetCheckpoint(ctx context.Context, deviceID string) (*Checkpoint, error) {
	var c Checkpoint
	var gen time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT device_id,sequence,digest,created_at,signature
		 FROM checkpoints WHERE device_id=$1`, deviceID).
		Scan(&c.DeviceID, &c.Sequence, &c.Digest, &gen, &c.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Generated = gen
	return &c, nil
}

// DeviceStatus is the projection returned by the status endpoint.
type DeviceStatus struct {
	Device        *Device
	Keys          []KeyGen
	OpenConflicts []ConflictInfo
	Checkpoint    *Checkpoint
}

// DeviceStatusTx assembles the status projection.
func (s *Store) DeviceStatus(ctx context.Context, deviceID string) (*DeviceStatus, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	keys, err := s.ListKeyGenerations(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	conflicts, err := s.ListOpenConflicts(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	cp, err := s.GetCheckpoint(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return &DeviceStatus{Device: d, Keys: keys, OpenConflicts: conflicts, Checkpoint: cp}, nil
}

// WaitResult holds newly visible contiguous events for the wait endpoint.
type WaitResult struct {
	HighWatermark int64
	Events        []EventRecord
	CheckpointSeq int64
}

// WaitForEvents blocks until at least one accepted event exists strictly after
// afterSequence, or until wait returns false on timeout. It runs on a
// dedicated connection: LISTEN is registered before the watermark is read, so
// no committed notification can fall in the gap between check and wait.
func (s *Store) WaitForEvents(ctx context.Context, deviceID string, afterSequence int64,
	deadline time.Time, limit int) (*WaitResult, bool, error) {

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Release() // pgx discards LISTEN state on release

	if _, err := conn.Exec(ctx, "LISTEN "+NotifyChannel); err != nil {
		return nil, false, err
	}

	var token [16]byte
	sum := sha256.Sum256([]byte(deviceID))
	copy(token[:], sum[:16])
	wantToken := DeviceChannelToken(deviceID)

	for {
		// Re-check inside the loop on a fresh statement so each iteration sees
		// the newest committed state.
		var hwm, cpSeq int64
		err := conn.QueryRow(ctx,
			`SELECT contiguous_high_watermark, checkpoint_seq FROM devices WHERE device_id=$1`,
			deviceID).Scan(&hwm, &cpSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, errf(CodeDeviceNotFound, "device %q not found", deviceID)
		}
		if err != nil {
			return nil, false, err
		}
		if afterSequence < cpSeq {
			return nil, false, errf(CodeBeforeCheckpoint,
				"afterSequence %d is behind checkpoint %d; resume from %d",
				afterSequence, cpSeq, cpSeq+1).
				WithDetail("checkpointSequence", cpSeq).
				WithDetail("resumeFromSequence", cpSeq+1)
		}
		if hwm > afterSequence {
			hi := afterSequence + int64(limit)
			if hi > hwm {
				hi = hwm
			}
			rows, err := conn.Query(ctx,
				`SELECT device_id,sequence,digest,event_id,occurred_at,key_version,prev_digest,
				        payload_canonical,signature
				 FROM events WHERE device_id=$1 AND sequence BETWEEN $2 AND $3 AND status='accepted'
				 ORDER BY sequence`, deviceID, afterSequence+1, hi)
			if err != nil {
				return nil, false, err
			}
			out := &WaitResult{HighWatermark: hwm, CheckpointSeq: cpSeq}
			for rows.Next() {
				var e EventRecord
				if err := rows.Scan(&e.DeviceID, &e.Sequence, &e.Digest, &e.EventID,
					&e.OccurredAt, &e.KeyVersion, &e.PrevDigest, &e.PayloadCanonical,
					&e.Signature); err != nil {
					rows.Close()
					return nil, false, err
				}
				out.Events = append(out.Events, e)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, false, err
			}
			return out, true, nil
		}

		now := time.Now()
		if !now.Before(deadline) {
			return &WaitResult{HighWatermark: hwm, CheckpointSeq: cpSeq}, false, nil
		}
		// Wake at least once a second as a belt-and-braces guard, on any device
		// notification, or when the client goes away. The poll deadline never
		// exceeds the caller's context, so a client disconnect interrupts it.
		pollDeadline := minTime(deadline, now.Add(time.Second))
		nctx, cancel := context.WithDeadline(ctx, pollDeadline)
		notification, werr := conn.Conn().WaitForNotification(nctx)
		cancel()
		if werr != nil {
			if errors.Is(werr, context.DeadlineExceeded) {
				if !time.Now().Before(deadline) {
					return &WaitResult{HighWatermark: hwm, CheckpointSeq: cpSeq}, false, nil
				}
				continue
			}
			if errors.Is(werr, context.Canceled) {
				if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, false, ctx.Err()
				}
				continue
			}
			return nil, false, fmt.Errorf("wait for notification: %w", werr)
		}
		_ = notification
		if notification == nil || !matchToken(notification.Payload, wantToken) {
			continue
		}
	}
}

func matchToken(payload, want string) bool {
	if len(payload) < len(want) {
		return false
	}
	return payload[:len(want)] == want
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ExpireViews deletes views past their expiry. Safe to run repeatedly.
func (s *Store) ExpireViews(ctx context.Context) (int64, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM views WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
