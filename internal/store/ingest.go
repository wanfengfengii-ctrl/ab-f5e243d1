package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"telemetry/internal/envelope"
	"telemetry/internal/render"
)

// GenesisDigest re-exports the protocol genesis anchor used for sequence 1.
const GenesisDigest = envelope.GenesisDigest

// NotifyChannel is the single Postgres LISTEN channel used for wakeups.
const NotifyChannel = "telemetry_events"

// DeviceChannelToken returns the stable per-device token embedded in notify
// payloads (hex of truncated SHA-256 of the device id).
func DeviceChannelToken(deviceID string) string {
	sum := sha256.Sum256([]byte(deviceID))
	return hex.EncodeToString(sum[:16])
}

// IngestEvent is one fully pre-validated inbound event. PayloadCanonical and
// Digest are computed by the API layer with the canonical rules; signature
// verification happens against the device key generations read under the
// staging transaction's shared device lock.
type IngestEvent struct {
	Event

	PayloadCanonical []byte
	Digest           string
	OccurredAtCanon  string // normalized UTC RFC3339Nano string used in the record
	SigningInput     []byte // exact bytes covered by the Ed25519 signature
}

// Event mirrors the wire event but without the raw payload helper.
type Event struct {
	DeviceID   string
	Sequence   int64
	EventID    string
	KeyVersion int
	PrevDigest string
	Signature  []byte
}

// IngestInput is a batch ingestion request.
type IngestInput struct {
	RequestID   string
	DeviceID    string
	ContentHash [32]byte // SHA-256 of the canonical request document
	Events      []IngestEvent
}

// ConflictInfo describes the conflict state at one sequence.
type ConflictInfo struct {
	Sequence     int64           `json:"sequence"`
	Reason       string          `json:"reason"`
	Status       string          `json:"status"`
	Revision     int64           `json:"revision"`
	Candidates   []CandidateInfo `json:"candidates,omitempty"`
	Resolution   *string         `json:"resolution,omitempty"`
	ChosenDigest string          `json:"chosenDigest,omitempty"`
}

// CandidateInfo is one conflict candidate.
type CandidateInfo struct {
	Digest     string    `json:"digest"`
	EventID    string    `json:"eventId"`
	KeyVersion int       `json:"keyVersion"`
	Status     string    `json:"status"`
	FirstSeen  time.Time `json:"firstSeen"`
}

// IngestResult is the transactional outcome of a batch.
type IngestResult struct {
	DeviceID      string
	HighWatermark int64
	ConflictRev   int64
	// Newly inserted (or resurrected) candidate sequences.
	Stored []int64
	// Sequences whose identical digest was already present.
	Duplicates []int64
	// Sequences that became part of the contiguous prefix during this call.
	Advanced []int64
	// Current conflicts touching sequences in the batch (post-state).
	Conflicts []ConflictInfo
}

// Terminal is a fully rendered HTTP response captured durably so idempotent
// replays return byte-identical results.
type Terminal struct {
	Status int
	Body   json.RawMessage
}

// Ingest atomically stages a batch, then advances the contiguous prefix.
//
// Correctness under same-sequence concurrency rests on a session-advisory
// barrier (deviceBarrierKey):
//
//  1. the request acquires a SESSION-level shared barrier lock before
//     staging, so genuinely-concurrent uploads for the device are all inside
//     the barrier simultaneously;
//  2. the all-or-nothing staging transaction inserts the batch's candidates
//     and commits;
//  3. the shared barrier is released and the request opens an advancement
//     transaction that takes the barrier EXCLUSIVELY (xact) lock plus the
//     device row FOR UPDATE. It proceeds only once every concurrent staging
//     session has released its shared lock, i.e. once all competing
//     candidates for a sequence are durably visible.
//
// A genuinely earlier request that completes before a later one starts
// legitimately wins the frontier; two in-flight uploads of distinct
// same-sequence events deterministically produce a conflict instead of a
// silent first-wins overwrite.
func (s *Store) Ingest(ctx context.Context, in *IngestInput,
	build func(*IngestResult, *Error) Terminal) (term Terminal, replayed bool, err error) {

	if len(in.Events) < 1 || len(in.Events) > 500 {
		return term, false, errf(CodeBatchInvalid, "batch size must be between 1 and 500 events")
	}

	// Phase 0: idempotency. A committed response always replays; a different
	// document under the same requestId is a stable conflict; an in-flight
	// record (response NULL) is awaited and then retried.
	if prior, mismatch, werr := s.lookupPrior(ctx, in); werr != nil {
		return term, false, werr
	} else if mismatch != nil {
		return build(nil, mismatch), true, nil
	} else if prior != nil {
		return *prior, true, nil
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return term, false, err
	}
	defer conn.Release()

	barrierKey := deviceBarrierKey(in.DeviceID)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock_shared($1)", barrierKey); err != nil {
		return term, false, err
	}
	barrierHeld := true
	releaseBarrier := func() {
		if barrierHeld {
			_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock_shared($1)", barrierKey)
			barrierHeld = false
		}
	}
	defer releaseBarrier()

	// Phase 1: staging. A terminal error is already persisted (including
	// signature/key/batch validation failures) and returned directly so a
	// retry replays it byte-identically.
	stageTerminal, stageErr := s.stageBatch(ctx, conn.Conn(), in)
	if stageErr != nil {
		if errors.Is(stageErr, errStageFailed) {
			return stageTerminal, false, nil
		}
		return term, false, stageErr
	}

	// Phase 2: leave the staging barrier and exclusively advance.
	releaseBarrier()
	res, advErr := s.advanceDevice(ctx, conn.Conn(), in.DeviceID, in.Events)
	if advErr != nil {
		return term, false, advErr
	}
	term = build(res, nil)
	persisted, uerr := s.recordTerminal(ctx, in.RequestID, term)
	if uerr != nil {
		return term, false, uerr
	}
	return persisted, false, nil
}

// deviceBarrierKey maps a device id to a stable positive advisory-lock key.
func deviceBarrierKey(deviceID string) int64 {
	sum := sha256.Sum256([]byte("telemetry-barrier:" + deviceID))
	v := int64(sum[0])<<56 | int64(sum[1])<<48 | int64(sum[2])<<40 | int64(sum[3])<<32 |
		int64(sum[4])<<24 | int64(sum[5])<<16 | int64(sum[6])<<8 | int64(sum[7])
	return v & 0x7fffffffffffffff
}

// BarrierKey exposes the per-device staging barrier advisory-lock key. Tests
// use it with pg_advisory_lock_shared/unlock_shared to force concurrent
// staging requests to overlap deterministically.
func (s *Store) BarrierKey(deviceID string) int64 { return deviceBarrierKey(deviceID) }

// Pool is already exposed via db.go for raw test access.

// lookupPrior handles every idempotency-record state.
func (s *Store) lookupPrior(ctx context.Context, in *IngestInput) (*Terminal, *Error, error) {
	for attempt := 0; ; attempt++ {
		var storedHash []byte
		var storedBody []byte
		var storedCode *int
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, nil, err
		}
		lookupErr := tx.QueryRow(ctx,
			`SELECT content_hash, response, response_code FROM ingest_requests
			 WHERE request_id=$1`, in.RequestID).
			Scan(&storedHash, &storedBody, &storedCode)
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			return nil, nil, nil
		}
		if lookupErr != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, lookupErr
		}
		if !hashEqual(storedHash, in.ContentHash[:]) {
			_ = tx.Rollback(ctx)
			return nil, errf(CodeRequestContentMismatch,
				"requestId %q was already submitted with different canonical content", in.RequestID).
				WithDetail("requestId", in.RequestID), nil
		}
		if storedCode != nil && len(storedBody) > 0 {
			_ = tx.Rollback(ctx)
			return &Terminal{Status: *storedCode, Body: storedBody}, nil, nil
		}
		_ = tx.Rollback(ctx)
		// The first attempt crashed between staging and response
		// recording. Wait briefly for the concurrent driver to finish,
		// then fall through to re-run staging/advancement ourselves: both
		// are idempotent.
		if attempt >= 100 {
			return nil, nil, nil
		}
		if err := pgSleep(ctx, s.pool, 20*time.Millisecond); err != nil {
			return nil, nil, err
		}
	}
}

// stageBatch runs the all-or-nothing staging transaction on the given
// connection (which already holds the session-shared barrier lock).
//
// A savepoint separates the requestId reservation (kept, even on failure)
// from the candidate work (rolled back on any validation error), so the
// terminal failure response can be committed with the batch's events absent.
func (s *Store) stageBatch(ctx context.Context, conn *pgx.Conn, in *IngestInput) (Terminal, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Terminal{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO ingest_requests(request_id,device_id,content_hash,response)
		 VALUES ($1,$2,$3,NULL)
		 ON CONFLICT (request_id) DO NOTHING`,
		in.RequestID, in.DeviceID, in.ContentHash[:]); err != nil {
		return Terminal{}, err
	}
	var existingHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT content_hash FROM ingest_requests WHERE request_id=$1`,
		in.RequestID).Scan(&existingHash); err != nil {
		return Terminal{}, err
	}
	if !hashEqual(existingHash, in.ContentHash[:]) {
		return Terminal{}, errf(CodeRequestContentMismatch,
			"requestId %q was already submitted with different canonical content", in.RequestID).
			WithDetail("requestId", in.RequestID)
	}

	if _, err := tx.Exec(ctx, "SAVEPOINT staging"); err != nil {
		return Terminal{}, err
	}
	stageErr := s.stageCandidates(tx, ctx, in)
	if stageErr != nil {
		se := asStoreError(stageErr)
		if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT staging"); rerr != nil {
			return Terminal{}, rerr
		}
		failed := Terminal{
			Status: render.HTTPStatusFor(se),
			Body:   render.MustRenderError(se),
		}
		if _, err := tx.Exec(ctx,
			`UPDATE ingest_requests SET response=$2, response_code=$3
			 WHERE request_id=$1 AND response IS NULL`,
			in.RequestID, append([]byte(nil), failed.Body...), failed.Status); err != nil {
			return Terminal{}, err
		}
		stored, err := readBackIngest(tx, ctx, in.RequestID)
		if err != nil {
			return Terminal{}, err
		}
		failed.Body = stored
		if err := tx.Commit(ctx); err != nil {
			return Terminal{}, err
		}
		return failed, errStageFailed
	}
	if err := tx.Commit(ctx); err != nil {
		return Terminal{}, err
	}
	return Terminal{}, nil
}

// errStageFailed tells the caller the batch was rejected with the Terminal
// already committed (no advancement must run).
var errStageFailed = errors.New("stage failed (terminal committed)")

func readBackIngest(tx pgx.Tx, ctx context.Context, requestID string) (json.RawMessage, error) {
	var body []byte
	if err := tx.QueryRow(ctx,
		`SELECT response FROM ingest_requests WHERE request_id=$1`, requestID).Scan(&body); err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// stageCandidates performs validation and candidate insertion; any error
// causes the savepoint to roll back every row it touched.
func (s *Store) stageCandidates(tx pgx.Tx, ctx context.Context, in *IngestInput) error {
	var hwm int64
	if err := tx.QueryRow(ctx,
		`SELECT contiguous_high_watermark FROM devices WHERE device_id=$1 FOR SHARE`,
		in.DeviceID).Scan(&hwm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errf(CodeDeviceNotFound, "device %q not found", in.DeviceID)
		}
		return err
	}
	keys, err := queryKeys(tx, ctx, in.DeviceID)
	if err != nil {
		return err
	}

	seqs := make([]int64, len(in.Events))
	seenSeq := map[int64]struct{}{}
	for i := range in.Events {
		e := &in.Events[i]
		if e.DeviceID != in.DeviceID {
			return errf(CodeBatchMixedDevices, "event deviceId %q does not match batch device %q",
				e.DeviceID, in.DeviceID).WithDetail("index", i)
		}
		if e.Sequence < 1 {
			return errf(CodeValidation, "sequence must be >= 1").WithDetail("index", i)
		}
		if e.EventID == "" {
			return errf(CodeValidation, "eventId is required").WithDetail("index", i)
		}
		if _, dup := seenSeq[e.Sequence]; dup {
			return errf(CodeBatchDuplicate, "duplicate sequence %d within the batch", e.Sequence).
				WithDetail("sequence", e.Sequence)
		}
		seenSeq[e.Sequence] = struct{}{}
		if _, perr := parseDigestText(e.PrevDigest); perr != nil &&
			!(e.Sequence == 1 && e.PrevDigest == GenesisDigest) {
			return errf(CodeValidation, "invalid prevDigest: %s", perr).WithDetail("index", i)
		}
		seqs[i] = e.Sequence

		reqKey, ok := keyForSequence(keys, e.Sequence)
		if !ok {
			return errf(CodeUnknownKeyVersion, "no key generation is valid for sequence %d", e.Sequence).
				WithDetail("sequence", e.Sequence)
		}
		if e.KeyVersion != reqKey.KeyVersion {
			return errf(CodeKeyGenerationMismatch,
				"sequence %d requires keyVersion %d but event used %d",
				e.Sequence, reqKey.KeyVersion, e.KeyVersion).
				WithDetail("sequence", e.Sequence).
				WithDetail("expectedKeyVersion", reqKey.KeyVersion).
				WithDetail("eventKeyVersion", e.KeyVersion)
		}
		if !ed25519.Verify(reqKey.PublicKey, e.SigningInput, e.Signature) {
			return errf(CodeBadSignature, "signature verification failed for sequence %d", e.Sequence).
				WithDetail("sequence", e.Sequence)
		}
	}

	// Insert candidates. The primary key is (device, sequence, digest), so an
	// identical concurrent retry affects no rows and creates no duplicate.
	// Sequences already in the immutable prefix are validated here too.
	existing, err := loadRowsAt(tx, ctx, in.DeviceID, seqs)
	if err != nil {
		return err
	}
	for i := range in.Events {
		e := &in.Events[i]
		rows := existing[e.Sequence]

		if e.Sequence <= hwm {
			var acceptedDigest string
			for _, r := range rows {
				if r.Status == "accepted" {
					acceptedDigest = r.Digest
				}
			}
			if acceptedDigest == "" {
				return fmt.Errorf("store invariant: hwm %d but no accepted event at %d", hwm, e.Sequence)
			}
			if acceptedDigest != e.Digest {
				return errf(CodeSequenceSealed,
					"sequence %d is already part of the immutable contiguous prefix", e.Sequence).
					WithDetail("sequence", e.Sequence)
			}
			continue
		}

		var liveSame, liveOther, rejectedSame bool
		for _, r := range rows {
			switch r.Status {
			case "accepted":
				return fmt.Errorf("store invariant: accepted row above hwm at %d", e.Sequence)
			case "pending", "chosen":
				if r.Digest == e.Digest {
					liveSame = true
				} else {
					liveOther = true
				}
			case "rejected":
				if r.Digest == e.Digest {
					rejectedSame = true
				}
			}
		}
		if liveSame {
			continue
		}
		if rejectedSame {
			if _, err := tx.Exec(ctx,
				`UPDATE events SET status='pending'
				 WHERE device_id=$1 AND sequence=$2 AND digest=$3 AND status='rejected'`,
				in.DeviceID, e.Sequence, e.Digest); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO events(device_id,sequence,digest,event_id,occurred_at,key_version,
			                    prev_digest,payload_canonical,signature,status)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending')
			 ON CONFLICT (device_id,sequence,digest) DO NOTHING`,
			in.DeviceID, e.Sequence, e.Digest, e.EventID, e.OccurredAtCanon, e.KeyVersion,
			e.PrevDigest, e.PayloadCanonical, e.Signature); err != nil {
			return err
		}
		_ = liveOther
	}
	return nil
}

// advanceDevice runs the exclusive advancement transaction on the given
// connection. A transaction-scoped exclusive barrier lock guarantees every
// concurrent staging session has released its shared barrier before this
// transaction can touch candidates.
func (s *Store) advanceDevice(ctx context.Context, conn *pgx.Conn, deviceID string, events []IngestEvent) (*IngestResult, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", deviceBarrierKey(deviceID)); err != nil {
		return nil, err
	}
	d, err := lockDevice(tx, ctx, deviceID)
	if err != nil {
		return nil, err
	}
	_ = d
	touched := make([]int64, len(events))
	for i, e := range events {
		touched[i] = e.Sequence
	}

	// Global divergent-conflict registration and prefix walk happen inside
	// advanceFromLocked; the barrier above guarantees it observes every
	// concurrently staged candidate.
	adv, _, rev, err := advanceFromLocked(tx, ctx, deviceID)
	if err != nil {
		return nil, err
	}

	d2, err := scanDevice(tx.QueryRow(ctx, `SELECT `+scanDeviceCols+` FROM devices WHERE device_id=$1`, deviceID))
	if err != nil {
		return nil, err
	}
	cis, err := conflictsAt(tx, ctx, deviceID, touched)
	if err != nil {
		return nil, err
	}

	// Report the batch's touched sequences for the response; these fields are
	// informational since the watermark and conflicts are authoritative.
	stored, dup, err := classifyTouched(tx, ctx, deviceID, touched)
	if err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`NOTIFY %s, %s`, NotifyChannel,
		quoteLiteral(DeviceChannelToken(deviceID)+":"+itoa(d2.HWM)))); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &IngestResult{
		DeviceID:      deviceID,
		HighWatermark: d2.HWM,
		ConflictRev:   rev,
		Stored:        stored,
		Duplicates:    dup,
		Advanced:      adv,
		Conflicts:     cis,
	}, nil
}

func classifyTouched(tx pgx.Tx, ctx context.Context, deviceID string, seqs []int64) ([]int64, []int64, error) {
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT sequence FROM events WHERE device_id=$1 AND sequence = ANY($2)
		 ORDER BY sequence`, deviceID, seqs)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var stored []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return nil, nil, err
		}
		stored = append(stored, seq)
	}
	return stored, nil, rows.Err()
}

// recordTerminal persists the final response for a requestId and returns the
// bytes exactly as they will be read back. jsonb normalizes key order, so
// every response (first call or replay) must be served from the stored bytes
// to guarantee byte-identical idempotent results.
//
// The UPDATE only fills a still-NULL response: when two identical requests
// race, the response of the first committer wins and is never overwritten.
func (s *Store) recordTerminal(ctx context.Context, requestID string, term Terminal) (Terminal, error) {
	if _, err := s.pool.Exec(ctx,
		`UPDATE ingest_requests SET response=$2, response_code=$3
		 WHERE request_id=$1 AND response IS NULL`,
		requestID, append([]byte(nil), term.Body...), term.Status); err != nil {
		return term, err
	}
	var stored []byte
	var code int
	if err := s.pool.QueryRow(ctx,
		`SELECT response, response_code FROM ingest_requests WHERE request_id=$1`,
		requestID).Scan(&stored, &code); err != nil {
		return term, err
	}
	return Terminal{Status: code, Body: stored}, nil
}

type eventRow struct {
	Sequence   int64
	Digest     string
	EventID    string
	KeyVersion int
	PrevDigest string
	Status     string
	FirstSeen  time.Time
}

func loadRowsAt(tx pgx.Tx, ctx context.Context, deviceID string, seqs []int64) (map[int64][]eventRow, error) {
	out := map[int64][]eventRow{}
	rows, err := tx.Query(ctx,
		`SELECT sequence,digest,event_id,key_version,prev_digest,status,first_seen
		 FROM events WHERE device_id=$1 AND sequence = ANY($2)`, deviceID, seqs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r eventRow
		if err := rows.Scan(&r.Sequence, &r.Digest, &r.EventID, &r.KeyVersion,
			&r.PrevDigest, &r.Status, &r.FirstSeen); err != nil {
			return nil, err
		}
		out[r.Sequence] = append(out[r.Sequence], r)
	}
	return out, rows.Err()
}

// keyForSequence returns the generation whose effective range contains seq:
// generation i covers [effective_i, effective_{i+1}-1); the last covers
// [effective_last, +inf).
func keyForSequence(keys []KeyGen, seq int64) (KeyGen, bool) {
	best := KeyGen{}
	found := false
	for _, k := range keys {
		if seq >= k.EffectiveSequence {
			best, found = k, true
		}
	}
	return best, found
}

// advanceFromLocked walks the contiguous prefix while holding the device row
// update lock. Before walking, it registers divergent conflicts for EVERY
// sequence that has two or more live candidates (not just the frontier), so a
// divergence staged beyond a gap is visible even if the process crashed
// between staging and advancement. Returns accepted sequences,
// conflict-change sequences and the resulting conflict_revision.
func advanceFromLocked(tx pgx.Tx, ctx context.Context, deviceID string) ([]int64, []int64, int64, error) {
	var hwm, rev int64
	if err := tx.QueryRow(ctx,
		`SELECT contiguous_high_watermark,conflict_revision FROM devices WHERE device_id=$1`,
		deviceID).Scan(&hwm, &rev); err != nil {
		return nil, nil, 0, err
	}
	var accepted, changedSeqs []int64

	divergentRows, err := tx.Query(ctx,
		`SELECT sequence FROM events
		 WHERE device_id=$1 AND status IN ('pending','chosen')
		 GROUP BY sequence HAVING COUNT(*) >= 2
		 ORDER BY sequence`, deviceID)
	if err != nil {
		return nil, nil, 0, err
	}
	var divergent []int64
	for divergentRows.Next() {
		var seq int64
		if err := divergentRows.Scan(&seq); err != nil {
			divergentRows.Close()
			return nil, nil, 0, err
		}
		divergent = append(divergent, seq)
	}
	divergentRows.Close()
	if err := divergentRows.Err(); err != nil {
		return nil, nil, 0, err
	}
	for _, seq := range divergent {
		changed, err := upsertConflict(tx, ctx, deviceID, seq, "divergent_candidates", nil)
		if err != nil {
			return nil, nil, 0, err
		}
		if changed {
			if rev, err = bumpConflictRevision(tx, ctx, deviceID); err != nil {
				return nil, nil, 0, err
			}
			changedSeqs = append(changedSeqs, seq)
		}
	}
	headDigest := GenesisDigest
	if hwm > 0 {
		if err := tx.QueryRow(ctx,
			`SELECT digest FROM events WHERE device_id=$1 AND sequence=$2 AND status='accepted'`,
			deviceID, hwm).Scan(&headDigest); err != nil {
			return nil, nil, 0, err
		}
	}

	for {
		next := hwm + 1
		rows, err := queryLive(tx, ctx, deviceID, next)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(rows) == 0 {
			break
		}
		if len(rows) > 1 {
			changed, err := upsertConflict(tx, ctx, deviceID, next, "divergent_candidates", nil)
			if err != nil {
				return nil, nil, 0, err
			}
			if changed {
				if rev, err = bumpConflictRevision(tx, ctx, deviceID); err != nil {
					return nil, nil, 0, err
				}
				changedSeqs = append(changedSeqs, next)
			}
			break
		}
		cand := rows[0]
		if cand.PrevDigest != headDigest {
			changed, err := upsertConflict(tx, ctx, deviceID, next, "wrong_predecessor", nil)
			if err != nil {
				return nil, nil, 0, err
			}
			if changed {
				if rev, err = bumpConflictRevision(tx, ctx, deviceID); err != nil {
					return nil, nil, 0, err
				}
				changedSeqs = append(changedSeqs, next)
			}
			break
		}

		if _, err := tx.Exec(ctx,
			`UPDATE events SET status='accepted', accepted_at=now()
			 WHERE device_id=$1 AND sequence=$2 AND digest=$3 AND status IN ('pending','chosen')`,
			deviceID, next, cand.Digest); err != nil {
			return nil, nil, 0, err
		}
		if err := resolveBlockingConflict(tx, ctx, deviceID, next, &rev, &changedSeqs); err != nil {
			return nil, nil, 0, err
		}
		if ct, err := tx.Exec(ctx,
			`UPDATE devices SET contiguous_high_watermark=$2, updated_at=now()
			 WHERE device_id=$3 AND contiguous_high_watermark=$1`,
			hwm, next, deviceID); err != nil {
			return nil, nil, 0, err
		} else if ct.RowsAffected() != 1 {
			return nil, nil, 0, fmt.Errorf("store invariant: watermark advanced concurrently")
		}
		accepted = append(accepted, next)
		hwm = next
		headDigest = cand.Digest
	}
	return accepted, changedSeqs, rev, nil
}

// resolveBlockingConflict closes an open conflict once its single live
// candidate has been verified and accepted.
func resolveBlockingConflict(tx pgx.Tx, ctx context.Context, deviceID string, seq int64,
	rev *int64, changedSeqs *[]int64) error {
	ct, err := tx.Exec(ctx,
		`UPDATE conflicts SET status='resolved', resolved_at=now(),
		                       revision=(SELECT conflict_revision FROM devices WHERE device_id=$1)+1
		 WHERE device_id=$1 AND sequence=$2 AND status='open'`,
		deviceID, seq)
	if err != nil {
		return err
	}
	if ct.RowsAffected() > 0 {
		r, err := bumpConflictRevision(tx, ctx, deviceID)
		if err != nil {
			return err
		}
		*rev = r
		*changedSeqs = append(*changedSeqs, seq)
	}
	return nil
}

func queryLive(tx pgx.Tx, ctx context.Context, deviceID string, seq int64) ([]eventRow, error) {
	rows, err := tx.Query(ctx,
		`SELECT sequence,digest,event_id,key_version,prev_digest,status,first_seen
		 FROM events WHERE device_id=$1 AND sequence=$2
		   AND status IN ('pending','chosen')`, deviceID, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []eventRow
	for rows.Next() {
		var r eventRow
		if err := rows.Scan(&r.Sequence, &r.Digest, &r.EventID, &r.KeyVersion,
			&r.PrevDigest, &r.Status, &r.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// upsertConflict ensures an open conflict with the given reason exists.
// Returns true when the conflict state changed.
func upsertConflict(tx pgx.Tx, ctx context.Context, deviceID string, seq int64,
	reason string, chosenDigest *string) (bool, error) {
	var curReason, curStatus string
	err := tx.QueryRow(ctx,
		`SELECT reason,status FROM conflicts WHERE device_id=$1 AND sequence=$2`,
		deviceID, seq).Scan(&curReason, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO conflicts(device_id,sequence,reason,status,revision,chosen_digest)
			 SELECT $1,$2,$3,'open',conflict_revision+1,$4 FROM devices WHERE device_id=$1`,
			deviceID, seq, reason, chosenDigest); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if curStatus == "open" && curReason == reason {
		if chosenDigest != nil {
			if _, err := tx.Exec(ctx,
				`UPDATE conflicts SET chosen_digest=$3 WHERE device_id=$1 AND sequence=$2`,
				deviceID, seq, *chosenDigest); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE conflicts SET reason=$3,status='open',resolution=NULL,resolved_at=NULL,
		                       opened_at=now(),
		                       revision=(SELECT conflict_revision+1 FROM devices WHERE device_id=$1),
		                       chosen_digest=COALESCE($4, chosen_digest)
		 WHERE device_id=$1 AND sequence=$2`,
		deviceID, seq, reason, chosenDigest); err != nil {
		return false, err
	}
	return true, nil
}

func bumpConflictRevision(tx pgx.Tx, ctx context.Context, deviceID string) (int64, error) {
	row := tx.QueryRow(ctx,
		`UPDATE devices SET conflict_revision=conflict_revision+1, updated_at=now()
		 WHERE device_id=$1 RETURNING conflict_revision`, deviceID)
	var rev int64
	if err := row.Scan(&rev); err != nil {
		return 0, err
	}
	return rev, nil
}

func conflictsAt(tx pgx.Tx, ctx context.Context, deviceID string, seqs []int64) ([]ConflictInfo, error) {
	rows, err := tx.Query(ctx,
		`SELECT sequence,reason,status,revision,resolution,COALESCE(chosen_digest,'')
		 FROM conflicts WHERE device_id=$1 AND sequence = ANY($2) ORDER BY sequence`,
		deviceID, seqs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConflictInfo
	for rows.Next() {
		var c ConflictInfo
		var res *string
		if err := rows.Scan(&c.Sequence, &c.Reason, &c.Status, &c.Revision, &res, &c.ChosenDigest); err != nil {
			return nil, err
		}
		if res != nil {
			c.Resolution = res
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListOpenConflicts returns all open conflicts for a device with candidates.
func (s *Store) ListOpenConflicts(ctx context.Context, deviceID string) ([]ConflictInfo, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		`SELECT sequence,reason,status,revision,resolution,COALESCE(chosen_digest,'')
		 FROM conflicts WHERE device_id=$1 AND status='open' ORDER BY sequence`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConflictInfo
	for rows.Next() {
		var c ConflictInfo
		var res *string
		if err := rows.Scan(&c.Sequence, &c.Reason, &c.Status, &c.Revision, &res, &c.ChosenDigest); err != nil {
			return nil, err
		}
		if res != nil {
			c.Resolution = res
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cands, err := candidatesFor(tx, ctx, deviceID, out[i].Sequence)
		if err != nil {
			return nil, err
		}
		out[i].Candidates = cands
	}
	return out, tx.Commit(ctx)
}

func candidatesFor(tx pgx.Tx, ctx context.Context, deviceID string, seq int64) ([]CandidateInfo, error) {
	rows, err := tx.Query(ctx,
		`SELECT digest,event_id,key_version,status,first_seen FROM events
		 WHERE device_id=$1 AND sequence=$2 ORDER BY first_seen,digest`, deviceID, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CandidateInfo
	for rows.Next() {
		var c CandidateInfo
		if err := rows.Scan(&c.Digest, &c.EventID, &c.KeyVersion, &c.Status, &c.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetConflict returns one conflict with its candidates.
func (s *Store) GetConflict(ctx context.Context, deviceID string, seq int64) (*ConflictInfo, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var c ConflictInfo
	var res *string
	err = tx.QueryRow(ctx,
		`SELECT sequence,reason,status,revision,resolution,COALESCE(chosen_digest,'')
		 FROM conflicts WHERE device_id=$1 AND sequence=$2`, deviceID, seq).
		Scan(&c.Sequence, &c.Reason, &c.Status, &c.Revision, &res, &c.ChosenDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeConflictNotFound, "no conflict at sequence %d", seq)
	}
	if err != nil {
		return nil, err
	}
	if res != nil {
		c.Resolution = res
	}
	c.Candidates, err = candidatesFor(tx, ctx, deviceID, seq)
	if err != nil {
		return nil, err
	}
	return &c, tx.Commit(ctx)
}

// helpers -------------------------------------------------------------------

func hashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(n int64) string { return fmt.Sprintf("%d", n) }

// quoteLiteral safely quotes a string for use as a NOTIFY payload literal.
func quoteLiteral(s string) string {
	return "'" + pgQuoteReplace(s) + "'"
}

func pgQuoteReplace(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\'' {
			out = append(out, '\'')
		}
		out = append(out, r)
	}
	return string(out)
}

func asStoreError(err error) *Error {
	var se *Error
	if errors.As(err, &se) {
		return se
	}
	return &Error{Code: "internal_error", Message: err.Error()}
}

// parseDigestText mirrors the canonical textual digest format
// ("sha256:" + 64 lowercase hex chars) without importing extra packages.
func parseDigestText(s string) ([32]byte, error) {
	var out [32]byte
	const p = "sha256:"
	if len(s) != len(p)+64 || s[:len(p)] != p {
		return out, fmt.Errorf("malformed digest")
	}
	if _, err := hex.Decode(out[:], []byte(s[len(p):])); err != nil {
		return out, fmt.Errorf("malformed digest")
	}
	return out, nil
}
