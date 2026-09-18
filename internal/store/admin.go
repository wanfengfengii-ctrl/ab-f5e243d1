package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"telemetry/internal/render"
)

// AdminOutcome is the result of an idempotent management command.
type AdminOutcome struct {
	Replayed bool
	Status   int
	Body     json.RawMessage
	Device   *Device
}

// beginCommand locks the commandId. A prior record either replays (same
// content hash) or produces a stable mismatch conflict. Returns (replayed,
// outcome). On a fresh command the caller continues within tx.
//
// The content hash covers commandType as well as the canonical command body,
// so the same commandId cannot be silently reused for a different command.
func beginCommand(tx pgx.Tx, ctx context.Context, commandID, commandType, deviceID string,
	contentHash [32]byte) (bool, *AdminOutcome, error) {
	var gotType, gotDevice *string
	var gotHash []byte
	var gotCode int
	var gotBody []byte
	err := tx.QueryRow(ctx,
		`SELECT command_type,device_id,content_hash,response_code,response
		 FROM admin_commands WHERE command_id=$1 FOR UPDATE`, commandID).
		Scan(&gotType, &gotDevice, &gotHash, &gotCode, &gotBody)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO admin_commands(command_id,command_type,device_id,content_hash,response_code,response)
			 VALUES ($1,$2,$3,$4,0,'{}'::jsonb)`,
			commandID, commandType, nullableString(deviceID), contentHash[:]); err != nil {
			return false, nil, err
		}
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	_ = gotType
	_ = gotDevice
	if !hashEqual(gotHash, contentHash[:]) {
		return true, &AdminOutcome{
			Replayed: true,
			Status:   409,
			Body:     json.RawMessage(`{"error":{"code":"command_content_mismatch","message":"commandId was already used with different content"}}`),
		}, nil
	}
	return true, &AdminOutcome{Replayed: true, Status: gotCode, Body: gotBody}, nil
}

func finishCommand(tx pgx.Tx, ctx context.Context, commandID string, status int, body []byte) error {
	_, err := tx.Exec(ctx,
		`UPDATE admin_commands SET response_code=$2,response=$3 WHERE command_id=$1`,
		commandID, status, body)
	return err
}

// readBackCommand returns the jsonb-normalized stored response so first call
// and replay are byte-identical.
func readBackCommand(tx pgx.Tx, ctx context.Context, commandID string) (json.RawMessage, error) {
	var body []byte
	if err := tx.QueryRow(ctx,
		`SELECT response FROM admin_commands WHERE command_id=$1`, commandID).Scan(&body); err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RotateKeyAdmin performs an idempotent key rotation guarded by a command
// record. render builds the success body from the post-rotation device.
func (s *Store) RotateKeyAdmin(ctx context.Context, commandID, deviceID string, contentHash [32]byte,
	newVersion int, newPublicKey ed25519.PublicKey, effectiveSequence, expectedControlRevision int64,
	render func(*RotateKeyResult) (int, json.RawMessage, *Error)) (*AdminOutcome, error) {

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	replayed, prior, err := beginCommand(tx, ctx, commandID, "rotate_key", deviceID, contentHash)
	if err != nil {
		return nil, err
	}
	if replayed {
		return prior, tx.Commit(ctx)
	}

	res, serr := s.rotateKeyTx(tx, ctx, deviceID, newVersion, newPublicKey, effectiveSequence, expectedControlRevision)
	var status int
	var body json.RawMessage
	if serr != nil {
		status, body = errorResponse(serr)
	} else {
		status, body, serr = render(res)
		if serr != nil {
			status, body = errorResponse(serr)
		}
	}
	if err := finishCommand(tx, ctx, commandID, status, body); err != nil {
		return nil, err
	}
	storedBody, err := readBackCommand(tx, ctx, commandID)
	if err != nil {
		return nil, err
	}
	body = storedBody
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AdminOutcome{Replayed: false, Status: status, Body: body, Device: deviceOf(res)}, nil
}

func deviceOf(r *RotateKeyResult) *Device {
	if r == nil {
		return nil
	}
	return r.Device
}

func (s *Store) rotateKeyTx(tx pgx.Tx, ctx context.Context, deviceID string, newVersion int,
	newPublicKey ed25519.PublicKey, effectiveSequence, expectedControlRevision int64) (*RotateKeyResult, *Error) {

	// Wait for every in-flight ingest staging transaction to finish so the
	// boundary-occupation check and key-generation view are complete.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", deviceBarrierKey(deviceID)); err != nil {
		return nil, asStoreError(err)
	}
	d, err := lockDevice(tx, ctx, deviceID)
	if err != nil {
		return nil, asStoreError(err)
	}
	if d.ControlRevision != expectedControlRevision {
		return nil, errf(CodeControlRevisionStale,
			"control revision mismatch: expected %d, current %d", expectedControlRevision, d.ControlRevision).
			WithDetail("expected", expectedControlRevision).WithDetail("current", d.ControlRevision)
	}
	keys, err := queryKeys(tx, ctx, deviceID)
	if err != nil {
		return nil, asStoreError(err)
	}
	for _, k := range keys {
		if k.KeyVersion == newVersion {
			return nil, errf(CodeDuplicateKeyVersion,
				"keyVersion %d already exists for device %q", newVersion, deviceID).
				WithDetail("keyVersion", newVersion)
		}
	}
	latest := keys[len(keys)-1]
	if newVersion <= latest.KeyVersion {
		return nil, errf(CodeDuplicateKeyVersion,
			"keyVersion %d must be greater than the latest version %d",
			newVersion, latest.KeyVersion).
			WithDetail("keyVersion", newVersion).
			WithDetail("latestKeyVersion", latest.KeyVersion)
	}
	if effectiveSequence <= d.HWM {
		return nil, errf(CodeRotationEffectiveTooLow,
			"effectiveSequence %d must be strictly greater than contiguous watermark %d",
			effectiveSequence, d.HWM).
			WithDetail("effectiveSequence", effectiveSequence).WithDetail("highWatermark", d.HWM)
	}
	if effectiveSequence <= latest.EffectiveSequence {
		return nil, errf(CodeRotationOverlap,
			"effectiveSequence %d must exceed previous generation's effectiveSequence %d",
			effectiveSequence, latest.EffectiveSequence).
			WithDetail("effectiveSequence", effectiveSequence).
			WithDetail("previousEffectiveSequence", latest.EffectiveSequence)
	}
	// The new effective range must not contain any already-staged candidate.
	// Such candidates could only have been signed by the then-current old
	// generation; accepting the rotation would make their key generation
	// invalid forever. Reject deterministically and let the caller choose an
	// effectiveSequence past the furthest staged candidate.
	var occupiedAt, occupiedBeyond int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0) FROM events
		 WHERE device_id=$1 AND sequence>=$2
		   AND status IN ('pending','chosen','accepted')`,
		deviceID, effectiveSequence).Scan(&occupiedAt, &occupiedBeyond); err != nil {
		return nil, asStoreError(err)
	}
	if occupiedAt > 0 {
		return nil, errf(CodeRotationBoundaryOccupied,
			"staged events already occupy sequences [%d,%d]; effectiveSequence must be greater than %d",
			occupiedAt, occupiedBeyond, occupiedBeyond).
			WithDetail("effectiveSequence", effectiveSequence).
			WithDetail("firstOccupied", occupiedAt).
			WithDetail("lastOccupied", occupiedBeyond)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO device_keys(device_id,key_version,public_key,effective_sequence)
		 VALUES ($1,$2,$3,$4)`,
		deviceID, newVersion, []byte(newPublicKey), effectiveSequence); err != nil {
		return nil, asStoreError(err)
	}
	d2, err := bumpControlRevision(tx, ctx, deviceID)
	if err != nil {
		return nil, asStoreError(err)
	}
	return &RotateKeyResult{
		Device:  d2,
		Key:     &KeyGen{KeyVersion: newVersion, PublicKey: append([]byte(nil), newPublicKey...), EffectiveSequence: effectiveSequence},
		Created: true,
	}, nil
}

// AdjudicationDecision enumerates supported resolutions.
const (
	DecisionChooseCandidate = "choose_candidate"
	DecisionRejectAll       = "reject_all"
)

// Adjudicate resolves a conflict atomically and then attempts to advance the
// contiguous watermark. expectedConflictRevision must equal the device's
// current conflict revision.
func (s *Store) Adjudicate(ctx context.Context, commandID, deviceID string, contentHash [32]byte,
	seq int64, expectedConflictRevision int64, decision, candidateDigest string,
	render func(*AdjudicationResult) (int, json.RawMessage, *Error)) (*AdminOutcome, error) {

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	replayed, prior, err := beginCommand(tx, ctx, commandID, "adjudicate", deviceID, contentHash)
	if err != nil {
		return nil, err
	}
	if replayed {
		return prior, tx.Commit(ctx)
	}

	res, serr := s.adjudicateTx(tx, ctx, deviceID, seq, expectedConflictRevision, decision, candidateDigest)
	var status int
	var body json.RawMessage
	if serr != nil {
		status, body = errorResponse(serr)
	} else {
		status, body, serr = render(res)
		if serr != nil {
			status, body = errorResponse(serr)
		}
	}
	if err := finishCommand(tx, ctx, commandID, status, body); err != nil {
		return nil, err
	}
	storedBody, err := readBackCommand(tx, ctx, commandID)
	if err != nil {
		return nil, err
	}
	body = storedBody
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	var dev *Device
	if res != nil {
		dev = res.Device
	}
	return &AdminOutcome{Replayed: false, Status: status, Body: body, Device: dev}, nil
}

// AdjudicationResult is the post-commit projection for response rendering.
type AdjudicationResult struct {
	Device           *Device
	Sequence         int64
	Decision         string
	ChosenDigest     string
	Advanced         []int64
	HighWatermark    int64
	ConflictRev      int64
	ConflictReopener string // reason when advancement re-blocked the sequence
}

func (s *Store) adjudicateTx(tx pgx.Tx, ctx context.Context, deviceID string, seq int64,
	expectedRevision int64, decision, candidateDigest string) (*AdjudicationResult, *Error) {

	// Barrier: adjudication and advancement must observe all concurrently
	// staged candidates.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", deviceBarrierKey(deviceID)); err != nil {
		return nil, asStoreError(err)
	}
	d, gerr := lockDevice(tx, ctx, deviceID)
	if gerr != nil {
		return nil, asStoreError(gerr)
	}
	if d.ConflictRevision != expectedRevision {
		return nil, errf(CodeConflictRevisionStale,
			"conflict revision mismatch: expected %d, current %d", expectedRevision, d.ConflictRevision).
			WithDetail("expected", expectedRevision).WithDetail("current", d.ConflictRevision)
	}

	var reason, status string
	err := tx.QueryRow(ctx,
		`SELECT reason,status FROM conflicts WHERE device_id=$1 AND sequence=$2 FOR UPDATE`,
		deviceID, seq).Scan(&reason, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errf(CodeConflictNotFound, "no conflict at sequence %d", seq).
			WithDetail("sequence", seq)
	}
	if err != nil {
		return nil, asStoreError(err)
	}
	if status != "open" {
		return nil, errf(CodeConflictAlreadyResolved,
			"conflict at sequence %d is already resolved", seq).WithDetail("sequence", seq)
	}

	res := &AdjudicationResult{Device: d, Sequence: seq, Decision: decision}

	switch decision {
	case DecisionRejectAll:
		ct, err := tx.Exec(ctx,
			`UPDATE events SET status='rejected'
			 WHERE device_id=$1 AND sequence=$2 AND status IN ('pending','chosen')`,
			deviceID, seq)
		if err != nil {
			return nil, asStoreError(err)
		}
		if ct.RowsAffected() == 0 {
			return nil, errf(CodeCandidateNotFound, "no live candidates at sequence %d", seq)
		}
		if err := closeConflict(tx, ctx, deviceID, seq, DecisionRejectAll, ""); err != nil {
			return nil, err
		}

	case DecisionChooseCandidate:
		if candidateDigest == "" {
			return nil, errf(CodeValidation, "candidateDigest is required for choose_candidate")
		}
		var candStatus string
		err := tx.QueryRow(ctx,
			`SELECT status FROM events WHERE device_id=$1 AND sequence=$2 AND digest=$3 FOR UPDATE`,
			deviceID, seq, candidateDigest).Scan(&candStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errf(CodeCandidateNotFound,
				"candidate %s not found at sequence %d", candidateDigest, seq).
				WithDetail("candidateDigest", candidateDigest)
		}
		if err != nil {
			return nil, asStoreError(err)
		}
		if candStatus == "rejected" {
			return nil, errf(CodeCandidateNotFound,
				"candidate %s was previously rejected", candidateDigest)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE events SET status='rejected'
			 WHERE device_id=$1 AND sequence=$2 AND status IN ('pending','chosen') AND digest<>$3`,
			deviceID, seq, candidateDigest); err != nil {
			return nil, asStoreError(err)
		}
		if candStatus == "pending" {
			if _, err := tx.Exec(ctx,
				`UPDATE events SET status='chosen'
				 WHERE device_id=$1 AND sequence=$2 AND digest=$3`,
				deviceID, seq, candidateDigest); err != nil {
				return nil, asStoreError(err)
			}
		}
		if err := closeConflict(tx, ctx, deviceID, seq, DecisionChooseCandidate, candidateDigest); err != nil {
			return nil, err
		}
		res.ChosenDigest = candidateDigest

	default:
		return nil, errf(CodeValidation, "decision must be %q or %q",
			DecisionChooseCandidate, DecisionRejectAll)
	}

	// Try to extend the contiguous prefix. If the chosen candidate does not
	// chain to its predecessor, advancement deterministically reopens the
	// conflict with reason wrong_predecessor.
	adv, _, rev, err := advanceFromLocked(tx, ctx, deviceID)
	if err != nil {
		return nil, asStoreError(err)
	}
	res.Advanced = adv
	res.ConflictRev = rev
	d2, gerr := s.getDeviceTx(tx, ctx, deviceID)
	if gerr != nil {
		return nil, asStoreError(gerr)
	}
	res.Device = d2
	res.HighWatermark = d2.HWM
	if len(adv) > 0 {
		if _, nerr := tx.Exec(ctx, fmt.Sprintf(
			`NOTIFY %s, %s`, NotifyChannel,
			quoteLiteral(DeviceChannelToken(deviceID)+":"+itoa(d2.HWM)))); nerr != nil {
			return nil, asStoreError(nerr)
		}
	}
	var openReason string
	if err := tx.QueryRow(ctx,
		`SELECT reason FROM conflicts WHERE device_id=$1 AND sequence=$2 AND status='open'`,
		deviceID, seq).Scan(&openReason); err == nil {
		res.ConflictReopener = openReason
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, asStoreError(err)
	}
	return res, nil
}

func (s *Store) getDeviceTx(tx pgx.Tx, ctx context.Context, deviceID string) (*Device, error) {
	row := tx.QueryRow(ctx, `SELECT `+scanDeviceCols+` FROM devices WHERE device_id=$1`, deviceID)
	return scanDevice(row)
}

func closeConflict(tx pgx.Tx, ctx context.Context, deviceID string, seq int64,
	decision, chosenDigest string) *Error {
	// Persisted resolution vocabulary differs from the API decision verb.
	resolution := "rejected_all"
	if decision == DecisionChooseCandidate {
		resolution = "chose_candidate"
	}
	if _, err := tx.Exec(ctx,
		`UPDATE conflicts SET status='resolved', resolution=$3, chosen_digest=$4,
		                       resolved_at=now(),
		                       revision=(SELECT conflict_revision+1 FROM devices WHERE device_id=$1)
		 WHERE device_id=$1 AND sequence=$2`,
		deviceID, seq, resolution, chosenDigest); err != nil {
		return asStoreError(err)
	}
	if _, err := bumpConflictRevision(tx, ctx, deviceID); err != nil {
		return asStoreError(err)
	}
	return nil
}

// errorResponse renders the canonical error body shared by admin commands.
func errorResponse(se *Error) (int, json.RawMessage) {
	return render.HTTPStatusFor(se), json.RawMessage(render.MustRenderError(se))
}
