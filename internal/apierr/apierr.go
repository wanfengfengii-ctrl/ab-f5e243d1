// Package apierr holds the structured error type and stable machine codes
// shared by the store, render and HTTP packages without import cycles.
package apierr

import "fmt"

// Error is a structured error carrying a stable machine code.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code + ": " + e.Message
}

// WithDetail attaches a detail value and returns the same error.
func (e *Error) WithDetail(k string, v any) *Error {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details[k] = v
	return e
}

// New builds an Error.
func New(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Stable error codes.
const (
	CodeDeviceExists             = "device_exists"
	CodeDeviceNotFound           = "device_not_found"
	CodeControlRevisionStale     = "control_revision_stale"
	CodeConflictRevisionStale    = "conflict_revision_stale"
	CodeDuplicateKeyVersion      = "duplicate_key_version"
	CodeRotationOverlap          = "rotation_overlapping_effective_range"
	CodeRotationBoundaryOccupied = "rotation_boundary_occupied"
	CodeRotationEffectiveTooLow  = "rotation_effective_sequence_too_low"
	CodeRequestContentMismatch   = "idempotency_content_mismatch"
	CodeCommandContentMismatch   = "command_content_mismatch"
	CodeBatchInvalid             = "batch_invalid"
	CodeBatchMixedDevices        = "batch_mixed_devices"
	CodeBatchDuplicate           = "batch_duplicate_sequence"
	CodeValidation               = "validation_error"
	CodeUnknownKeyVersion        = "unknown_key_version"
	CodeKeyGenerationMismatch    = "key_generation_mismatch"
	CodeBadSignature             = "bad_signature"
	CodeSequenceSealed           = "sequence_sealed"
	CodeConflictNotFound         = "conflict_not_found"
	CodeConflictAlreadyResolved  = "conflict_already_resolved"
	CodeCandidateNotFound        = "candidate_not_found"
	CodeCandidateBadPredecessor  = "candidate_bad_predecessor"
	CodeViewNotFound             = "view_not_found"
	CodeViewExpired              = "view_expired"
	CodeCursorInvalid            = "invalid_cursor"
	CodeCursorStale              = "cursor_stale"
	CodeBeforeCheckpoint         = "before_checkpoint"
	CodeCheckpointUnavailable    = "checkpoint_unavailable"
	CodeCompactionNotPossible    = "compaction_not_possible"
	CodeUnsupportedMediaType     = "unsupported_media_type"
	CodeRequestBodyTooLarge      = "request_body_too_large"
	CodeUnauthorized             = "unauthorized"
	CodeInvalidJSON              = "invalid_json"
	CodeTimeoutInvalid           = "invalid_timeout"
)
