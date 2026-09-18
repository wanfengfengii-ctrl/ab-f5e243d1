package store

import "telemetry/internal/apierr"

// Error is an alias so store code can keep using its local name while the
// canonical definition lives in the leaf package apierr.
type Error = apierr.Error

// errf builds a structured store error.
func errf(code, format string, args ...any) *Error {
	return apierr.New(code, format, args...)
}

// Re-exported stable codes.
const (
	CodeDeviceExists             = apierr.CodeDeviceExists
	CodeDeviceNotFound           = apierr.CodeDeviceNotFound
	CodeControlRevisionStale     = apierr.CodeControlRevisionStale
	CodeConflictRevisionStale    = apierr.CodeConflictRevisionStale
	CodeDuplicateKeyVersion      = apierr.CodeDuplicateKeyVersion
	CodeRotationOverlap          = apierr.CodeRotationOverlap
	CodeRotationBoundaryOccupied = apierr.CodeRotationBoundaryOccupied
	CodeRotationEffectiveTooLow  = apierr.CodeRotationEffectiveTooLow
	CodeRequestContentMismatch   = apierr.CodeRequestContentMismatch
	CodeCommandContentMismatch   = apierr.CodeCommandContentMismatch
	CodeBatchInvalid             = apierr.CodeBatchInvalid
	CodeBatchMixedDevices        = apierr.CodeBatchMixedDevices
	CodeBatchDuplicate           = apierr.CodeBatchDuplicate
	CodeValidation               = apierr.CodeValidation
	CodeUnknownKeyVersion        = apierr.CodeUnknownKeyVersion
	CodeKeyGenerationMismatch    = apierr.CodeKeyGenerationMismatch
	CodeBadSignature             = apierr.CodeBadSignature
	CodeSequenceSealed           = apierr.CodeSequenceSealed
	CodeConflictNotFound         = apierr.CodeConflictNotFound
	CodeConflictAlreadyResolved  = apierr.CodeConflictAlreadyResolved
	CodeCandidateNotFound        = apierr.CodeCandidateNotFound
	CodeCandidateBadPredecessor  = apierr.CodeCandidateBadPredecessor
	CodeViewNotFound             = apierr.CodeViewNotFound
	CodeViewExpired              = apierr.CodeViewExpired
	CodeCursorInvalid            = apierr.CodeCursorInvalid
	CodeCursorStale              = apierr.CodeCursorStale
	CodeBeforeCheckpoint         = apierr.CodeBeforeCheckpoint
	CodeCheckpointUnavailable    = apierr.CodeCheckpointUnavailable
	CodeCompactionNotPossible    = apierr.CodeCompactionNotPossible
	CodeUnsupportedMediaType     = apierr.CodeUnsupportedMediaType
	CodeRequestBodyTooLarge      = apierr.CodeRequestBodyTooLarge
	CodeUnauthorized             = apierr.CodeUnauthorized
	CodeInvalidJSON              = apierr.CodeInvalidJSON
	CodeTimeoutInvalid           = apierr.CodeTimeoutInvalid
)
