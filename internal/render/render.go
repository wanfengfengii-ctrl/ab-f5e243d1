// Package render renders the service's canonical structured error documents
// and maps store error codes to HTTP status codes. It is shared by the store
// (which persists terminal responses for idempotent replays) and the HTTP
// layer.
package render

import (
	"encoding/json"

	"telemetry/internal/apierr"
)

// HTTPStatusFor maps an error code to an HTTP status.
func HTTPStatusFor(se *apierr.Error) int {
	switch se.Code {
	case apierr.CodeDeviceExists:
		return 409
	case apierr.CodeDeviceNotFound, apierr.CodeConflictNotFound, apierr.CodeCandidateNotFound:
		return 404
	case apierr.CodeControlRevisionStale, apierr.CodeConflictRevisionStale:
		return 409
	case apierr.CodeDuplicateKeyVersion, apierr.CodeRotationOverlap,
		apierr.CodeRotationBoundaryOccupied, apierr.CodeRotationEffectiveTooLow:
		return 409
	case apierr.CodeRequestContentMismatch, apierr.CodeCommandContentMismatch:
		return 409
	case apierr.CodeConflictAlreadyResolved:
		return 409
	case apierr.CodeUnauthorized:
		return 401
	case apierr.CodeRequestBodyTooLarge:
		return 413
	case apierr.CodeUnsupportedMediaType:
		return 415
	case apierr.CodeViewExpired:
		return 410
	case apierr.CodeBeforeCheckpoint:
		return 410
	case apierr.CodeCursorStale, apierr.CodeCursorInvalid:
		return 400
	case apierr.CodeBatchInvalid, apierr.CodeBatchMixedDevices, apierr.CodeBatchDuplicate,
		apierr.CodeValidation, apierr.CodeInvalidJSON, apierr.CodeTimeoutInvalid:
		return 400
	case apierr.CodeUnknownKeyVersion, apierr.CodeKeyGenerationMismatch,
		apierr.CodeBadSignature, apierr.CodeSequenceSealed, apierr.CodeCandidateBadPredecessor:
		return 422
	default:
		return 500
	}
}

// ErrorBody is the canonical error envelope: {"error":{code,message,details}}.
type ErrorBody struct {
	Error ErrorPayload `json:"error"`
}

// ErrorPayload carries a stable code and optional details.
type ErrorPayload struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// MustRenderError renders an error document; it cannot fail for the inputs
// produced by this service.
func MustRenderError(se *apierr.Error) []byte {
	b, err := json.Marshal(ErrorBody{Error: ErrorPayload{
		Code: se.Code, Message: se.Message, Details: se.Details,
	}})
	if err != nil {
		return []byte(`{"error":{"code":"internal_error","message":"error rendering failed"}}`)
	}
	return b
}
