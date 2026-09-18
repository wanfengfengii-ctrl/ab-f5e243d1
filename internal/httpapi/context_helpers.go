package httpapi

import (
	"errors"

	"telemetry/internal/store"
)

// asStoreError is errors.As sugar returning whether err is a *store.Error.
func asStoreError(err error, target **store.Error) bool { return errors.As(err, target) }
