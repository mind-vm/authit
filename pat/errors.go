package pat

import (
	"errors"

	"github.com/mind-vm/authit/internal/sentinel"
)

var (
	// ErrInvalidToken also matches authithttp.ErrInvalidToken under
	// errors.Is, so authithttp.StatusFor answers 401 to it.
	ErrInvalidToken   = sentinel.New("authit/pat: invalid, revoked, or expired token", sentinel.InvalidToken)
	ErrExpiryTooFar   = errors.New("authit/pat: requested expiry exceeds the configured maximum")
	ErrExpiryRequired = errors.New("authit/pat: an expiry is required")
	ErrNotOwner       = errors.New("authit/pat: token does not belong to this user")
)
