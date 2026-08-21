package pat

import "errors"

var (
	ErrInvalidToken   = errors.New("authit/pat: invalid, revoked, or expired token")
	ErrExpiryTooFar   = errors.New("authit/pat: requested expiry exceeds the configured maximum")
	ErrExpiryRequired = errors.New("authit/pat: an expiry is required")
	ErrNotOwner       = errors.New("authit/pat: token does not belong to this user")
)
