package superuser

import "errors"

var (
	ErrInvalidCredentials = errors.New("authit/superuser: invalid credentials")
	ErrAccountLocked      = errors.New("authit/superuser: account locked")
	ErrInactive           = errors.New("authit/superuser: account is not active")
	ErrInvalidToken       = errors.New("authit/superuser: invalid or expired token")
	// ErrNotFound is returned when an operation names a superuser that does
	// not exist. It used to surface as store.ErrNotFound from whatever the
	// host had implemented; now that the query is authit's own, so is the
	// error.
	ErrNotFound             = errors.New("authit/superuser: superuser not found")
	ErrCannotDeactivateSelf = errors.New("authit/superuser: cannot deactivate your own account")
	ErrAlreadyBootstrapped  = errors.New("authit/superuser: at least one superuser already exists")
)
