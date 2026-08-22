package user

import "errors"

var (
	ErrInvalidCredentials  = errors.New("authit/user: invalid credentials")
	ErrEmailTaken          = errors.New("authit/user: email already registered")
	ErrEmailNotVerified    = errors.New("authit/user: email not verified")
	ErrAccountLocked       = errors.New("authit/user: account locked")
	ErrInvalidToken        = errors.New("authit/user: invalid or expired token")
	ErrTwoFactorRequired   = errors.New("authit/user: two-factor code required")
	ErrTwoFactorEnabled    = errors.New("authit/user: two-factor already enabled")
	ErrTwoFactorNotEnabled = errors.New("authit/user: two-factor not enabled")
	ErrInvalidTwoFactor    = errors.New("authit/user: invalid two-factor code")
	ErrSessionNotFound     = errors.New("authit/user: session not found")
	// ErrNotFound is returned when an operation names a user that does not
	// exist. It used to arrive as store.ErrNotFound from whatever the host had
	// implemented; now that the query is authit's own, so is the error.
	ErrNotFound = errors.New("authit/user: user not found")
)
