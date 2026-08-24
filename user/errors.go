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
)
