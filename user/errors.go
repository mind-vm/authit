package user

import (
	"errors"

	authitcrypto "github.com/mind-vm/authit/crypto"
)

// ErrWeakPassword is returned by Register, ChangePassword and ResetPassword
// when Config.PasswordValidator rejects the new password. It is an alias for
// crypto.ErrWeakPassword, so errors.Is matches either. A custom validator
// may return any error it likes and the service passes it through, so do not
// assume every rejection wraps this one.
var ErrWeakPassword = authitcrypto.ErrWeakPassword

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
