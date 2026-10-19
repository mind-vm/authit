package superuser

import (
	"errors"

	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/internal/sentinel"
	"github.com/mind-vm/authit/ratelimit"
)

// ErrRateLimited is returned when Config.RateLimiter refuses a login.
// Alias for ratelimit.ErrRateLimited. A limiter's own failure is propagated
// unchanged instead.
var ErrRateLimited = ratelimit.ErrRateLimited

// ErrWeakPassword is returned by Bootstrap and CreateSuperuser when
// Config.PasswordValidator rejects the password. Alias for
// crypto.ErrWeakPassword so errors.Is matches either.
var ErrWeakPassword = authitcrypto.ErrWeakPassword

var (
	ErrInvalidCredentials = errors.New("authit/superuser: invalid credentials")
	ErrAccountLocked      = errors.New("authit/superuser: account locked")
	ErrInactive           = errors.New("authit/superuser: account is not active")
	// ErrInvalidToken also matches authithttp.ErrInvalidToken under
	// errors.Is, so authithttp.StatusFor answers 401 to it.
	ErrInvalidToken         = sentinel.New("authit/superuser: invalid or expired token", sentinel.InvalidToken)
	ErrCannotDeactivateSelf = errors.New("authit/superuser: cannot deactivate your own account")
	ErrAlreadyBootstrapped  = errors.New("authit/superuser: at least one superuser already exists")

	ErrTwoFactorUnavailable = errors.New("authit/superuser: this deployment has no second-factor store")
	ErrTwoFactorEnabled     = errors.New("authit/superuser: a second factor is already enabled")
	ErrTwoFactorNotEnabled  = errors.New("authit/superuser: no second factor is enabled")
	ErrInvalidTwoFactor     = errors.New("authit/superuser: invalid second-factor code")
	ErrSessionNotFound      = errors.New("authit/superuser: no such session")
)
