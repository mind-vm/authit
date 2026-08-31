package user

import (
	"errors"

	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
)

// ErrRateLimited is returned when Config.RateLimiter refuses an operation.
// Alias for ratelimit.ErrRateLimited, so errors.Is matches either; use
// ratelimit.RetryAfter to recover a wait hint for a 429 response.
//
// A limiter's own failure (a Redis timeout, say) is NOT this error and is
// propagated unchanged, so a host can tell "too many attempts" from "the
// limiter is down" — which want different status codes.
var ErrRateLimited = ratelimit.ErrRateLimited

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
	// ErrCurrentSessionRequired means RevokeOtherSessions was not told
	// which session to keep. It is the caller's mistake, not a fault: with
	// nothing to exclude, the only honest options are revoking every
	// session including the caller's own, or refusing. It refuses.
	ErrCurrentSessionRequired = errors.New("authit/user: the current session must be identified")
	// ErrNotOpaqueSession is returned by Refresh when Config.SessionMode is
	// SessionModeOpaque. There is no refresh token in that mode -- the
	// session token is the credential, and it is extended by using it
	// rather than exchanged for a new one.
	ErrNotOpaqueSession = errors.New("authit/user: refresh is not used in opaque session mode")
)
