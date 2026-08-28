package device

import (
	"errors"

	"github.com/mind-vm/authit/ratelimit"
)

// ErrRateLimited is returned when Config.RateLimiter refuses a user-code
// lookup or an approval. Alias for ratelimit.ErrRateLimited.
//
// It is deliberately distinct from ErrInvalidUserCode: a host must not
// report it as "wrong code", because the caller's code may well have been
// right. RFC 8628 has no error code for this at the verification endpoint,
// which is a UI surface rather than a token endpoint — 429 with a
// try-again message is the sensible rendering.
var ErrRateLimited = ratelimit.ErrRateLimited

// These map directly to RFC 8628 §3.5's token-endpoint error codes; a host
// application's HTTP layer translates them to the matching
// "error" field (authorization_pending, slow_down, access_denied,
// expired_token).
var (
	ErrAuthorizationPending = errors.New("authit/device: authorization pending")
	ErrSlowDown             = errors.New("authit/device: polling too frequently")
	ErrAccessDenied         = errors.New("authit/device: access denied")
	ErrExpiredToken         = errors.New("authit/device: device code expired or invalid")
	ErrInvalidUserCode      = errors.New("authit/device: invalid, already-used, or expired user code")
)
