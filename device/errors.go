package device

import "errors"

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
