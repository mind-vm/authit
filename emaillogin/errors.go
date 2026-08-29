package emaillogin

import (
	"errors"

	"github.com/mind-vm/authit/ratelimit"
)

var (
	// ErrInvalidToken means the magic link or code did not resolve: wrong,
	// expired, already used, or destroyed by too many failed guesses.
	//
	// It is deliberately one error for all of those. Distinguishing
	// "expired" from "wrong" tells an attacker whether the code they tried
	// was ever real, and distinguishing "no such token" from "no such
	// account" tells them which addresses are registered.
	ErrInvalidToken = errors.New("authit/emaillogin: invalid or expired sign-in credential")
	// ErrSignUpDisabled means the address matches no account and
	// Config.DisableSignUp is set. It is returned at redemption, so it
	// never reveals at request time whether an address is registered.
	ErrSignUpDisabled = errors.New("authit/emaillogin: sign-up by email is disabled")
)

// ErrRateLimited is returned when Config.RateLimiter refuses. It is an
// alias for ratelimit.ErrRateLimited, not a distinct error, so a caller
// holding either matches both.
//
// It is a refusal, not a fault: the caller did nothing wrong except arrive
// too often, and the answer is to wait rather than to change the request.
// ratelimit.RetryAfter reports how long, when the limiter said.
var ErrRateLimited = ratelimit.ErrRateLimited
