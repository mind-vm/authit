package emaillogin

import (
	"errors"

	"github.com/mind-vm/authit/ratelimit"
)

var rateLimited = ratelimit.ErrRateLimited

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
	// ErrRateLimited is returned when Config.RateLimiter refuses. Alias for
	// ratelimit.ErrRateLimited.
	ErrRateLimited = rateLimited
)
