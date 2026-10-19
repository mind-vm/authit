package pin

import (
	"errors"

	"github.com/mind-vm/authit/ratelimit"
)

var (
	// ErrInvalidCredentials is every failed SignIn that is not a lock: an
	// unknown login, a user without a PIN, and a wrong PIN all return it,
	// so the answer never says which of the two was wrong.
	ErrInvalidCredentials = errors.New("authit/pin: login or PIN incorrect")
	// ErrLocked means too many wrong PINs were entered for this login
	// within Config.LockDuration, or an operator locked the account. It is
	// returned for an unknown login too, once it has collected as many
	// failures, so it reveals no more than ErrInvalidCredentials does.
	ErrLocked = errors.New("authit/pin: sign-in locked after too many wrong PINs")
	// ErrInvalidToken is a device token that is unknown, revoked, expired,
	// or whose user no longer exists.
	ErrInvalidToken = errors.New("authit/pin: device not signed in, or revoked")
	// ErrAccountLocked is ValidateDevice for a user an operator has locked
	// (store.LockoutStore.LockAccount): the device is still bound, but may
	// not be used until the account is unlocked.
	ErrAccountLocked = errors.New("authit/pin: account locked")
	// ErrInvalidPIN is SetPIN with a PIN that is not exactly
	// Config.PINLength digits.
	ErrInvalidPIN = errors.New("authit/pin: PIN has the wrong length or is not all digits")
	// ErrInvalidImport is ImportPINHash or ImportDevice with a hash in a
	// format authit cannot verify.
	ErrInvalidImport = errors.New("authit/pin: hash in an unrecognised format")
	// ErrRateLimited is returned when Config.RateLimiter refuses a sign-in.
	// Alias for ratelimit.ErrRateLimited.
	ErrRateLimited = ratelimit.ErrRateLimited
)
