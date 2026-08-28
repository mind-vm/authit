package crypto

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ErrWeakPassword is the sentinel behind every rejection from the built-in
// policies. Custom validators are free to return their own errors; the
// service packages pass whatever comes back through unchanged, so a host
// can surface a specific reason to the user.
var ErrWeakPassword = errors.New("authit/crypto: password does not meet policy")

// Password length bounds used by DefaultPasswordPolicy.
//
// The minimum is OWASP's current floor. The maximum exists because a
// password is attacker-controlled input to a deliberately expensive
// function: without a ceiling, a multi-megabyte password is a cheap way to
// make the server do expensive work. It is set far above any real password
// so it never rejects a passphrase or a password-manager string.
const (
	DefaultMinPasswordLength = 12
	DefaultMaxPasswordLength = 1024
)

// PasswordValidator reports whether a password is acceptable, returning a
// non-nil error to reject it. The email address of the account the password
// is being set on is supplied so a policy can reject passwords derived from
// it; it is the address the caller passed in, and may be empty on flows
// where it is not known.
//
// A validator is called before the password is hashed, on registration,
// password change and password reset. It is not called on login: an
// existing password that no longer meets a tightened policy must still let
// its owner in, or raising the policy locks out the users it was meant to
// protect.
type PasswordValidator func(ctx context.Context, email, password string) error

// DefaultPasswordPolicy is what a Config with no PasswordValidator gets. It
// enforces length only, deliberately: composition rules ("one uppercase,
// one digit") measurably reduce entropy by steering users toward
// predictable substitutions, and blocklist checks need a corpus authit has
// no business shipping. Compose your own for anything stricter --
// a breached-password check is the highest-value addition.
func DefaultPasswordPolicy() PasswordValidator {
	return LengthPolicy(DefaultMinPasswordLength, DefaultMaxPasswordLength)
}

// LengthPolicy rejects passwords shorter than min or longer than max runes.
// A max of 0 means DefaultMaxPasswordLength.
func LengthPolicy(min, max int) PasswordValidator {
	if max <= 0 {
		max = DefaultMaxPasswordLength
	}
	return func(_ context.Context, _, password string) error {
		// Counted in runes, not bytes, so a policy of 12 does not demand
		// 12 bytes of a language whose characters are three bytes each.
		if n := utf8.RuneCountInString(password); n < min {
			return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, min)
		} else if n > max {
			return fmt.Errorf("%w: must be at most %d characters", ErrWeakPassword, max)
		}
		return nil
	}
}

// NotEmailPolicy rejects a password that contains, or is contained by, the
// local part of the account's email address. Compose it with LengthPolicy
// via AllPolicies.
func NotEmailPolicy() PasswordValidator {
	return func(_ context.Context, email, password string) error {
		local, _, ok := strings.Cut(email, "@")
		if !ok || len(local) < 3 {
			return nil
		}
		if strings.Contains(strings.ToLower(password), strings.ToLower(local)) {
			return fmt.Errorf("%w: must not contain your email address", ErrWeakPassword)
		}
		return nil
	}
}

// AllPolicies runs each validator in order and returns the first rejection.
// Nil validators are skipped, so it is safe to build a list conditionally.
func AllPolicies(validators ...PasswordValidator) PasswordValidator {
	return func(ctx context.Context, email, password string) error {
		for _, v := range validators {
			if v == nil {
				continue
			}
			if err := v(ctx, email, password); err != nil {
				return err
			}
		}
		return nil
	}
}
