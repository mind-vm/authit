// Package ratelimit defines the port authit's service packages use to
// throttle expensive or guessable operations, plus an in-memory
// implementation of it.
//
// # What this is not
//
// This is not a replacement for rate limiting at your HTTP layer, and it
// cannot be. A service method sees only the arguments it is given: some
// have an IP address, some have only an email, and none of them see
// headers, routes, or the shape of the request. Per-route, per-IP limiting
// belongs in middleware, where that information exists.
//
// What this port covers is the subset a host *cannot* implement from
// outside, because the thing being guessed is looked up inside authit: the
// device flow's user codes, and the login paths where refusing early avoids
// running a deliberately expensive password KDF for an attacker.
//
// Use both.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrRateLimited is the sentinel every rejection wraps, so a caller can
// classify one with errors.Is without knowing the implementation.
var ErrRateLimited = errors.New("authit/ratelimit: rate limit exceeded")

// Limiter decides whether an operation identified by key may proceed now,
// consuming budget when it says yes. Returning a non-nil error refuses it.
//
// Implementations should return an *Error (or something wrapping
// ErrRateLimited) for a refusal, and reserve other error values for their
// own failures — a Redis timeout, say. The distinction matters at the call
// site: the service packages treat a refusal as a denial to report to the
// caller, and anything else as a fault to propagate.
//
// Allow must be safe for concurrent use.
type Limiter interface {
	Allow(ctx context.Context, key string) error
}

// Error is a refusal, carrying a hint for how long to wait. Hosts can
// surface RetryAfter in a 429 response.
type Error struct {
	Key        string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	return fmt.Sprintf("authit/ratelimit: rate limit exceeded for %q, retry in %s", e.Key, e.RetryAfter)
}

// Unwrap makes errors.Is(err, ErrRateLimited) true for every *Error.
func (e *Error) Unwrap() error { return ErrRateLimited }

// RetryAfter reports how long a caller should wait before retrying, if err
// is a refusal that carries a hint. It returns false for any other error,
// including a refusal from an implementation that does not provide one.
func RetryAfter(err error) (time.Duration, bool) {
	var e *Error
	if errors.As(err, &e) && e.RetryAfter > 0 {
		return e.RetryAfter, true
	}
	return 0, false
}

// AllowEach consults l for each key in turn and returns the first refusal,
// or nil if every key was allowed.
//
// Two rules, both of which were learned the hard way and neither of which
// is obvious from Limiter:
//
// A key ending in ":" is skipped. Callers build keys by joining a namespace
// to a value -- "login:ip:" + ipAddress -- and a value that is absent
// leaves the separator dangling. Consulting that key would put every caller
// with no IP address into one shared bucket, so the first few would spend
// the budget of all the rest. Skipping is the safe reading: the dimension
// is unknown for this caller, so it cannot be metered.
//
// Every key is consulted even after one refuses. Returning early would
// leave the later dimensions uncharged, and an attacker who can make the
// first key refuse -- by exhausting a bucket they share with nobody --
// would then ride the others for free.
//
// A limiter's own failure (a Redis timeout, not a refusal) is returned
// immediately and unwrapped, so a caller can tell "you are going too fast"
// from "the control is broken" and fail closed on the second.
func AllowEach(ctx context.Context, l Limiter, keys ...string) error {
	var refusal error
	for _, key := range keys {
		if strings.HasSuffix(key, ":") {
			continue
		}
		if err := l.Allow(ctx, key); err != nil {
			if !errors.Is(err, ErrRateLimited) {
				return err
			}
			if refusal == nil {
				refusal = err
			}
		}
	}
	return refusal
}

// Noop allows everything. It is what a Config with a nil RateLimiter gets,
// so leaving the field unset disables the control rather than panicking —
// the same opt-in shape as audit.Logger.
type Noop struct{}

func (Noop) Allow(context.Context, string) error { return nil }
