package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/user"
)

// countingLimiter records the keys it is asked about, so a test can assert
// on the dimensions being limited rather than only on the outcome.
type countingLimiter struct {
	inner ratelimit.Limiter
	keys  []string
}

func (c *countingLimiter) Allow(ctx context.Context, key string) error {
	c.keys = append(c.keys, key)
	return c.inner.Allow(ctx, key)
}

func (c *countingLimiter) sawPrefix(prefix string) bool {
	for _, k := range c.keys {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// failingLimiter stands in for a limiter whose backend is down.
type failingLimiter struct{ err error }

func (f failingLimiter) Allow(context.Context, string) error { return f.err }

// TestLoginIsRateLimitedBeforeTheKDFRuns is the reason this control exists
// at the service layer. Argon2id costs 19 MiB and real CPU per attempt, so
// an unauthenticated flood is a resource-exhaustion vector whether or not
// any password is ever guessed. Refusal has to come first.
func TestLoginIsRateLimitedBeforeTheKDFRuns(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	lim := &countingLimiter{inner: ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 2, Interval: time.Hour})}
	svc := serviceOver(t, stores, emailer, user.Config{RateLimiter: lim})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	for i := 0; i < 2; i++ {
		if _, err := svc.Authenticate(ctx, email, "wrong-horse-battery", "ua", "1.2.3.4"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	err := errorFromAuth(svc.Authenticate(ctx, email, "wrong-horse-battery", "ua", "1.2.3.4"))
	if !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	// Even a correct password is refused: the limit is on the attempt, not
	// on failure, which is what makes it a defence against the cost.
	if err := errorFromAuth(svc.Authenticate(ctx, email, password, "ua", "1.2.3.4")); !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited for a correct password too, got %v", err)
	}
	if !lim.sawPrefix("login:ip:") || !lim.sawPrefix("login:email:") {
		t.Fatalf("both dimensions should be limited, saw %v", lim.keys)
	}
	// A hint must survive out to the caller, for a Retry-After header.
	if d, ok := ratelimit.RetryAfter(err); !ok || d <= 0 {
		t.Fatalf("RetryAfter = %v, %v; want a usable hint", d, ok)
	}
}

// TestRateLimitKeysUseTheNormalisedEmail: if the key were the raw input,
// varying case would buy a fresh budget — the same bug that email
// normalisation fixed for the lockout counter.
func TestRateLimitKeysUseTheNormalisedEmail(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	lim := &countingLimiter{inner: ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 2, Interval: time.Hour})}
	svc := serviceOver(t, stores, emailer, user.Config{RateLimiter: lim})

	// No IP, so only the email dimension is charged.
	for _, variant := range []string{"Victim@Example.com", "VICTIM@EXAMPLE.COM"} {
		_, _ = svc.Authenticate(ctx, variant, "guess-passphrase", "ua", "")
	}
	if err := errorFromAuth(svc.Authenticate(ctx, "victim@example.com", "guess-passphrase", "ua", "")); !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("case variants must share one budget, got %v", err)
	}
	for _, k := range lim.keys {
		if k != "login:email:victim@example.com" {
			t.Fatalf("unexpected key %q: keys must carry the normalised address, and an empty IP must be skipped", k)
		}
	}
}

// TestLimiterFailureIsNotARefusal: "too many attempts" and "the limiter is
// down" want different status codes, so they must be distinguishable.
func TestLimiterFailureIsNotARefusal(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	backendDown := errors.New("redis: connection refused")
	svc := serviceOver(t, stores, emailer, user.Config{RateLimiter: failingLimiter{err: backendDown}})

	err := errorFromAuth(svc.Authenticate(ctx, "alice@example.com", "correct-horse-battery", "ua", "1.2.3.4"))
	if !errors.Is(err, backendDown) {
		t.Fatalf("a limiter fault must propagate unchanged, got %v", err)
	}
	if errors.Is(err, user.ErrRateLimited) {
		t.Fatal("a limiter fault must not be reported as a rate-limit refusal")
	}
}

// TestTwoFactorAndEmailPathsAreLimited covers the remaining wired paths.
func TestTwoFactorAndEmailPathsAreLimited(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	lim := &countingLimiter{inner: ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 1, Interval: time.Hour})}
	svc := serviceOver(t, stores, emailer, user.Config{RateLimiter: lim})
	const email = "alice@example.com"
	registerCaptured(t, svc, emailer, email, "correct-horse-battery")

	if err := svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, email); !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("password reset must be limited (inbox flooding), got %v", err)
	}
	// An unregistered address is limited identically, so the limit itself
	// cannot be used to probe for accounts.
	if err := svc.RequestPasswordReset(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("first request for an unknown address: %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, "nobody@example.com"); !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("expected the same treatment for an unknown address, got %v", err)
	}
	if err := svc.RequestEmailVerificationByEmail(ctx, email); err != nil {
		t.Fatalf("RequestEmailVerificationByEmail: %v", err)
	}
	if err := svc.RequestEmailVerificationByEmail(ctx, email); !errors.Is(err, user.ErrRateLimited) {
		t.Fatalf("email verification must be limited, got %v", err)
	}
}

// TestNilLimiterIsOff: leaving the field unset must disable the control,
// not panic — the same nil-safe shape as AuditLogger.
func TestNilLimiterIsOff(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	for i := 0; i < 50; i++ {
		if _, err := svc.Authenticate(ctx, email, password, "ua", "1.2.3.4"); err != nil {
			t.Fatalf("attempt %d with no limiter configured: %v", i+1, err)
		}
	}
}

func errorFromAuth(_ user.AuthResult, err error) error { return err }
