package device_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mind-vm/authit/device"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/ratelimit"
)

func limitedService(t *testing.T, cfg ratelimit.MemoryConfig) *device.Service {
	t.Helper()
	svc, err := device.NewService(
		device.Stores{Authorizations: memstore.NewDeviceAuthorizationStore()},
		device.Config{RateLimiter: ratelimit.NewMemory(cfg)},
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// TestUserCodeGuessingIsBounded closes the gap crypto/usercode.go named but
// nothing enforced: a user code carries ~34.5 bits precisely so a human can
// retype it, and RFC 8628 §5.2 says the security of that choice rests on
// limiting guesses. Without a limiter the space is searchable.
func TestUserCodeGuessingIsBounded(t *testing.T) {
	ctx := context.Background()
	svc := limitedService(t, ratelimit.MemoryConfig{Burst: 5, Interval: time.Hour})

	var lastErr error
	for i := 0; i < 20; i++ {
		lastErr = svc.DenyDeviceAuthorization(ctx, fmt.Sprintf("GUES-%04d", i))
		if errors.Is(lastErr, ratelimit.ErrRateLimited) {
			if i < 5 {
				t.Fatalf("cut off after only %d guesses, expected the configured burst", i)
			}
			return
		}
		if !errors.Is(lastErr, device.ErrInvalidUserCode) {
			t.Fatalf("guess %d: unexpected error %v", i, lastErr)
		}
	}
	t.Fatalf("20 wrong codes were accepted without limit; last error %v", lastErr)
}

// TestSuccessfulLookupsDoNotConsumeTheGuessBudget is what makes the global
// counter affordable: a user typing their own code correctly must never
// spend from a budget sized for attackers.
func TestSuccessfulLookupsDoNotConsumeTheGuessBudget(t *testing.T) {
	ctx := context.Background()
	svc := limitedService(t, ratelimit.MemoryConfig{Burst: 2, Interval: time.Hour})

	for i := 0; i < 10; i++ {
		auth, err := svc.StartDeviceAuthorization(ctx, "cli", "read")
		if err != nil {
			t.Fatalf("StartDeviceAuthorization: %v", err)
		}
		if err := svc.ApproveDeviceAuthorization(ctx, fmt.Sprintf("user-%d", i), auth.UserCode); err != nil {
			t.Fatalf("approval %d must not be charged to the guess budget: %v", i+1, err)
		}
	}
	// The budget is untouched, so a wrong code still gets the ordinary error.
	if err := svc.DenyDeviceAuthorization(ctx, "WRON-GXXX"); !errors.Is(err, device.ErrInvalidUserCode) {
		t.Fatalf("expected ErrInvalidUserCode, got %v", err)
	}
}

// TestApprovalIsLimitedPerCaller: the global counter bounds enumeration in
// aggregate, but one authenticated account must also not be able to sweep
// on its own.
func TestApprovalIsLimitedPerCaller(t *testing.T) {
	ctx := context.Background()
	svc := limitedService(t, ratelimit.MemoryConfig{Burst: 3, Interval: time.Hour})

	var attacker error
	for i := 0; i < 10; i++ {
		attacker = svc.ApproveDeviceAuthorization(ctx, "attacker", fmt.Sprintf("GUES-%04d", i))
		if errors.Is(attacker, ratelimit.ErrRateLimited) {
			break
		}
	}
	if !errors.Is(attacker, ratelimit.ErrRateLimited) {
		t.Fatalf("one caller should have been cut off, got %v", attacker)
	}
	// A different caller has their own budget, so one attacker cannot lock
	// everyone else out of approving through this key.
	auth, err := svc.StartDeviceAuthorization(ctx, "cli", "read")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if err := svc.ApproveDeviceAuthorization(ctx, "innocent", auth.UserCode); err != nil {
		t.Fatalf("a different caller must not inherit the attacker's exhaustion: %v", err)
	}
}

// TestRateLimitedIsNotReportedAsAWrongCode: the two must stay distinct, or
// a host renders "invalid code" to a user whose code was in fact correct.
func TestRateLimitedIsNotReportedAsAWrongCode(t *testing.T) {
	ctx := context.Background()
	svc := limitedService(t, ratelimit.MemoryConfig{Burst: 1, Interval: time.Hour})

	if err := svc.DenyDeviceAuthorization(ctx, "AAAA-BBBB"); !errors.Is(err, device.ErrInvalidUserCode) {
		t.Fatalf("expected ErrInvalidUserCode, got %v", err)
	}
	err := svc.DenyDeviceAuthorization(ctx, "CCCC-DDDD")
	if !errors.Is(err, device.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if errors.Is(err, device.ErrInvalidUserCode) {
		t.Fatal("exhaustion must not masquerade as a wrong code")
	}
}

// TestNilLimiterIsOff keeps the nil-safe shape: unset means the control is
// off, not broken. The Config doc says to set it; it must not panic if you
// do not.
func TestNilLimiterIsOff(t *testing.T) {
	ctx := context.Background()
	svc, err := device.NewService(
		device.Stores{Authorizations: memstore.NewDeviceAuthorizationStore()},
		device.Config{},
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	for i := 0; i < 100; i++ {
		if err := svc.DenyDeviceAuthorization(ctx, fmt.Sprintf("GUES-%04d", i)); !errors.Is(err, device.ErrInvalidUserCode) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
}
