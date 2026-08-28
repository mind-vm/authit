package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mind-vm/authit/ratelimit"
)

func TestMemoryAllowsBurstThenRefuses(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 3, Interval: time.Minute})

	for i := 0; i < 3; i++ {
		if err := m.Allow(ctx, "k"); err != nil {
			t.Fatalf("attempt %d should be allowed: %v", i+1, err)
		}
	}
	err := m.Allow(ctx, "k")
	if !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	// The hint must be usable for a Retry-After header.
	d, ok := ratelimit.RetryAfter(err)
	if !ok || d <= 0 || d > time.Minute {
		t.Fatalf("RetryAfter = %v, %v; want a positive duration within the interval", d, ok)
	}
}

func TestMemoryKeysAreIndependent(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 1, Interval: time.Minute})

	if err := m.Allow(ctx, "a"); err != nil {
		t.Fatalf("first key: %v", err)
	}
	if err := m.Allow(ctx, "a"); err == nil {
		t.Fatal("second use of the same key should be refused")
	}
	if err := m.Allow(ctx, "b"); err != nil {
		t.Fatalf("a different key must have its own budget: %v", err)
	}
}

func TestMemoryRefills(t *testing.T) {
	ctx := context.Background()
	// A short interval keeps the test fast; the refill is fractional, so
	// one interval's wait buys exactly one unit back.
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 1, Interval: 40 * time.Millisecond})

	if err := m.Allow(ctx, "k"); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if err := m.Allow(ctx, "k"); err == nil {
		t.Fatal("expected the budget to be spent")
	}
	time.Sleep(80 * time.Millisecond)
	if err := m.Allow(ctx, "k"); err != nil {
		t.Fatalf("budget should have refilled: %v", err)
	}
}

// TestMemoryBoundsItsKeyspace: a limiter that grows a map per distinct key
// is itself a memory-exhaustion vector, since the attacker chooses the key.
func TestMemoryBoundsItsKeyspace(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{
		Burst: 1, Interval: time.Millisecond, MaxKeys: 50,
	})
	for i := 0; i < 5000; i++ {
		_ = m.Allow(ctx, fmt.Sprintf("attacker-%d", i))
	}
	// Eviction only reclaims fully-refilled buckets, so the ceiling is
	// approximate; what matters is that it is a ceiling at all.
	if got := m.Len(); got > 200 {
		t.Fatalf("tracked %d keys after 5000 distinct ones; the map is unbounded", got)
	}
}

// TestMemoryEvictionIsLossless: eviction must never hand budget back to a
// key that is currently being limited, or the cap becomes a bypass —
// flood with junk keys, get your own bucket dropped, continue.
func TestMemoryEvictionIsLossless(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{
		Burst: 1, Interval: time.Hour, MaxKeys: 10,
	})
	if err := m.Allow(ctx, "victim"); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if err := m.Allow(ctx, "victim"); err == nil {
		t.Fatal("victim should be limited")
	}
	for i := 0; i < 1000; i++ {
		_ = m.Allow(ctx, fmt.Sprintf("junk-%d", i))
	}
	if err := m.Allow(ctx, "victim"); err == nil {
		t.Fatal("flooding with distinct keys must not restore a limited key's budget")
	}
}

func TestMemoryIsConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 100, Interval: time.Hour})

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Allow(ctx, "shared"); err == nil {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("expected exactly Burst=100 to be allowed, got %d", allowed)
	}
}

func TestNoopAllowsEverything(t *testing.T) {
	ctx := context.Background()
	var l ratelimit.Limiter = ratelimit.Noop{}
	for i := 0; i < 1000; i++ {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("Noop must never refuse: %v", err)
		}
	}
}

func TestRetryAfterIgnoresOtherErrors(t *testing.T) {
	if _, ok := ratelimit.RetryAfter(errors.New("redis: connection refused")); ok {
		t.Fatal("RetryAfter must not claim a hint for an unrelated error")
	}
	if _, ok := ratelimit.RetryAfter(nil); ok {
		t.Fatal("RetryAfter(nil) must be false")
	}
}
