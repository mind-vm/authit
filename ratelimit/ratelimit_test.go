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
// MaxKeys is a hard bound, not a target -- an earlier version let the map
// overshoot by however many keys arrived before something became
// evictable, which made this test's ceiling depend on machine speed.
func TestMemoryBoundsItsKeyspace(t *testing.T) {
	ctx := context.Background()
	const maxKeys = 50
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{
		Burst: 1, Interval: time.Hour, MaxKeys: maxKeys,
	})
	for i := 0; i < 5000; i++ {
		_ = m.Allow(ctx, fmt.Sprintf("attacker-%d", i))
	}
	if got := m.Len(); got > maxKeys {
		t.Fatalf("tracked %d keys with MaxKeys=%d; the cap must be hard", got, maxKeys)
	}
}

// TestMemoryFailsClosedWhenFull: once the table is full of actively-limited
// keys, an unseen key must be refused rather than admitted untracked.
// Admitting it would be the bypass the cap exists to prevent -- flood with
// junk, then proceed unmetered.
func TestMemoryFailsClosedWhenFull(t *testing.T) {
	ctx := context.Background()
	m := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 1, Interval: time.Hour, MaxKeys: 4})
	for i := 0; i < 4; i++ {
		if err := m.Allow(ctx, fmt.Sprintf("k-%d", i)); err != nil {
			t.Fatalf("filling the table: %v", err)
		}
	}
	if err := m.Allow(ctx, "unseen"); !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("a new key must be refused, not admitted untracked: %v", err)
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

// recordingLimiter records every key it was consulted with, and refuses the
// ones named in refuse.
type recordingLimiter struct {
	seen   []string
	refuse map[string]error
}

func (l *recordingLimiter) Allow(_ context.Context, key string) error {
	l.seen = append(l.seen, key)
	return l.refuse[key]
}

// TestAllowEachSkipsKeysWithAnAbsentComponent. Callers build keys by
// joining a namespace to a value, and a value that is absent leaves the
// separator dangling. Consulting "login:ip:" would put every caller whose
// IP is unknown into one bucket, so the first few would spend the budget of
// all the rest -- a denial of service against exactly the callers the
// limiter knows least about.
func TestAllowEachSkipsKeysWithAnAbsentComponent(t *testing.T) {
	l := &recordingLimiter{}
	if err := ratelimit.AllowEach(context.Background(), l, "login:email:a@example.com", "login:ip:"); err != nil {
		t.Fatalf("AllowEach: %v", err)
	}
	if len(l.seen) != 1 || l.seen[0] != "login:email:a@example.com" {
		t.Fatalf("consulted %v; a key with an empty trailing component must be skipped", l.seen)
	}
}

// TestAllowEachChargesEveryKeyDespiteARefusal. Returning at the first
// refusal would leave the later dimensions uncharged, so an attacker who
// can make the first key refuse -- by exhausting a bucket they share with
// nobody -- rides the rest for free.
func TestAllowEachChargesEveryKeyDespiteARefusal(t *testing.T) {
	l := &recordingLimiter{refuse: map[string]error{
		"a": &ratelimit.Error{Key: "a", RetryAfter: time.Second},
	}}
	err := ratelimit.AllowEach(context.Background(), l, "a", "b", "c")
	if !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("got %v, want a refusal", err)
	}
	if len(l.seen) != 3 {
		t.Fatalf("consulted %v; every key must be charged even after one refuses", l.seen)
	}
}

// TestAllowEachPropagatesLimiterFailureImmediately. A Redis timeout is not
// a refusal: the control is broken rather than the caller being too fast,
// and the distinction is what lets a service fail closed on one and report
// a 429 on the other.
func TestAllowEachPropagatesLimiterFailureImmediately(t *testing.T) {
	boom := errors.New("limiter is down")
	l := &recordingLimiter{refuse: map[string]error{"a": boom}}
	err := ratelimit.AllowEach(context.Background(), l, "a", "b")
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the limiter's own error", err)
	}
	if errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatal("a limiter failure must not be reported as a refusal")
	}
	if len(l.seen) != 1 {
		t.Fatalf("consulted %v; a broken limiter must stop the walk, not be retried per key", l.seen)
	}
}
