package ratelimit

import (
	"context"
	"sync"
	"time"
)

// DefaultMaxKeys bounds how many distinct keys a Memory tracks.
const DefaultMaxKeys = 100_000

// MemoryConfig configures a Memory limiter.
type MemoryConfig struct {
	// Burst is how many operations may happen back to back before the
	// limit bites. Must be at least 1; defaults to 5.
	Burst int
	// Interval is how long it takes to earn one unit of budget back.
	// Defaults to 1 minute, i.e. a sustained rate of one per minute with
	// bursts of Burst.
	Interval time.Duration
	// MaxKeys is a hard cap on tracked keys, so a caller varying the key on
	// every request cannot grow this map without bound. Defaults to
	// DefaultMaxKeys.
	//
	// Reaching it means every tracked key is currently under restriction,
	// which is itself a sign of a broad attack. See Allow for what happens
	// then; the short version is that it fails closed.
	MaxKeys int
}

func (c MemoryConfig) withDefaults() MemoryConfig {
	if c.Burst < 1 {
		c.Burst = 5
	}
	if c.Interval <= 0 {
		c.Interval = time.Minute
	}
	if c.MaxKeys < 1 {
		c.MaxKeys = DefaultMaxKeys
	}
	return c
}

// Memory is an in-process token-bucket Limiter, suitable for a single
// instance and for tests.
//
// It is deliberately not suitable for a horizontally scaled deployment:
// each process keeps its own buckets, so N instances behind a load balancer
// permit N times the configured rate. Implement Limiter over Redis (or
// whatever you already run) when that matters — it is one method.
type Memory struct {
	cfg MemoryConfig
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket holds a key's remaining budget. tokens is fractional so that
// refill is smooth rather than stepping once per Interval.
type bucket struct {
	tokens float64
	last   time.Time
}

// NewMemory returns an in-memory limiter.
func NewMemory(cfg MemoryConfig) *Memory {
	return &Memory{cfg: cfg.withDefaults(), now: time.Now, buckets: map[string]*bucket{}}
}

// Allow consumes one unit of key's budget, refusing with an *Error when
// there is none left.
//
// If the table is at MaxKeys and no bucket can be evicted -- meaning every
// tracked key is currently being limited -- a previously unseen key is
// refused rather than admitted untracked. That is the fail-closed choice:
// admitting it would be a bypass (flood the table with junk keys, then
// proceed unmetered), and growing past the cap would make the limiter a
// memory-exhaustion vector, which is exactly what the cap is for. The cost
// is that a genuine new caller is turned away while the flood lasts. At the
// default MaxKeys that state means 100,000 distinct keys are simultaneously
// over their limit, so the refusal is not the biggest problem you have.
func (m *Memory) Allow(_ context.Context, key string) error {
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.buckets[key]
	if !ok {
		if len(m.buckets) >= m.cfg.MaxKeys {
			m.evictFullLocked(now)
		}
		if len(m.buckets) >= m.cfg.MaxKeys {
			return &Error{Key: key, RetryAfter: m.cfg.Interval}
		}
		b = &bucket{tokens: float64(m.cfg.Burst), last: now}
		m.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last)
		if elapsed > 0 {
			b.tokens += float64(elapsed) / float64(m.cfg.Interval)
			if b.tokens > float64(m.cfg.Burst) {
				b.tokens = float64(m.cfg.Burst)
			}
			b.last = now
		}
	}

	if b.tokens < 1 {
		// Time until the bucket holds one whole token again.
		deficit := 1 - b.tokens
		return &Error{Key: key, RetryAfter: time.Duration(deficit * float64(m.cfg.Interval))}
	}
	b.tokens--
	return nil
}

// evictFullLocked drops keys whose budget has refilled completely.
//
// This is lossless, which is the reason the cap can be enforced this way at
// all: a bucket at full capacity permits exactly what an absent one does,
// so forgetting it changes no decision. Only keys currently under
// restriction are retained — precisely the ones an attacker wants
// forgotten.
//
// If nothing is evictable, every tracked key is actively limited and the
// map stays at its ceiling -- Allow then refuses the new key rather than
// admitting it, so MaxKeys is a hard bound and not a target.
func (m *Memory) evictFullLocked(now time.Time) {
	for key, b := range m.buckets {
		elapsed := now.Sub(b.last)
		if b.tokens+float64(elapsed)/float64(m.cfg.Interval) >= float64(m.cfg.Burst) {
			delete(m.buckets, key)
		}
	}
}

// Reset discards all state, restoring full budget to every key. It exists
// for tests and for an operator "unblock everyone" action.
func (m *Memory) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buckets = map[string]*bucket{}
}

// Len reports how many keys are currently tracked.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}
