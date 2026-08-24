package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/jryannel/authit/store"
)

// LockoutStore is an in-memory store.LockoutStore, shared by the user and
// superuser planes (they key lockouts by their own IDs/emails, which never
// collide across planes in practice since a host application uses separate
// instances per plane).
type LockoutStore struct {
	mu       sync.Mutex
	attempts []*store.FailedLoginAttempt
	locked   map[string]bool
}

func NewLockoutStore() *LockoutStore {
	return &LockoutStore{locked: map[string]bool{}}
}

func (s *LockoutStore) RecordFailedLoginAttempt(_ context.Context, a *store.FailedLoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	s.attempts = append(s.attempts, &cp)
	return nil
}

func (s *LockoutStore) CountRecentFailedLoginAttempts(_ context.Context, email string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, a := range s.attempts {
		if a.Email == email && a.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (s *LockoutStore) ClearFailedLoginAttempts(_ context.Context, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.attempts[:0]
	for _, a := range s.attempts {
		if a.Email != email {
			kept = append(kept, a)
		}
	}
	s.attempts = kept
	return nil
}

func (s *LockoutStore) LockAccount(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked[userID] = true
	return nil
}

func (s *LockoutStore) IsAccountLocked(_ context.Context, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked[userID], nil
}

func (s *LockoutStore) UnlockAccount(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locked, userID)
	return nil
}
