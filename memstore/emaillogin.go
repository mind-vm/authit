package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/mind-vm/authit/store"
)

// EmailLoginStore is an in-memory store.EmailLoginStore.
type EmailLoginStore struct {
	mu      sync.RWMutex
	byID    map[string]*store.EmailLoginToken
	byHash  map[string]string
	byEmail map[emailKindKey][]string
}

type emailKindKey struct {
	email string
	kind  store.EmailLoginKind
}

func NewEmailLoginStore() *EmailLoginStore {
	return &EmailLoginStore{
		byID:    map[string]*store.EmailLoginToken{},
		byHash:  map[string]string{},
		byEmail: map[emailKindKey][]string{},
	}
}

func (s *EmailLoginStore) CreateEmailLoginToken(_ context.Context, t *store.EmailLoginToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	key := emailKindKey{t.Email, t.Kind}
	s.byEmail[key] = append(s.byEmail[key], t.ID)
	return nil
}

func (s *EmailLoginStore) GetEmailLoginTokenByHash(_ context.Context, hash string) (*store.EmailLoginToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *EmailLoginStore) GetEmailLoginTokenByEmail(_ context.Context, email string, kind store.EmailLoginKind) (*store.EmailLoginToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byEmail[emailKindKey{email, kind}]
	// The newest outstanding token wins. Requesting a new one deletes the
	// old, so in practice there is at most one; iterating backwards keeps
	// that true even if a host's own code created two.
	for i := len(ids) - 1; i >= 0; i-- {
		if t, ok := s.byID[ids[i]]; ok {
			cp := *t
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

// MarkEmailLoginTokenUsed marks used under one lock, and refuses a token
// already marked. Both halves happen without releasing the lock, which is
// what makes it a compare-and-set rather than a read followed by a write.
func (s *EmailLoginStore) MarkEmailLoginTokenUsed(_ context.Context, id string, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok || t.UsedAt != nil {
		return store.ErrNotFound
	}
	cp := *t
	cp.UsedAt = &usedAt
	s.byID[id] = &cp
	return nil
}

func (s *EmailLoginStore) IncrementEmailLoginTokenAttempts(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	cp := *t
	cp.Attempts++
	s.byID[id] = &cp
	return cp.Attempts, nil
}

func (s *EmailLoginStore) DeleteEmailLoginTokens(_ context.Context, email string, kind store.EmailLoginKind) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := emailKindKey{email, kind}
	for _, id := range s.byEmail[key] {
		if t, ok := s.byID[id]; ok {
			delete(s.byHash, t.TokenHash)
			delete(s.byID, id)
		}
	}
	delete(s.byEmail, key)
	return nil
}
