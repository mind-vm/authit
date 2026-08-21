package memstore

import (
	"context"
	"sync"

	"github.com/jryannel/authit/store"
)

// RefreshTokenStore is an in-memory store.RefreshTokenStore.
type RefreshTokenStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.RefreshToken
	byHash   map[string]string // hash -> id
	byUserID map[string][]string
}

func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{
		byID: map[string]*store.RefreshToken{}, byHash: map[string]string{}, byUserID: map[string][]string{},
	}
}

func (s *RefreshTokenStore) CreateRefreshToken(_ context.Context, t *store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.byUserID[t.UserID] = append(s.byUserID[t.UserID], t.ID)
	return nil
}

func (s *RefreshTokenStore) GetRefreshTokenByHash(_ context.Context, hash string) (*store.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *RefreshTokenStore) RevokeRefreshToken(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	now := nowFunc()
	t.RevokedAt = &now
	return nil
}

func (s *RefreshTokenStore) RevokeAllUserRefreshTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowFunc()
	for _, id := range s.byUserID[userID] {
		if t := s.byID[id]; t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (s *RefreshTokenStore) ListActiveRefreshTokens(_ context.Context, userID string) ([]*store.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := nowFunc()
	var out []*store.RefreshToken
	for _, id := range s.byUserID[userID] {
		t := s.byID[id]
		if t.RevokedAt == nil && now.Before(t.ExpiresAt) {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out, nil
}
