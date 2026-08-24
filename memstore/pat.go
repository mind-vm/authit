package memstore

import (
	"context"
	"sync"

	"github.com/jryannel/authit/store"
)

// PersonalAccessTokenStore is an in-memory store.PersonalAccessTokenStore.
type PersonalAccessTokenStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.PersonalAccessToken
	byHash   map[string]string
	byUserID map[string][]string
}

func NewPersonalAccessTokenStore() *PersonalAccessTokenStore {
	return &PersonalAccessTokenStore{
		byID: map[string]*store.PersonalAccessToken{}, byHash: map[string]string{}, byUserID: map[string][]string{},
	}
}

func (s *PersonalAccessTokenStore) CreatePersonalAccessToken(_ context.Context, t *store.PersonalAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.byUserID[t.UserID] = append(s.byUserID[t.UserID], t.ID)
	return nil
}

func (s *PersonalAccessTokenStore) GetPersonalAccessToken(_ context.Context, id string) (*store.PersonalAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *PersonalAccessTokenStore) GetPersonalAccessTokenByHash(_ context.Context, hash string) (*store.PersonalAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *PersonalAccessTokenStore) ListPersonalAccessTokensByUser(_ context.Context, userID string) ([]*store.PersonalAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*store.PersonalAccessToken
	for _, id := range s.byUserID[userID] {
		cp := *s.byID[id]
		out = append(out, &cp)
	}
	return out, nil
}

func (s *PersonalAccessTokenStore) UpdatePersonalAccessToken(_ context.Context, t *store.PersonalAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[t.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *t
	s.byID[t.ID] = &cp
	return nil
}
