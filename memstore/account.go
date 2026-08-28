package memstore

import (
	"context"
	"slices"
	"sync"

	"github.com/mind-vm/authit/store"
)

// AccountStore is an in-memory store.AccountStore.
type AccountStore struct {
	mu sync.RWMutex
	// byID holds the rows; byProvider indexes the (provider, subject) pair
	// that every sign-in looks up, and enforces its uniqueness the way a
	// real schema's UNIQUE constraint would.
	byID       map[string]*store.Account
	byProvider map[providerKey]string
	byUserID   map[string][]string
}

type providerKey struct{ provider, accountID string }

func NewAccountStore() *AccountStore {
	return &AccountStore{
		byID:       map[string]*store.Account{},
		byProvider: map[providerKey]string{},
		byUserID:   map[string][]string{},
	}
}

func (s *AccountStore) CreateAccount(_ context.Context, a *store.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := providerKey{a.Provider, a.ProviderAccountID}
	if existing, ok := s.byProvider[key]; ok && existing != a.ID {
		// The uniqueness a real schema gets from a constraint. Without it
		// a second link for the same provider subject would shadow the
		// first, which is an account takeover rather than a duplicate row.
		return store.ErrConflict
	}
	cp := *a
	s.byID[a.ID] = &cp
	s.byProvider[key] = a.ID
	s.byUserID[a.UserID] = append(s.byUserID[a.UserID], a.ID)
	return nil
}

func (s *AccountStore) GetAccount(_ context.Context, id string) (*store.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *AccountStore) GetAccountByProvider(_ context.Context, provider, providerAccountID string) (*store.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byProvider[providerKey{provider, providerAccountID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *AccountStore) ListAccountsByUser(_ context.Context, userID string) ([]*store.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byUserID[userID]
	out := make([]*store.Account, 0, len(ids))
	for _, id := range ids {
		if a, ok := s.byID[id]; ok {
			cp := *a
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *AccountStore) UpdateAccount(_ context.Context, a *store.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[a.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *a
	s.byID[a.ID] = &cp
	s.byProvider[providerKey{a.Provider, a.ProviderAccountID}] = a.ID
	return nil
}

func (s *AccountStore) DeleteAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.byID, id)
	delete(s.byProvider, providerKey{a.Provider, a.ProviderAccountID})
	if ids := s.byUserID[a.UserID]; len(ids) > 0 {
		s.byUserID[a.UserID] = slices.DeleteFunc(ids, func(x string) bool { return x == id })
	}
	return nil
}
