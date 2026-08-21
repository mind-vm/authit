// Package memstore is a reference in-memory implementation of every
// interface in the store package. It is safe for concurrent use. It exists
// so authit is usable and testable with zero external dependencies; host
// applications that need durability implement the same interfaces against
// their own database.
package memstore

import (
	"context"
	"sync"

	"github.com/jryannel/authit/store"
)

// UserStore is an in-memory store.UserStore.
type UserStore struct {
	mu      sync.RWMutex
	byID    map[string]*store.User
	byEmail map[string]string // email -> id
}

// NewUserStore constructs an empty UserStore.
func NewUserStore() *UserStore {
	return &UserStore{byID: map[string]*store.User{}, byEmail: map[string]string{}}
}

func (s *UserStore) CreateUser(_ context.Context, u *store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[u.Email]; ok {
		return store.ErrConflict
	}
	cp := *u
	s.byID[u.ID] = &cp
	s.byEmail[u.Email] = u.ID
	return nil
}

func (s *UserStore) GetUserByID(_ context.Context, id string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *UserStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byEmail[email]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *UserStore) UpdateUser(_ context.Context, u *store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[u.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *u
	s.byID[u.ID] = &cp
	return nil
}
