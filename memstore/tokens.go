package memstore

import (
	"context"
	"sync"

	"github.com/mind-vm/authit/store"
)

// PasswordResetStore is an in-memory store.PasswordResetStore.
type PasswordResetStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.PasswordResetToken
	byHash   map[string]string
	byUserID map[string][]string
}

func NewPasswordResetStore() *PasswordResetStore {
	return &PasswordResetStore{
		byID: map[string]*store.PasswordResetToken{}, byHash: map[string]string{}, byUserID: map[string][]string{},
	}
}

func (s *PasswordResetStore) CreatePasswordResetToken(_ context.Context, t *store.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.byUserID[t.UserID] = append(s.byUserID[t.UserID], t.ID)
	return nil
}

func (s *PasswordResetStore) GetPasswordResetTokenByHash(_ context.Context, hash string) (*store.PasswordResetToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *PasswordResetStore) MarkPasswordResetTokenUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	now := nowFunc()
	t.UsedAt = &now
	return nil
}

func (s *PasswordResetStore) DeleteUserPasswordResetTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.byUserID[userID] {
		if t, ok := s.byID[id]; ok {
			delete(s.byHash, t.TokenHash)
			delete(s.byID, id)
		}
	}
	s.byUserID[userID] = nil
	return nil
}

// EmailVerificationStore is an in-memory store.EmailVerificationStore.
type EmailVerificationStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.EmailVerificationToken
	byHash   map[string]string
	byUserID map[string][]string
}

func NewEmailVerificationStore() *EmailVerificationStore {
	return &EmailVerificationStore{
		byID: map[string]*store.EmailVerificationToken{}, byHash: map[string]string{}, byUserID: map[string][]string{},
	}
}

func (s *EmailVerificationStore) CreateEmailVerificationToken(_ context.Context, t *store.EmailVerificationToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.byUserID[t.UserID] = append(s.byUserID[t.UserID], t.ID)
	return nil
}

func (s *EmailVerificationStore) GetEmailVerificationTokenByHash(_ context.Context, hash string) (*store.EmailVerificationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *EmailVerificationStore) MarkEmailVerificationTokenUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	now := nowFunc()
	t.UsedAt = &now
	return nil
}

func (s *EmailVerificationStore) DeleteUserEmailVerificationTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.byUserID[userID] {
		if t, ok := s.byID[id]; ok {
			delete(s.byHash, t.TokenHash)
			delete(s.byID, id)
		}
	}
	s.byUserID[userID] = nil
	return nil
}
