package memstore

import (
	"context"
	"sync"

	"github.com/mind-vm/authit/store"
)

// TOTPStore is an in-memory store.TOTPStore.
type TOTPStore struct {
	mu       sync.RWMutex
	byUserID map[string]*store.TOTPSettings
}

func NewTOTPStore() *TOTPStore {
	return &TOTPStore{byUserID: map[string]*store.TOTPSettings{}}
}

func (s *TOTPStore) CreateTOTPSettings(_ context.Context, t *store.TOTPSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byUserID[t.UserID]; ok {
		return store.ErrConflict
	}
	cp := *t
	s.byUserID[t.UserID] = &cp
	return nil
}

func (s *TOTPStore) GetTOTPSettingsByUserID(_ context.Context, userID string) (*store.TOTPSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byUserID[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	cp.RecoveryCodeHashes = append([]string(nil), t.RecoveryCodeHashes...)
	return &cp, nil
}

func (s *TOTPStore) UpdateTOTPSettings(_ context.Context, t *store.TOTPSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byUserID[t.UserID]; !ok {
		return store.ErrNotFound
	}
	cp := *t
	cp.RecoveryCodeHashes = append([]string(nil), t.RecoveryCodeHashes...)
	s.byUserID[t.UserID] = &cp
	return nil
}

func (s *TOTPStore) DeleteTOTPSettings(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byUserID, userID)
	return nil
}

// PendingTwoFactorStore is an in-memory store.PendingTwoFactorStore.
type PendingTwoFactorStore struct {
	mu     sync.RWMutex
	byID   map[string]*store.PendingTwoFactorSession
	byHash map[string]string
}

func NewPendingTwoFactorStore() *PendingTwoFactorStore {
	return &PendingTwoFactorStore{byID: map[string]*store.PendingTwoFactorSession{}, byHash: map[string]string{}}
}

func (s *PendingTwoFactorStore) CreatePendingTwoFactorSession(_ context.Context, sess *store.PendingTwoFactorSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.byID[sess.ID] = &cp
	s.byHash[sess.TokenHash] = sess.ID
	return nil
}

func (s *PendingTwoFactorStore) GetPendingTwoFactorSessionByHash(_ context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *PendingTwoFactorStore) DeletePendingTwoFactorSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.byID[id]; ok {
		delete(s.byHash, t.TokenHash)
		delete(s.byID, id)
	}
	return nil
}
