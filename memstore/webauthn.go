package memstore

import (
	"context"
	"encoding/base64"
	"slices"
	"sync"

	"github.com/mind-vm/authit/store"
)

// WebAuthnCredentialStore is an in-memory store.WebAuthnCredentialStore.
type WebAuthnCredentialStore struct {
	mu sync.RWMutex
	// byCredentialID keys on the base64 of the raw credential id, because
	// a []byte cannot be a map key. It enforces the uniqueness a real
	// schema gets from a UNIQUE index.
	byID           map[string]*store.WebAuthnCredential
	byCredentialID map[string]string
	byUserID       map[string][]string
}

func NewWebAuthnCredentialStore() *WebAuthnCredentialStore {
	return &WebAuthnCredentialStore{
		byID:           map[string]*store.WebAuthnCredential{},
		byCredentialID: map[string]string{},
		byUserID:       map[string][]string{},
	}
}

func credKey(credentialID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credentialID)
}

// clone deep-copies the byte slices, so a caller mutating what it got back
// cannot reach into the store. The blob in particular is handed out on
// every login.
func clone(c *store.WebAuthnCredential) *store.WebAuthnCredential {
	cp := *c
	cp.CredentialID = slices.Clone(c.CredentialID)
	cp.Data = slices.Clone(c.Data)
	cp.Transports = slices.Clone(c.Transports)
	return &cp
}

func (s *WebAuthnCredentialStore) CreateWebAuthnCredential(_ context.Context, c *store.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credKey(c.CredentialID)
	if existing, ok := s.byCredentialID[key]; ok && existing != c.ID {
		return store.ErrConflict
	}
	s.byID[c.ID] = clone(c)
	s.byCredentialID[key] = c.ID
	s.byUserID[c.UserID] = append(s.byUserID[c.UserID], c.ID)
	return nil
}

func (s *WebAuthnCredentialStore) GetWebAuthnCredential(_ context.Context, id string) (*store.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clone(c), nil
}

func (s *WebAuthnCredentialStore) GetWebAuthnCredentialByCredentialID(_ context.Context, credentialID []byte) (*store.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byCredentialID[credKey(credentialID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clone(s.byID[id]), nil
}

func (s *WebAuthnCredentialStore) ListWebAuthnCredentialsByUser(_ context.Context, userID string) ([]*store.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byUserID[userID]
	out := make([]*store.WebAuthnCredential, 0, len(ids))
	for _, id := range ids {
		if c, ok := s.byID[id]; ok {
			out = append(out, clone(c))
		}
	}
	return out, nil
}

func (s *WebAuthnCredentialStore) UpdateWebAuthnCredential(_ context.Context, c *store.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[c.ID]; !ok {
		return store.ErrNotFound
	}
	s.byID[c.ID] = clone(c)
	s.byCredentialID[credKey(c.CredentialID)] = c.ID
	return nil
}

func (s *WebAuthnCredentialStore) DeleteWebAuthnCredential(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.byID, id)
	delete(s.byCredentialID, credKey(c.CredentialID))
	if ids := s.byUserID[c.UserID]; len(ids) > 0 {
		s.byUserID[c.UserID] = slices.DeleteFunc(ids, func(x string) bool { return x == id })
	}
	return nil
}
