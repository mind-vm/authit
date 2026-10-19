package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/mind-vm/authit/store"
)

// PINStore is an in-memory store.PINStore.
type PINStore struct {
	mu       sync.RWMutex
	byUserID map[string]*store.PINCredential
}

func NewPINStore() *PINStore {
	return &PINStore{byUserID: map[string]*store.PINCredential{}}
}

func (s *PINStore) SetPINCredential(_ context.Context, c *store.PINCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	if old, ok := s.byUserID[c.UserID]; ok {
		// A replaced PIN keeps the instant the first one was set, as an
		// upsert keeps the row's created_at.
		cp.CreatedAt = old.CreatedAt
	}
	s.byUserID[c.UserID] = &cp
	return nil
}

func (s *PINStore) GetPINCredential(_ context.Context, userID string) (*store.PINCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byUserID[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *PINStore) DeletePINCredential(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byUserID, userID)
	return nil
}

// BoundDeviceStore is an in-memory store.BoundDeviceStore.
type BoundDeviceStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.BoundDevice
	byHash   map[string]string
	byUserID map[string][]string
}

func NewBoundDeviceStore() *BoundDeviceStore {
	return &BoundDeviceStore{
		byID: map[string]*store.BoundDevice{}, byHash: map[string]string{}, byUserID: map[string][]string{},
	}
}

func (s *BoundDeviceStore) CreateBoundDevice(_ context.Context, d *store.BoundDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byHash[d.TokenHash]; ok {
		return store.ErrConflict
	}
	if _, ok := s.byID[d.ID]; ok {
		return store.ErrConflict
	}
	cp := *d
	s.byID[d.ID] = &cp
	s.byHash[d.TokenHash] = d.ID
	s.byUserID[d.UserID] = append(s.byUserID[d.UserID], d.ID)
	return nil
}

func (s *BoundDeviceStore) GetBoundDevice(_ context.Context, id string) (*store.BoundDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (s *BoundDeviceStore) GetBoundDeviceByTokenHash(_ context.Context, hash string) (*store.BoundDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *BoundDeviceStore) ListBoundDevicesByUser(_ context.Context, userID string) ([]*store.BoundDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*store.BoundDevice{}
	for _, id := range s.byUserID[userID] {
		cp := *s.byID[id]
		out = append(out, &cp)
	}
	return out, nil
}

func (s *BoundDeviceStore) TouchBoundDevice(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byID[id]
	if !ok || d.RevokedAt != nil {
		return store.ErrNotFound
	}
	d.LastUsedAt = &at
	return nil
}

func (s *BoundDeviceStore) RevokeBoundDevice(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	if d.RevokedAt == nil {
		d.RevokedAt = &at
	}
	return nil
}

func (s *BoundDeviceStore) RevokeAllBoundDevices(_ context.Context, userID string, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range s.byUserID[userID] {
		if d := s.byID[id]; d.RevokedAt == nil {
			d.RevokedAt = &at
			n++
		}
	}
	return n, nil
}
