package memstore

import (
	"context"
	"sync"

	"github.com/mind-vm/authit/store"
)

// DeviceAuthorizationStore is an in-memory store.DeviceAuthorizationStore.
type DeviceAuthorizationStore struct {
	mu         sync.RWMutex
	byID       map[string]*store.DeviceAuthorization
	byHash     map[string]string
	byUserCode map[string]string
}

func NewDeviceAuthorizationStore() *DeviceAuthorizationStore {
	return &DeviceAuthorizationStore{
		byID: map[string]*store.DeviceAuthorization{}, byHash: map[string]string{}, byUserCode: map[string]string{},
	}
}

func (s *DeviceAuthorizationStore) CreateDeviceAuthorization(_ context.Context, d *store.DeviceAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *d
	s.byID[d.ID] = &cp
	s.byHash[d.DeviceCodeHash] = d.ID
	s.byUserCode[d.UserCode] = d.ID
	return nil
}

func (s *DeviceAuthorizationStore) GetDeviceAuthorizationByDeviceCodeHash(_ context.Context, hash string) (*store.DeviceAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *DeviceAuthorizationStore) GetDeviceAuthorizationByUserCode(_ context.Context, userCode string) (*store.DeviceAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byUserCode[userCode]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *DeviceAuthorizationStore) UpdateDeviceAuthorization(_ context.Context, d *store.DeviceAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[d.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *d
	s.byID[d.ID] = &cp
	return nil
}

func (s *DeviceAuthorizationStore) DeleteDeviceAuthorization(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byID[id]
	if !ok {
		return nil
	}
	delete(s.byHash, d.DeviceCodeHash)
	delete(s.byUserCode, d.UserCode)
	delete(s.byID, id)
	return nil
}
