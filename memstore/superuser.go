package memstore

import (
	"context"
	"sync"

	"github.com/mind-vm/authit/store"
)

// SuperuserStore is an in-memory store.SuperuserStore.
type SuperuserStore struct {
	mu      sync.RWMutex
	byID    map[string]*store.Superuser
	byEmail map[string]string
}

func NewSuperuserStore() *SuperuserStore {
	return &SuperuserStore{byID: map[string]*store.Superuser{}, byEmail: map[string]string{}}
}

func (s *SuperuserStore) CreateSuperuser(_ context.Context, su *store.Superuser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[su.Email]; ok {
		return store.ErrConflict
	}
	cp := *su
	s.byID[su.ID] = &cp
	s.byEmail[su.Email] = su.ID
	return nil
}

func (s *SuperuserStore) GetSuperuserByID(_ context.Context, id string) (*store.Superuser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	su, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *su
	return &cp, nil
}

func (s *SuperuserStore) GetSuperuserByEmail(_ context.Context, email string) (*store.Superuser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byEmail[email]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *SuperuserStore) ListSuperusers(_ context.Context) ([]*store.Superuser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Superuser, 0, len(s.byID))
	for _, su := range s.byID {
		cp := *su
		out = append(out, &cp)
	}
	return out, nil
}

func (s *SuperuserStore) UpdateSuperuser(_ context.Context, su *store.Superuser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[su.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *su
	s.byID[su.ID] = &cp
	return nil
}

func (s *SuperuserStore) CountSuperusers(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID), nil
}

// SuperuserRefreshTokenStore is an in-memory store.SuperuserRefreshTokenStore.
type SuperuserRefreshTokenStore struct {
	mu     sync.RWMutex
	byID   map[string]*store.SuperuserRefreshToken
	byHash map[string]string
	bySuID map[string][]string
}

func NewSuperuserRefreshTokenStore() *SuperuserRefreshTokenStore {
	return &SuperuserRefreshTokenStore{
		byID: map[string]*store.SuperuserRefreshToken{}, byHash: map[string]string{}, bySuID: map[string][]string{},
	}
}

func (s *SuperuserRefreshTokenStore) CreateSuperuserRefreshToken(_ context.Context, t *store.SuperuserRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.bySuID[t.SuperuserID] = append(s.bySuID[t.SuperuserID], t.ID)
	return nil
}

func (s *SuperuserRefreshTokenStore) GetSuperuserRefreshTokenByHash(_ context.Context, hash string) (*store.SuperuserRefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *SuperuserRefreshTokenStore) RevokeSuperuserRefreshToken(_ context.Context, id string) error {
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

func (s *SuperuserRefreshTokenStore) ConsumeSuperuserRefreshToken(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok || t.RevokedAt != nil {
		return false, nil
	}
	now := nowFunc()
	t.RevokedAt = &now
	return true, nil
}

func (s *SuperuserRefreshTokenStore) RevokeAllSuperuserRefreshTokens(_ context.Context, superuserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowFunc()
	for _, id := range s.bySuID[superuserID] {
		if t := s.byID[id]; t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (s *SuperuserRefreshTokenStore) ListActiveSuperuserRefreshTokens(_ context.Context, superuserID string) ([]*store.SuperuserRefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := nowFunc()
	out := []*store.SuperuserRefreshToken{}
	for _, id := range s.bySuID[superuserID] {
		if t := s.byID[id]; t.RevokedAt == nil && now.Before(t.ExpiresAt) {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out, nil
}

// SuperuserTwoFactorStore is an in-memory store.SuperuserTwoFactorStore.
// The rows are the user plane's shapes, so it delegates to those stores; the
// separate instance is what keeps the two planes' rows apart.
type SuperuserTwoFactorStore struct {
	totp    *TOTPStore
	pending *PendingTwoFactorStore
}

func NewSuperuserTwoFactorStore() *SuperuserTwoFactorStore {
	return &SuperuserTwoFactorStore{totp: NewTOTPStore(), pending: NewPendingTwoFactorStore()}
}

func (s *SuperuserTwoFactorStore) CreateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.totp.CreateTOTPSettings(ctx, t)
}

func (s *SuperuserTwoFactorStore) GetSuperuserTOTPSettings(ctx context.Context, superuserID string) (*store.TOTPSettings, error) {
	return s.totp.GetTOTPSettingsByUserID(ctx, superuserID)
}

func (s *SuperuserTwoFactorStore) UpdateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.totp.UpdateTOTPSettings(ctx, t)
}

func (s *SuperuserTwoFactorStore) DeleteSuperuserTOTPSettings(ctx context.Context, superuserID string) error {
	return s.totp.DeleteTOTPSettings(ctx, superuserID)
}

func (s *SuperuserTwoFactorStore) CreateSuperuserPendingTwoFactorSession(ctx context.Context, p *store.PendingTwoFactorSession) error {
	return s.pending.CreatePendingTwoFactorSession(ctx, p)
}

func (s *SuperuserTwoFactorStore) GetSuperuserPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	return s.pending.GetPendingTwoFactorSessionByHash(ctx, hash)
}

func (s *SuperuserTwoFactorStore) DeleteSuperuserPendingTwoFactorSession(ctx context.Context, id string) error {
	return s.pending.DeletePendingTwoFactorSession(ctx, id)
}
