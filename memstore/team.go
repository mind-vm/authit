package memstore

import (
	"context"
	"sync"

	"github.com/mind-vm/authit/store"
)

// TeamStore is an in-memory store.TeamStore.
type TeamStore struct {
	mu     sync.RWMutex
	byID   map[string]*store.Team
	bySlug map[string]string
}

func NewTeamStore() *TeamStore {
	return &TeamStore{byID: map[string]*store.Team{}, bySlug: map[string]string{}}
}

func (s *TeamStore) CreateTeam(_ context.Context, t *store.Team) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bySlug[t.Slug]; ok {
		return store.ErrConflict
	}
	cp := *t
	s.byID[t.ID] = &cp
	s.bySlug[t.Slug] = t.ID
	return nil
}

func (s *TeamStore) GetTeam(_ context.Context, id string) (*store.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *TeamStore) GetTeamBySlug(_ context.Context, slug string) (*store.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.bySlug[slug]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *TeamStore) UpdateTeam(_ context.Context, t *store.Team) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[t.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *t
	s.byID[t.ID] = &cp
	return nil
}

func (s *TeamStore) DeleteTeam(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.bySlug, t.Slug)
	delete(s.byID, id)
	return nil
}

// MemberStore is an in-memory store.MemberStore.
type MemberStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.Member
	byTeamID map[string][]string
	byUserID map[string][]string
}

func NewMemberStore() *MemberStore {
	return &MemberStore{byID: map[string]*store.Member{}, byTeamID: map[string][]string{}, byUserID: map[string][]string{}}
}

func (s *MemberStore) CreateMember(_ context.Context, m *store.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *m
	s.byID[m.ID] = &cp
	s.byTeamID[m.TeamID] = append(s.byTeamID[m.TeamID], m.ID)
	if m.UserID != nil {
		s.byUserID[*m.UserID] = append(s.byUserID[*m.UserID], m.ID)
	}
	return nil
}

func (s *MemberStore) GetMember(_ context.Context, id string) (*store.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *m
	return &cp, nil
}

func (s *MemberStore) GetMemberByUserAndTeam(_ context.Context, userID, teamID string) (*store.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range s.byUserID[userID] {
		if m := s.byID[id]; m.TeamID == teamID {
			cp := *m
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *MemberStore) ListMembersByTeam(_ context.Context, teamID string) ([]*store.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*store.Member
	for _, id := range s.byTeamID[teamID] {
		cp := *s.byID[id]
		out = append(out, &cp)
	}
	return out, nil
}

func (s *MemberStore) ListMembershipsByUser(_ context.Context, userID string) ([]*store.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*store.Member
	for _, id := range s.byUserID[userID] {
		cp := *s.byID[id]
		out = append(out, &cp)
	}
	return out, nil
}

func (s *MemberStore) UpdateMember(_ context.Context, m *store.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[m.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *m
	s.byID[m.ID] = &cp
	return nil
}

func (s *MemberStore) DeleteMember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.byID, id)
	return nil
}

// InvitationStore is an in-memory store.InvitationStore.
type InvitationStore struct {
	mu       sync.RWMutex
	byID     map[string]*store.Invitation
	byHash   map[string]string
	byTeamID map[string][]string
}

func NewInvitationStore() *InvitationStore {
	return &InvitationStore{byID: map[string]*store.Invitation{}, byHash: map[string]string{}, byTeamID: map[string][]string{}}
}

func (s *InvitationStore) CreateInvitation(_ context.Context, i *store.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *i
	s.byID[i.ID] = &cp
	s.byHash[i.TokenHash] = i.ID
	s.byTeamID[i.TeamID] = append(s.byTeamID[i.TeamID], i.ID)
	return nil
}

func (s *InvitationStore) GetInvitation(_ context.Context, id string) (*store.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *i
	return &cp, nil
}

func (s *InvitationStore) GetInvitationByTokenHash(_ context.Context, hash string) (*store.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *InvitationStore) ListInvitationsByTeam(_ context.Context, teamID string) ([]*store.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*store.Invitation
	for _, id := range s.byTeamID[teamID] {
		cp := *s.byID[id]
		out = append(out, &cp)
	}
	return out, nil
}

func (s *InvitationStore) UpdateInvitation(_ context.Context, i *store.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[i.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *i
	s.byID[i.ID] = &cp
	return nil
}
