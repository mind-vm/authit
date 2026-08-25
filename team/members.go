package team

import (
	"context"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// GetMember looks up a member by ID.
func (s *Service) GetMember(ctx context.Context, id string) (store.Member, error) {
	m, err := s.stores.Members.GetMember(ctx, id)
	if err != nil {
		return store.Member{}, err
	}
	return *m, nil
}

// GetMemberByUserAndTeam looks up a user's membership within a specific
// team — typically used by a host application to resolve the caller's role
// for an authorization check.
func (s *Service) GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (store.Member, error) {
	m, err := s.stores.Members.GetMemberByUserAndTeam(ctx, userID, teamID)
	if err != nil {
		return store.Member{}, err
	}
	return *m, nil
}

// ListMembersByTeam lists every member of a team.
func (s *Service) ListMembersByTeam(ctx context.Context, teamID string) ([]store.Member, error) {
	members, err := s.stores.Members.ListMembersByTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	return derefMembers(members), nil
}

// ListMembershipsByUser lists every team a user belongs to — used to drive
// a multi-team login/team-selection step.
func (s *Service) ListMembershipsByUser(ctx context.Context, userID string) ([]store.Member, error) {
	members, err := s.stores.Members.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return derefMembers(members), nil
}

// UpdateMemberRole changes a member's role. It refuses to demote the last
// remaining owner of a team, since that would leave the team unownable.
func (s *Service) UpdateMemberRole(ctx context.Context, memberID string, role store.Role) error {
	m, err := s.stores.Members.GetMember(ctx, memberID)
	if err != nil {
		return err
	}
	if m.Role == store.RoleOwner && role != store.RoleOwner {
		if err := s.requireNotLastOwner(ctx, m.TeamID, m.ID); err != nil {
			return err
		}
	}
	m.Role = role
	m.UpdatedAt = time.Now()
	if err := s.stores.Members.UpdateMember(ctx, m); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamMemberRoleChanged, Result: audit.ResultSuccess, TargetID: memberID,
		Metadata: map[string]any{"team_id": m.TeamID, "role": string(role)},
	})
	return nil
}

// SetMemberActive activates or deactivates a member (soft removal).
func (s *Service) SetMemberActive(ctx context.Context, memberID string, active bool) error {
	m, err := s.stores.Members.GetMember(ctx, memberID)
	if err != nil {
		return err
	}
	if m.Role == store.RoleOwner && !active {
		if err := s.requireNotLastOwner(ctx, m.TeamID, m.ID); err != nil {
			return err
		}
	}
	m.IsActive = active
	m.UpdatedAt = time.Now()
	if err := s.stores.Members.UpdateMember(ctx, m); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamMemberStatusChanged, Result: audit.ResultSuccess, TargetID: memberID,
		Metadata: map[string]any{"team_id": m.TeamID, "active": active},
	})
	return nil
}

// RemoveMember permanently removes a member from a team. It refuses to
// remove the last remaining owner.
func (s *Service) RemoveMember(ctx context.Context, memberID string) error {
	m, err := s.stores.Members.GetMember(ctx, memberID)
	if err != nil {
		return err
	}
	if m.Role == store.RoleOwner {
		if err := s.requireNotLastOwner(ctx, m.TeamID, m.ID); err != nil {
			return err
		}
	}
	if err := s.stores.Members.DeleteMember(ctx, memberID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamMemberRemoved, Result: audit.ResultSuccess, TargetID: memberID,
		Metadata: map[string]any{"team_id": m.TeamID},
	})
	return nil
}

func (s *Service) requireNotLastOwner(ctx context.Context, teamID, excludeMemberID string) error {
	members, err := s.stores.Members.ListMembersByTeam(ctx, teamID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if m.ID != excludeMemberID && m.Role == store.RoleOwner && m.IsActive {
			return nil
		}
	}
	return ErrLastOwner
}

func derefMembers(members []*store.Member) []store.Member {
	out := make([]store.Member, len(members))
	for i, m := range members {
		out[i] = *m
	}
	return out
}
