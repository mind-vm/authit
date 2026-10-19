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
	m, err := s.guardedMemberWrite(ctx, memberID, func(m *store.Member) bool {
		return m.Role == store.RoleOwner && role != store.RoleOwner
	}, func(ctx context.Context, m *store.Member) error {
		m.Role = role
		m.UpdatedAt = time.Now()
		return s.stores.Members.UpdateMember(ctx, m)
	})
	if err != nil {
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
	m, err := s.guardedMemberWrite(ctx, memberID, func(m *store.Member) bool {
		return m.Role == store.RoleOwner && !active
	}, func(ctx context.Context, m *store.Member) error {
		m.IsActive = active
		m.UpdatedAt = time.Now()
		return s.stores.Members.UpdateMember(ctx, m)
	})
	if err != nil {
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
	m, err := s.guardedMemberWrite(ctx, memberID, func(m *store.Member) bool {
		return m.Role == store.RoleOwner
	}, func(ctx context.Context, m *store.Member) error {
		return s.stores.Members.DeleteMember(ctx, m.ID)
	})
	if err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamMemberRemoved, Result: audit.ResultSuccess, TargetID: memberID,
		Metadata: map[string]any{"team_id": m.TeamID},
	})
	return nil
}

// guardedMemberWrite reads a member, refuses with ErrLastOwner when
// losesOwner says the change would take away the team's last active owner,
// and otherwise applies write -- all in one transaction when Stores.Tx is
// set. Checked apart from the write, two owners demoting each other at once
// each see the other still standing and both succeed, leaving a team nobody
// can administer.
func (s *Service) guardedMemberWrite(ctx context.Context, memberID string, losesOwner func(*store.Member) bool, write func(context.Context, *store.Member) error) (*store.Member, error) {
	var m *store.Member
	err := store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		var err error
		m, err = s.stores.Members.GetMember(ctx, memberID)
		if err != nil {
			return err
		}
		if losesOwner(m) {
			if err := s.requireNotLastOwner(ctx, m.TeamID, m.ID); err != nil {
				return err
			}
		}
		return write(ctx, m)
	})
	if err != nil {
		return nil, err
	}
	return m, nil
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
