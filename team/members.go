package team

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// GetMember looks up a member by ID.
func (s *Service) GetMember(ctx context.Context, id string) (store.TeamMember, error) {
	return s.member(ctx, s.db, id)
}

func (s *Service) member(ctx context.Context, db *sqlb.DB, id string) (store.TeamMember, error) {
	m, err := sqlb.Query[store.TeamMember]().
		Where(store.TeamMemberCols.ID.Eq(id)).
		One(ctx, db)
	if err != nil && errors.Is(err, sqlb.ErrNotFound) {
		return store.TeamMember{}, ErrNotFound
	}
	return m, err
}

// GetMemberByUserAndTeam looks up a user's membership within a specific
// team — typically used by a host application to resolve the caller's role
// for an authorization check.
func (s *Service) GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (store.TeamMember, error) {
	m, err := sqlb.Query[store.TeamMember]().
		Where(
			store.TeamMemberCols.UserID.Eq(userID),
			store.TeamMemberCols.TeamID.Eq(teamID),
		).
		One(ctx, s.db)
	if err != nil && errors.Is(err, sqlb.ErrNotFound) {
		return store.TeamMember{}, ErrNotFound
	}
	return m, err
}

// ListMembersByTeam lists every member of a team.
func (s *Service) ListMembersByTeam(ctx context.Context, teamID string) ([]store.TeamMember, error) {
	return sqlb.Query[store.TeamMember]().
		Where(store.TeamMemberCols.TeamID.Eq(teamID)).
		All(ctx, s.db)
}

// ListMembershipsByUser lists every team a user belongs to — used to drive
// a multi-team login/team-selection step.
func (s *Service) ListMembershipsByUser(ctx context.Context, userID string) ([]store.TeamMember, error) {
	return sqlb.Query[store.TeamMember]().
		Where(store.TeamMemberCols.UserID.Eq(userID)).
		All(ctx, s.db)
}

// UpdateMemberRole changes a member's role. It refuses to demote the last
// remaining owner of a team, since that would leave the team unownable.
func (s *Service) UpdateMemberRole(ctx context.Context, memberID string, role Role) error {
	// Read, check and write in one transaction: the last-owner check is a
	// read-then-write race otherwise, and two concurrent demotions of the two
	// remaining owners would each see the other and both succeed.
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		m, err := s.member(ctx, tx, memberID)
		if err != nil {
			return err
		}
		if m.Role == string(RoleOwner) && role != RoleOwner {
			if err := s.requireNotLastOwner(ctx, tx, m.TeamID, m.ID); err != nil {
				return err
			}
		}
		_, err = store.UpdateTeamMember().
			SetRole(string(role)).
			SetUpdatedAt(time.Now()).
			Where(store.TeamMemberCols.ID.Eq(memberID)).
			Stmt().Exec(ctx, tx)
		return err
	})
}

// SetMemberActive activates or deactivates a member (soft removal).
func (s *Service) SetMemberActive(ctx context.Context, memberID string, active bool) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		m, err := s.member(ctx, tx, memberID)
		if err != nil {
			return err
		}
		if m.Role == string(RoleOwner) && !active {
			if err := s.requireNotLastOwner(ctx, tx, m.TeamID, m.ID); err != nil {
				return err
			}
		}
		_, err = store.UpdateTeamMember().
			SetIsActive(active).
			SetUpdatedAt(time.Now()).
			Where(store.TeamMemberCols.ID.Eq(memberID)).
			Stmt().Exec(ctx, tx)
		return err
	})
}

// RemoveMember permanently removes a member from a team. It refuses to
// remove the last remaining owner.
func (s *Service) RemoveMember(ctx context.Context, memberID string) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		m, err := s.member(ctx, tx, memberID)
		if err != nil {
			return err
		}
		if m.Role == string(RoleOwner) {
			if err := s.requireNotLastOwner(ctx, tx, m.TeamID, m.ID); err != nil {
				return err
			}
		}
		_, err = sqlb.DeleteRows[store.TeamMember]().
			Where(store.TeamMemberCols.ID.Eq(memberID)).
			Exec(ctx, tx)
		return err
	})
}

// requireNotLastOwner reports ErrLastOwner unless some *other* active owner of
// teamID exists. It counts rather than listing every member: the question is
// "is there at least one more", and a team with a thousand members should not
// have to load them to answer it.
func (s *Service) requireNotLastOwner(ctx context.Context, db *sqlb.DB, teamID, excludeMemberID string) error {
	others, err := sqlb.Query[store.TeamMember]().
		Where(
			store.TeamMemberCols.TeamID.Eq(teamID),
			store.TeamMemberCols.Role.Eq(string(RoleOwner)),
			store.TeamMemberCols.IsActive.Eq(true),
			store.TeamMemberCols.ID.Neq(excludeMemberID),
		).
		Exists(ctx, db)
	if err != nil {
		return err
	}
	if !others {
		return ErrLastOwner
	}
	return nil
}
