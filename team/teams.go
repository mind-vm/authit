package team

import (
	"context"
	"errors"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// CreateTeam creates a new team owned by ownerUserID and creates the
// corresponding owner membership.
//
// Both writes happen in one transaction: a team whose owner membership failed
// to insert is a team nobody can administer, and the last-owner protections
// elsewhere assume that cannot exist.
func (s *Service) CreateTeam(ctx context.Context, name, slug, ownerUserID, ownerDisplayName, ownerEmail string) (store.Team, error) {
	var created store.Team
	err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		taken, err := sqlb.Query[store.Team]().
			Where(store.TeamCols.Slug.Eq(slug)).
			Exists(ctx, tx)
		if err != nil {
			return err
		}
		if taken {
			return ErrSlugTaken
		}

		t := store.Team{Name: name, Slug: slug, OwnerID: ownerUserID}
		inserted, err := sqlb.InsertRows(&t).Exec(ctx, tx)
		if err != nil {
			return err
		}
		created = inserted[0]

		owner := ownerUserID
		m := store.TeamMember{
			TeamID: created.ID, UserID: &owner, Role: string(RoleOwner),
			DisplayName: ownerDisplayName, Email: ownerEmail, IsActive: true,
		}
		_, err = sqlb.InsertRows(&m).Exec(ctx, tx)
		return err
	})
	if err != nil {
		return store.Team{}, err
	}
	return created, nil
}

// GetTeam looks up a team by ID.
func (s *Service) GetTeam(ctx context.Context, id string) (store.Team, error) {
	t, err := sqlb.Query[store.Team]().Where(store.TeamCols.ID.Eq(id)).One(ctx, s.db)
	if err != nil && errors.Is(err, sqlb.ErrNotFound) {
		return store.Team{}, ErrNotFound
	}
	return t, err
}

// GetTeamBySlug looks up a team by its slug.
func (s *Service) GetTeamBySlug(ctx context.Context, slug string) (store.Team, error) {
	t, err := sqlb.Query[store.Team]().Where(store.TeamCols.Slug.Eq(slug)).One(ctx, s.db)
	if err != nil && errors.Is(err, sqlb.ErrNotFound) {
		return store.Team{}, ErrNotFound
	}
	return t, err
}
