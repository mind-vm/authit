package team

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// CreateTeam creates a new team owned by ownerUserID and creates the
// corresponding owner Member record.
func (s *Service) CreateTeam(ctx context.Context, name, slug, ownerUserID, ownerDisplayName, ownerEmail string) (store.Team, error) {
	if _, err := s.stores.Teams.GetTeamBySlug(ctx, slug); err == nil {
		return store.Team{}, ErrSlugTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Team{}, err
	}

	teamID, err := authitcrypto.NewID()
	if err != nil {
		return store.Team{}, err
	}
	now := time.Now()
	t := &store.Team{ID: teamID, Name: name, Slug: slug, OwnerID: ownerUserID, CreatedAt: now, UpdatedAt: now}
	if err := s.stores.Teams.CreateTeam(ctx, t); err != nil {
		return store.Team{}, err
	}

	memberID, err := authitcrypto.NewID()
	if err != nil {
		return store.Team{}, err
	}
	owner := ownerUserID
	if err := s.stores.Members.CreateMember(ctx, &store.Member{
		ID: memberID, TeamID: teamID, UserID: &owner, Role: store.RoleOwner,
		DisplayName: ownerDisplayName, Email: ownerEmail, IsActive: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return store.Team{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamCreated, Result: audit.ResultSuccess, ActorID: ownerUserID, TargetID: teamID,
	})
	return *t, nil
}

// GetTeam looks up a team by ID.
func (s *Service) GetTeam(ctx context.Context, id string) (store.Team, error) {
	t, err := s.stores.Teams.GetTeam(ctx, id)
	if err != nil {
		return store.Team{}, err
	}
	return *t, nil
}

// GetTeamBySlug looks up a team by its slug.
func (s *Service) GetTeamBySlug(ctx context.Context, slug string) (store.Team, error) {
	t, err := s.stores.Teams.GetTeamBySlug(ctx, slug)
	if err != nil {
		return store.Team{}, err
	}
	return *t, nil
}
