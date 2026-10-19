package pgstore

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

// The team plane's three ports: teams, their members and the invitations to
// join them.

var (
	_ store.TeamStore       = (*Store)(nil)
	_ store.MemberStore     = (*Store)(nil)
	_ store.InvitationStore = (*Store)(nil)
)

func (s *Store) CreateTeam(ctx context.Context, t *store.Team) error {
	return mapErr(s.q(ctx).CreateTeam(ctx, db.CreateTeamParams{
		ID: t.ID, Name: t.Name, Slug: t.Slug, OwnerID: t.OwnerID, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}))
}

func (s *Store) GetTeam(ctx context.Context, id string) (*store.Team, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetTeam(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toTeam(r), nil
}

func (s *Store) GetTeamBySlug(ctx context.Context, slug string) (*store.Team, error) {
	r, err := s.q(ctx).GetTeamBySlug(ctx, slug)
	if err != nil {
		return nil, mapErr(err)
	}
	return toTeam(r), nil
}

func (s *Store) UpdateTeam(ctx context.Context, t *store.Team) error {
	if !isID(t.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateTeam(ctx, db.UpdateTeamParams{
		ID: t.ID, Name: t.Name, Slug: t.Slug, OwnerID: t.OwnerID, UpdatedAt: t.UpdatedAt,
	}))
}

// DeleteTeam takes the team's members and invitations with it.
func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).DeleteTeam(ctx, id))
}

func toTeam(r db.AuthTeam) *store.Team {
	return &store.Team{
		ID: r.ID, Name: r.Name, Slug: r.Slug, OwnerID: r.OwnerID, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Store) CreateMember(ctx context.Context, m *store.Member) error {
	return mapErr(s.q(ctx).CreateMember(ctx, db.CreateMemberParams{
		ID: m.ID, TeamID: m.TeamID, UserID: m.UserID, Role: string(m.Role), DisplayName: m.DisplayName,
		Email: m.Email, IsActive: m.IsActive, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}))
}

func (s *Store) GetMember(ctx context.Context, id string) (*store.Member, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetMember(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toMember(r), nil
}

// GetMemberByUserAndTeam never matches a member without a user: the
// equality is false against NULL.
func (s *Store) GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (*store.Member, error) {
	if !isID(userID) || !isID(teamID) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetMemberByUserAndTeam(ctx, db.GetMemberByUserAndTeamParams{UserID: &userID, TeamID: teamID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toMember(r), nil
}

// ListMembersByTeam lists every member, active or not, since the last-owner
// check reads Role and IsActive itself. Inside a transaction it also locks
// the rows it returns, so that check and the write it guards cannot
// interleave with another transaction doing the same.
func (s *Store) ListMembersByTeam(ctx context.Context, teamID string) ([]*store.Member, error) {
	if !isID(teamID) {
		return []*store.Member{}, nil
	}
	list := s.q(ctx).ListMembersByTeam
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		list = s.q(ctx).ListMembersByTeamForUpdate
	}
	rows, err := list(ctx, teamID)
	if err != nil {
		return nil, mapErr(err)
	}
	return toMembers(rows), nil
}

func (s *Store) ListMembershipsByUser(ctx context.Context, userID string) ([]*store.Member, error) {
	if !isID(userID) {
		return []*store.Member{}, nil
	}
	rows, err := s.q(ctx).ListMembershipsByUser(ctx, &userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return toMembers(rows), nil
}

func (s *Store) UpdateMember(ctx context.Context, m *store.Member) error {
	if !isID(m.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateMember(ctx, db.UpdateMemberParams{
		ID: m.ID, UserID: m.UserID, Role: string(m.Role), DisplayName: m.DisplayName,
		Email: m.Email, IsActive: m.IsActive, UpdatedAt: m.UpdatedAt,
	}))
}

func (s *Store) DeleteMember(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).DeleteMember(ctx, id))
}

func toMember(r db.AuthTeamMember) *store.Member {
	return &store.Member{
		ID: r.ID, TeamID: r.TeamID, UserID: r.UserID, Role: store.Role(r.Role), DisplayName: r.DisplayName,
		Email: r.Email, IsActive: r.IsActive, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func toMembers(rows []db.AuthTeamMember) []*store.Member {
	out := make([]*store.Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, toMember(r))
	}
	return out
}

func (s *Store) CreateInvitation(ctx context.Context, i *store.Invitation) error {
	return mapErr(s.q(ctx).CreateInvitation(ctx, db.CreateInvitationParams{
		ID: i.ID, TeamID: i.TeamID, Email: i.Email, TokenHash: i.TokenHash, Role: string(i.Role),
		Status: string(i.Status), InvitedByID: optional(i.InvitedByID), ExpiresAt: i.ExpiresAt,
		AcceptedAt: i.AcceptedAt, CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt,
	}))
}

func (s *Store) GetInvitation(ctx context.Context, id string) (*store.Invitation, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetInvitation(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toInvitation(r), nil
}

func (s *Store) GetInvitationByTokenHash(ctx context.Context, hash string) (*store.Invitation, error) {
	r, err := s.q(ctx).GetInvitationByTokenHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toInvitation(r), nil
}

func (s *Store) ListInvitationsByTeam(ctx context.Context, teamID string) ([]*store.Invitation, error) {
	if !isID(teamID) {
		return []*store.Invitation{}, nil
	}
	rows, err := s.q(ctx).ListInvitationsByTeam(ctx, teamID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.Invitation, 0, len(rows))
	for _, r := range rows {
		out = append(out, toInvitation(r))
	}
	return out, nil
}

func (s *Store) UpdateInvitation(ctx context.Context, i *store.Invitation) error {
	if !isID(i.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateInvitation(ctx, db.UpdateInvitationParams{
		ID: i.ID, Email: i.Email, TokenHash: i.TokenHash, Role: string(i.Role), Status: string(i.Status),
		InvitedByID: optional(i.InvitedByID), ExpiresAt: i.ExpiresAt, AcceptedAt: i.AcceptedAt,
		UpdatedAt: i.UpdatedAt,
	}))
}

func toInvitation(r db.AuthTeamInvitation) *store.Invitation {
	i := &store.Invitation{
		ID: r.ID, TeamID: r.TeamID, Email: r.Email, TokenHash: r.TokenHash, Role: store.Role(r.Role),
		Status: store.InvitationStatus(r.Status), ExpiresAt: r.ExpiresAt, AcceptedAt: r.AcceptedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.InvitedByID != nil {
		i.InvitedByID = *r.InvitedByID
	}
	return i
}

// optional binds an empty id as NULL, for a reference the port spells as a
// plain string.
func optional(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}
