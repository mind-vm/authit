package sqlitestore

import (
	"context"

	"github.com/mind-vm/authit/store"
)

// The team plane's three ports: teams, their members and the invitations to
// join them.

var (
	_ store.TeamStore       = (*Store)(nil)
	_ store.MemberStore     = (*Store)(nil)
	_ store.InvitationStore = (*Store)(nil)
)

const teamCols = `id, name, slug, owner_id, created_at, updated_at`

func scanTeam(r scanner) (*store.Team, error) {
	var t store.Team
	err := r.Scan(&t.ID, &t.Name, &t.Slug, &t.OwnerID, tm{&t.CreatedAt}, tm{&t.UpdatedAt})
	return &t, err
}

func (s *Store) CreateTeam(ctx context.Context, t *store.Team) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	ownerID, err := ref(t.OwnerID)
	if err != nil {
		return err
	}
	t.OwnerID = ownerID
	return s.exec(ctx, `INSERT INTO auth_teams (`+teamCols+`) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Slug, t.OwnerID, ts(t.CreatedAt), ts(t.UpdatedAt))
}

func (s *Store) GetTeam(ctx context.Context, id string) (*store.Team, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanTeam, `SELECT `+teamCols+` FROM auth_teams WHERE id = ?`, id)
}

func (s *Store) GetTeamBySlug(ctx context.Context, slug string) (*store.Team, error) {
	return one(ctx, s.q(ctx), scanTeam, `SELECT `+teamCols+` FROM auth_teams WHERE slug = ?`, slug)
}

func (s *Store) UpdateTeam(ctx context.Context, t *store.Team) error {
	id, ok := canon(t.ID)
	if !ok {
		return store.ErrNotFound
	}
	ownerID, err := ref(t.OwnerID)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_teams SET name = ?, slug = ?, owner_id = ?, updated_at = ? WHERE id = ?`,
		t.Name, t.Slug, ownerID, ts(t.UpdatedAt), id)
}

// DeleteTeam takes the team's members and invitations with it.
func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `DELETE FROM auth_teams WHERE id = ?`, id)
}

const memberCols = `id, team_id, user_id, role, display_name, email, is_active, created_at, updated_at`

func scanMember(r scanner) (*store.Member, error) {
	var m store.Member
	err := r.Scan(&m.ID, &m.TeamID, &m.UserID, &m.Role, &m.DisplayName, &m.Email, &m.IsActive,
		tm{&m.CreatedAt}, tm{&m.UpdatedAt})
	return &m, err
}

func (s *Store) CreateMember(ctx context.Context, m *store.Member) error {
	if err := newID(&m.ID); err != nil {
		return err
	}
	teamID, err := ref(m.TeamID)
	if err != nil {
		return err
	}
	m.TeamID = teamID
	if m.UserID != nil {
		userID, err := ref(*m.UserID)
		if err != nil {
			return err
		}
		m.UserID = &userID
	}
	return s.exec(ctx, `INSERT INTO auth_team_members (`+memberCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.TeamID, m.UserID, string(m.Role), m.DisplayName, m.Email, m.IsActive,
		ts(m.CreatedAt), ts(m.UpdatedAt))
}

func (s *Store) GetMember(ctx context.Context, id string) (*store.Member, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanMember, `SELECT `+memberCols+` FROM auth_team_members WHERE id = ?`, id)
}

// GetMemberByUserAndTeam never matches a member without a user: the
// equality is false against NULL.
func (s *Store) GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (*store.Member, error) {
	userID, ok := canon(userID)
	if !ok {
		return nil, store.ErrNotFound
	}
	teamID, ok = canon(teamID)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanMember, `SELECT `+memberCols+` FROM auth_team_members
		WHERE user_id = ? AND team_id = ?`, userID, teamID)
}

// ListMembersByTeam lists every member, active or not, since the last-owner
// check reads Role and IsActive itself. Inside a transaction it needs no
// lock of its own: the transaction already holds SQLite's write lock, so
// that check and the write it guards cannot interleave with another.
func (s *Store) ListMembersByTeam(ctx context.Context, teamID string) ([]*store.Member, error) {
	teamID, ok := canon(teamID)
	if !ok {
		return []*store.Member{}, nil
	}
	return collect(ctx, s.q(ctx), scanMember, `SELECT `+memberCols+` FROM auth_team_members
		WHERE team_id = ? ORDER BY created_at, id`, teamID)
}

func (s *Store) ListMembershipsByUser(ctx context.Context, userID string) ([]*store.Member, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.Member{}, nil
	}
	return collect(ctx, s.q(ctx), scanMember, `SELECT `+memberCols+` FROM auth_team_members
		WHERE user_id = ? ORDER BY created_at, id`, userID)
}

func (s *Store) UpdateMember(ctx context.Context, m *store.Member) error {
	id, ok := canon(m.ID)
	if !ok {
		return store.ErrNotFound
	}
	userID, err := refPtr(m.UserID)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_team_members
		SET user_id = ?, role = ?, display_name = ?, email = ?, is_active = ?, updated_at = ?
		WHERE id = ?`,
		userID, string(m.Role), m.DisplayName, m.Email, m.IsActive, ts(m.UpdatedAt), id)
}

func (s *Store) DeleteMember(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `DELETE FROM auth_team_members WHERE id = ?`, id)
}

const invitationCols = `id, team_id, email, token_hash, role, status, invited_by_id,
	expires_at, accepted_at, created_at, updated_at`

func scanInvitation(r scanner) (*store.Invitation, error) {
	var i store.Invitation
	var invitedBy *string
	err := r.Scan(&i.ID, &i.TeamID, &i.Email, &i.TokenHash, &i.Role, &i.Status, &invitedBy,
		tm{&i.ExpiresAt}, tmPtr{&i.AcceptedAt}, tm{&i.CreatedAt}, tm{&i.UpdatedAt})
	if invitedBy != nil {
		i.InvitedByID = *invitedBy
	}
	return &i, err
}

// optionalRef canonicalises a reference the port spells as a plain string,
// where empty means none; empty is NULL.
func optionalRef(id *string) (any, error) {
	if *id == "" {
		return nil, nil
	}
	c, err := ref(*id)
	if err != nil {
		return nil, err
	}
	*id = c
	return c, nil
}

func (s *Store) CreateInvitation(ctx context.Context, i *store.Invitation) error {
	if err := newID(&i.ID); err != nil {
		return err
	}
	teamID, err := ref(i.TeamID)
	if err != nil {
		return err
	}
	i.TeamID = teamID
	invitedBy, err := optionalRef(&i.InvitedByID)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_team_invitations (`+invitationCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.TeamID, i.Email, i.TokenHash, string(i.Role), string(i.Status), invitedBy,
		ts(i.ExpiresAt), tsPtr(i.AcceptedAt), ts(i.CreatedAt), ts(i.UpdatedAt))
}

func (s *Store) GetInvitation(ctx context.Context, id string) (*store.Invitation, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanInvitation, `SELECT `+invitationCols+` FROM auth_team_invitations WHERE id = ?`, id)
}

// GetInvitationByTokenHash returns every status, not only pending: the
// service reads Status to refuse a revoked or accepted invitation.
func (s *Store) GetInvitationByTokenHash(ctx context.Context, hash string) (*store.Invitation, error) {
	return one(ctx, s.q(ctx), scanInvitation,
		`SELECT `+invitationCols+` FROM auth_team_invitations WHERE token_hash = ?`, hash)
}

func (s *Store) ListInvitationsByTeam(ctx context.Context, teamID string) ([]*store.Invitation, error) {
	teamID, ok := canon(teamID)
	if !ok {
		return []*store.Invitation{}, nil
	}
	return collect(ctx, s.q(ctx), scanInvitation, `SELECT `+invitationCols+` FROM auth_team_invitations
		WHERE team_id = ? ORDER BY created_at, id`, teamID)
}

func (s *Store) UpdateInvitation(ctx context.Context, i *store.Invitation) error {
	id, ok := canon(i.ID)
	if !ok {
		return store.ErrNotFound
	}
	invitedBy, err := optionalRef(&i.InvitedByID)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_team_invitations
		SET email = ?, token_hash = ?, role = ?, status = ?, invited_by_id = ?,
		    expires_at = ?, accepted_at = ?, updated_at = ?
		WHERE id = ?`,
		i.Email, i.TokenHash, string(i.Role), string(i.Status), invitedBy,
		ts(i.ExpiresAt), tsPtr(i.AcceptedAt), ts(i.UpdatedAt), id)
}
