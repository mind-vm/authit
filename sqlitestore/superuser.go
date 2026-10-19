package sqlitestore

import (
	"context"

	"github.com/mind-vm/authit/store"
)

// The operator plane's ports. They sit in their own file, and their rows in
// their own tables, for the reason the superuser package exists at all: a
// dump of the user-plane tables must not be replayable as an admin session.

var (
	_ store.SuperuserStore             = (*Store)(nil)
	_ store.SuperuserRefreshTokenStore = (*Store)(nil)
	_ store.SuperuserTwoFactorStore    = (*Store)(nil)
)

const superuserCols = `id, email, password_hash, display_name, is_active, created_by, last_login_at, created_at, updated_at`

func scanSuperuser(r scanner) (*store.Superuser, error) {
	var su store.Superuser
	err := r.Scan(&su.ID, &su.Email, &su.PasswordHash, &su.DisplayName, &su.IsActive, &su.CreatedBy,
		tmPtr{&su.LastLoginAt}, tm{&su.CreatedAt}, tm{&su.UpdatedAt})
	return &su, err
}

func (s *Store) CreateSuperuser(ctx context.Context, su *store.Superuser) error {
	if err := newID(&su.ID); err != nil {
		return err
	}
	createdBy, err := refPtr(su.CreatedBy)
	if err != nil {
		return err
	}
	if c, ok := createdBy.(string); ok {
		su.CreatedBy = &c
	}
	return s.exec(ctx, `INSERT INTO auth_superusers (`+superuserCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		su.ID, su.Email, su.PasswordHash, su.DisplayName, su.IsActive, createdBy, tsPtr(su.LastLoginAt),
		ts(su.CreatedAt), ts(su.UpdatedAt))
}

func (s *Store) GetSuperuserByID(ctx context.Context, id string) (*store.Superuser, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanSuperuser, `SELECT `+superuserCols+` FROM auth_superusers WHERE id = ?`, id)
}

func (s *Store) GetSuperuserByEmail(ctx context.Context, email string) (*store.Superuser, error) {
	return one(ctx, s.q(ctx), scanSuperuser, `SELECT `+superuserCols+` FROM auth_superusers WHERE email = ?`, email)
}

func (s *Store) ListSuperusers(ctx context.Context) ([]*store.Superuser, error) {
	return collect(ctx, s.q(ctx), scanSuperuser, `SELECT `+superuserCols+` FROM auth_superusers ORDER BY created_at, id`)
}

func (s *Store) UpdateSuperuser(ctx context.Context, su *store.Superuser) error {
	id, ok := canon(su.ID)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_superusers
		SET email = ?, password_hash = ?, display_name = ?, is_active = ?, last_login_at = ?, updated_at = ?
		WHERE id = ?`,
		su.Email, su.PasswordHash, su.DisplayName, su.IsActive, tsPtr(su.LastLoginAt), ts(su.UpdatedAt), id)
}

func (s *Store) CountSuperusers(ctx context.Context) (int, error) {
	var n int
	err := s.q(ctx).QueryRowContext(ctx, `SELECT count(*) FROM auth_superusers`).Scan(&n)
	return n, mapErr(err)
}

const superuserRefreshTokenCols = `id, superuser_id, token_hash, expires_at, revoked_at, user_agent, ip_address, created_at`

func scanSuperuserRefreshToken(r scanner) (*store.SuperuserRefreshToken, error) {
	var t store.SuperuserRefreshToken
	err := r.Scan(&t.ID, &t.SuperuserID, &t.TokenHash, tm{&t.ExpiresAt}, tmPtr{&t.RevokedAt},
		&t.UserAgent, &t.IPAddress, tm{&t.CreatedAt})
	return &t, err
}

func (s *Store) CreateSuperuserRefreshToken(ctx context.Context, t *store.SuperuserRefreshToken) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	superuserID, err := ref(t.SuperuserID)
	if err != nil {
		return err
	}
	t.SuperuserID = superuserID
	return s.exec(ctx, `INSERT INTO auth_superuser_refresh_tokens (`+superuserRefreshTokenCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SuperuserID, t.TokenHash, ts(t.ExpiresAt), tsPtr(t.RevokedAt), t.UserAgent, t.IPAddress, ts(t.CreatedAt))
}

func (s *Store) GetSuperuserRefreshTokenByHash(ctx context.Context, hash string) (*store.SuperuserRefreshToken, error) {
	return one(ctx, s.q(ctx), scanSuperuserRefreshToken,
		`SELECT `+superuserRefreshTokenCols+` FROM auth_superuser_refresh_tokens WHERE token_hash = ?`, hash)
}

func (s *Store) RevokeSuperuserRefreshToken(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_superuser_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`,
		now(), id)
}

func (s *Store) ConsumeSuperuserRefreshToken(ctx context.Context, id string) (bool, error) {
	id, ok := canon(id)
	if !ok {
		return false, nil
	}
	n, err := s.execCount(ctx, `UPDATE auth_superuser_refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
	return n == 1, err
}

func (s *Store) RevokeAllSuperuserRefreshTokens(ctx context.Context, superuserID string) error {
	superuserID, ok := canon(superuserID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `UPDATE auth_superuser_refresh_tokens SET revoked_at = ?
		WHERE superuser_id = ? AND revoked_at IS NULL`, now(), superuserID)
}

func (s *Store) ListActiveSuperuserRefreshTokens(ctx context.Context, superuserID string) ([]*store.SuperuserRefreshToken, error) {
	superuserID, ok := canon(superuserID)
	if !ok {
		return []*store.SuperuserRefreshToken{}, nil
	}
	return collect(ctx, s.q(ctx), scanSuperuserRefreshToken, `SELECT `+superuserRefreshTokenCols+`
		FROM auth_superuser_refresh_tokens
		WHERE superuser_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at, id`, superuserID, now())
}

func (s *Store) CreateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.createTOTP(ctx, "auth_superuser_totp_settings", "superuser_id", t)
}

func (s *Store) GetSuperuserTOTPSettings(ctx context.Context, superuserID string) (*store.TOTPSettings, error) {
	return s.getTOTP(ctx, "auth_superuser_totp_settings", "superuser_id", superuserID)
}

func (s *Store) UpdateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.updateTOTP(ctx, "auth_superuser_totp_settings", "superuser_id", t)
}

func (s *Store) DeleteSuperuserTOTPSettings(ctx context.Context, superuserID string) error {
	return s.deleteTOTP(ctx, "auth_superuser_totp_settings", "superuser_id", superuserID)
}

func (s *Store) CreateSuperuserPendingTwoFactorSession(ctx context.Context, p *store.PendingTwoFactorSession) error {
	return s.createPending(ctx, "auth_superuser_pending_two_factor_sessions", "superuser_id", p)
}

func (s *Store) GetSuperuserPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	return s.getPending(ctx, "auth_superuser_pending_two_factor_sessions", "superuser_id", hash)
}

func (s *Store) DeleteSuperuserPendingTwoFactorSession(ctx context.Context, id string) error {
	return s.deletePending(ctx, "auth_superuser_pending_two_factor_sessions", id)
}
