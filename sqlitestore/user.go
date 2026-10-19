package sqlitestore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
)

const userCols = `id, email, password_hash, email_verified, email_verified_at, created_at, updated_at`

func scanUser(r scanner) (*store.User, error) {
	var u store.User
	err := r.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, tmPtr{&u.EmailVerifiedAt},
		tm{&u.CreatedAt}, tm{&u.UpdatedAt})
	return &u, err
}

func (s *Store) CreateUser(ctx context.Context, u *store.User) error {
	if err := newID(&u.ID); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_users (`+userCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.EmailVerified, tsPtr(u.EmailVerifiedAt), ts(u.CreatedAt), ts(u.UpdatedAt))
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*store.User, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanUser, `SELECT `+userCols+` FROM auth_users WHERE id = ?`, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	return one(ctx, s.q(ctx), scanUser, `SELECT `+userCols+` FROM auth_users WHERE email = ?`, email)
}

func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	id, ok := canon(u.ID)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_users
		SET email = ?, password_hash = ?, email_verified = ?, email_verified_at = ?, updated_at = ?
		WHERE id = ?`,
		u.Email, u.PasswordHash, u.EmailVerified, tsPtr(u.EmailVerifiedAt), ts(u.UpdatedAt), id)
}

const refreshTokenCols = `id, user_id, token_hash, expires_at, revoked_at, user_agent, ip_address, created_at`

func scanRefreshToken(r scanner) (*store.RefreshToken, error) {
	var t store.RefreshToken
	err := r.Scan(&t.ID, &t.UserID, &t.TokenHash, tm{&t.ExpiresAt}, tmPtr{&t.RevokedAt},
		&t.UserAgent, &t.IPAddress, tm{&t.CreatedAt})
	return &t, err
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	userID, err := ref(t.UserID)
	if err != nil {
		return err
	}
	t.UserID = userID
	return s.exec(ctx, `INSERT INTO auth_refresh_tokens (`+refreshTokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, ts(t.ExpiresAt), tsPtr(t.RevokedAt), t.UserAgent, t.IPAddress, ts(t.CreatedAt))
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*store.RefreshToken, error) {
	return one(ctx, s.q(ctx), scanRefreshToken,
		`SELECT `+refreshTokenCols+` FROM auth_refresh_tokens WHERE token_hash = ?`, hash)
}

func (s *Store) RevokeRefreshToken(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, now(), id)
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, id string) (bool, error) {
	id, ok := canon(id)
	if !ok {
		return false, nil
	}
	n, err := s.execCount(ctx, `UPDATE auth_refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
	return n == 1, err
}

// TouchRefreshToken does not extend a revoked session back to life.
func (s *Store) TouchRefreshToken(ctx context.Context, id string, expiresAt time.Time) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_refresh_tokens SET expires_at = ? WHERE id = ? AND revoked_at IS NULL`,
		ts(expiresAt), id)
}

func (s *Store) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	userID, ok := canon(userID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `UPDATE auth_refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		now(), userID)
}

func (s *Store) ListActiveRefreshTokens(ctx context.Context, userID string) ([]*store.RefreshToken, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.RefreshToken{}, nil
	}
	return collect(ctx, s.q(ctx), scanRefreshToken, `SELECT `+refreshTokenCols+` FROM auth_refresh_tokens
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at, id`, userID, now())
}

// oneTimeToken is the shape password-reset and email-verification tokens
// share, and so do their tables.
type oneTimeToken struct {
	ID, UserID, TokenHash string
	ExpiresAt, CreatedAt  time.Time
	UsedAt                *time.Time
}

const oneTimeTokenCols = `id, user_id, token_hash, expires_at, used_at, created_at`

func scanOneTimeToken(r scanner) (*oneTimeToken, error) {
	var t oneTimeToken
	err := r.Scan(&t.ID, &t.UserID, &t.TokenHash, tm{&t.ExpiresAt}, tmPtr{&t.UsedAt}, tm{&t.CreatedAt})
	return &t, err
}

func (s *Store) createOneTimeToken(ctx context.Context, table string, id, userID *string, hash string, expiresAt time.Time, usedAt *time.Time, createdAt time.Time) error {
	if err := newID(id); err != nil {
		return err
	}
	u, err := ref(*userID)
	if err != nil {
		return err
	}
	*userID = u
	return s.exec(ctx, `INSERT INTO `+table+` (`+oneTimeTokenCols+`) VALUES (?, ?, ?, ?, ?, ?)`,
		*id, *userID, hash, ts(expiresAt), tsPtr(usedAt), ts(createdAt))
}

func (s *Store) markOneTimeTokenUsed(ctx context.Context, table, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE `+table+` SET used_at = ? WHERE id = ?`, now(), id)
}

func (s *Store) deleteUserOneTimeTokens(ctx context.Context, table, userID string) error {
	userID, ok := canon(userID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM `+table+` WHERE user_id = ?`, userID)
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, t *store.PasswordResetToken) error {
	return s.createOneTimeToken(ctx, "auth_password_reset_tokens", &t.ID, &t.UserID, t.TokenHash, t.ExpiresAt, t.UsedAt, t.CreatedAt)
}

func (s *Store) GetPasswordResetTokenByHash(ctx context.Context, hash string) (*store.PasswordResetToken, error) {
	t, err := one(ctx, s.q(ctx), scanOneTimeToken,
		`SELECT `+oneTimeTokenCols+` FROM auth_password_reset_tokens WHERE token_hash = ?`, hash)
	if err != nil {
		return nil, err
	}
	return &store.PasswordResetToken{
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt,
	}, nil
}

func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, id string) error {
	return s.markOneTimeTokenUsed(ctx, "auth_password_reset_tokens", id)
}

func (s *Store) DeleteUserPasswordResetTokens(ctx context.Context, userID string) error {
	return s.deleteUserOneTimeTokens(ctx, "auth_password_reset_tokens", userID)
}

func (s *Store) CreateEmailVerificationToken(ctx context.Context, t *store.EmailVerificationToken) error {
	return s.createOneTimeToken(ctx, "auth_email_verification_tokens", &t.ID, &t.UserID, t.TokenHash, t.ExpiresAt, t.UsedAt, t.CreatedAt)
}

func (s *Store) GetEmailVerificationTokenByHash(ctx context.Context, hash string) (*store.EmailVerificationToken, error) {
	t, err := one(ctx, s.q(ctx), scanOneTimeToken,
		`SELECT `+oneTimeTokenCols+` FROM auth_email_verification_tokens WHERE token_hash = ?`, hash)
	if err != nil {
		return nil, err
	}
	return &store.EmailVerificationToken{
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt,
	}, nil
}

func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, id string) error {
	return s.markOneTimeTokenUsed(ctx, "auth_email_verification_tokens", id)
}

func (s *Store) DeleteUserEmailVerificationTokens(ctx context.Context, userID string) error {
	return s.deleteUserOneTimeTokens(ctx, "auth_email_verification_tokens", userID)
}
