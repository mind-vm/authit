package pgstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

func (s *Store) CreateUser(ctx context.Context, u *store.User) error {
	return mapErr(s.q(ctx).CreateUser(ctx, db.CreateUserParams{
		ID: u.ID, Email: u.Email, PasswordHash: u.PasswordHash, EmailVerified: u.EmailVerified,
		EmailVerifiedAt: u.EmailVerifiedAt, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}))
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*store.User, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetUserByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toUser(r), nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	r, err := s.q(ctx).GetUserByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}
	return toUser(r), nil
}

func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	if !isID(u.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateUser(ctx, db.UpdateUserParams{
		ID: u.ID, Email: u.Email, PasswordHash: u.PasswordHash, EmailVerified: u.EmailVerified,
		EmailVerifiedAt: u.EmailVerifiedAt, UpdatedAt: u.UpdatedAt,
	}))
}

func toUser(r db.AuthUser) *store.User {
	return &store.User{
		ID: r.ID, Email: r.Email, PasswordHash: r.PasswordHash, EmailVerified: r.EmailVerified,
		EmailVerifiedAt: r.EmailVerifiedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	return mapErr(s.q(ctx).CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt, UserAgent: t.UserAgent, IpAddress: t.IPAddress, TeamID: t.TeamID, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*store.RefreshToken, error) {
	r, err := s.q(ctx).GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toRefreshToken(r), nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).RevokeRefreshToken(ctx, id))
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, id string) (bool, error) {
	if !isID(id) {
		return false, nil
	}
	n, err := s.q(ctx).ConsumeRefreshToken(ctx, id)
	return n == 1, mapErr(err)
}

func (s *Store) TouchRefreshToken(ctx context.Context, id string, expiresAt time.Time) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).TouchRefreshToken(ctx, db.TouchRefreshTokenParams{ID: id, ExpiresAt: expiresAt}))
}

func (s *Store) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).RevokeAllUserRefreshTokens(ctx, userID))
}

func (s *Store) ListActiveRefreshTokens(ctx context.Context, userID string) ([]*store.RefreshToken, error) {
	if !isID(userID) {
		return []*store.RefreshToken{}, nil
	}
	rows, err := s.q(ctx).ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.RefreshToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRefreshToken(r))
	}
	return out, nil
}

func toRefreshToken(r db.AuthRefreshToken) *store.RefreshToken {
	return &store.RefreshToken{
		ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
		RevokedAt: r.RevokedAt, UserAgent: r.UserAgent, IPAddress: r.IpAddress, TeamID: r.TeamID, CreatedAt: r.CreatedAt,
	}
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, t *store.PasswordResetToken) error {
	return mapErr(s.q(ctx).CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetPasswordResetTokenByHash(ctx context.Context, hash string) (*store.PasswordResetToken, error) {
	r, err := s.q(ctx).GetPasswordResetTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.PasswordResetToken{
		ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).MarkPasswordResetTokenUsed(ctx, id))
}

func (s *Store) DeleteUserPasswordResetTokens(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteUserPasswordResetTokens(ctx, userID))
}

func (s *Store) CreateEmailVerificationToken(ctx context.Context, t *store.EmailVerificationToken) error {
	return mapErr(s.q(ctx).CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetEmailVerificationTokenByHash(ctx context.Context, hash string) (*store.EmailVerificationToken, error) {
	r, err := s.q(ctx).GetEmailVerificationTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.EmailVerificationToken{
		ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).MarkEmailVerificationTokenUsed(ctx, id))
}

func (s *Store) DeleteUserEmailVerificationTokens(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteUserEmailVerificationTokens(ctx, userID))
}
