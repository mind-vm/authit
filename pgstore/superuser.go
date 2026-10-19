package pgstore

import (
	"context"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

// The operator plane's two ports. They sit in their own file, and their rows
// in their own tables, for the reason the superuser package exists at all: a
// dump of the user-plane tables must not be replayable as an admin session.

var (
	_ store.SuperuserStore             = (*Store)(nil)
	_ store.SuperuserRefreshTokenStore = (*Store)(nil)
	_ store.SuperuserTwoFactorStore    = (*Store)(nil)
)

func (s *Store) CreateSuperuser(ctx context.Context, su *store.Superuser) error {
	return mapErr(s.q(ctx).CreateSuperuser(ctx, db.CreateSuperuserParams{
		ID: su.ID, Email: su.Email, PasswordHash: su.PasswordHash, DisplayName: su.DisplayName,
		IsActive: su.IsActive, CreatedBy: su.CreatedBy, LastLoginAt: su.LastLoginAt,
		CreatedAt: su.CreatedAt, UpdatedAt: su.UpdatedAt,
	}))
}

func (s *Store) GetSuperuserByID(ctx context.Context, id string) (*store.Superuser, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetSuperuserByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toSuperuser(r), nil
}

func (s *Store) GetSuperuserByEmail(ctx context.Context, email string) (*store.Superuser, error) {
	r, err := s.q(ctx).GetSuperuserByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}
	return toSuperuser(r), nil
}

func (s *Store) ListSuperusers(ctx context.Context) ([]*store.Superuser, error) {
	rows, err := s.q(ctx).ListSuperusers(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.Superuser, 0, len(rows))
	for _, r := range rows {
		out = append(out, toSuperuser(r))
	}
	return out, nil
}

func (s *Store) UpdateSuperuser(ctx context.Context, su *store.Superuser) error {
	if !isID(su.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateSuperuser(ctx, db.UpdateSuperuserParams{
		ID: su.ID, Email: su.Email, PasswordHash: su.PasswordHash, DisplayName: su.DisplayName,
		IsActive: su.IsActive, LastLoginAt: su.LastLoginAt, UpdatedAt: su.UpdatedAt,
	}))
}

func (s *Store) CountSuperusers(ctx context.Context) (int, error) {
	n, err := s.q(ctx).CountSuperusers(ctx)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(n), nil
}

func toSuperuser(r db.AuthSuperuser) *store.Superuser {
	return &store.Superuser{
		ID: r.ID, Email: r.Email, PasswordHash: r.PasswordHash, DisplayName: r.DisplayName,
		IsActive: r.IsActive, CreatedBy: r.CreatedBy, LastLoginAt: r.LastLoginAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Store) CreateSuperuserRefreshToken(ctx context.Context, t *store.SuperuserRefreshToken) error {
	return mapErr(s.q(ctx).CreateSuperuserRefreshToken(ctx, db.CreateSuperuserRefreshTokenParams{
		ID: t.ID, SuperuserID: t.SuperuserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt, UserAgent: t.UserAgent, IpAddress: t.IPAddress, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetSuperuserRefreshTokenByHash(ctx context.Context, hash string) (*store.SuperuserRefreshToken, error) {
	r, err := s.q(ctx).GetSuperuserRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.SuperuserRefreshToken{
		ID: r.ID, SuperuserID: r.SuperuserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
		RevokedAt: r.RevokedAt, UserAgent: r.UserAgent, IPAddress: r.IpAddress, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) RevokeSuperuserRefreshToken(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).RevokeSuperuserRefreshToken(ctx, id))
}

func (s *Store) RevokeAllSuperuserRefreshTokens(ctx context.Context, superuserID string) error {
	if !isID(superuserID) {
		return nil
	}
	return mapErr(s.q(ctx).RevokeAllSuperuserRefreshTokens(ctx, superuserID))
}

func (s *Store) ListActiveSuperuserRefreshTokens(ctx context.Context, superuserID string) ([]*store.SuperuserRefreshToken, error) {
	if !isID(superuserID) {
		return []*store.SuperuserRefreshToken{}, nil
	}
	rows, err := s.q(ctx).ListActiveSuperuserRefreshTokens(ctx, superuserID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.SuperuserRefreshToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, &store.SuperuserRefreshToken{
			ID: r.ID, SuperuserID: r.SuperuserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
			RevokedAt: r.RevokedAt, UserAgent: r.UserAgent, IPAddress: r.IpAddress, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (s *Store) CreateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return mapErr(s.q(ctx).CreateSuperuserTOTPSettings(ctx, db.CreateSuperuserTOTPSettingsParams{
		ID: t.ID, SuperuserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled,
		VerifiedAt: t.VerifiedAt, RecoveryCodeHashes: nonNil(t.RecoveryCodeHashes),
		RecoveryCodesUsed: int32(t.RecoveryCodesUsed), CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}))
}

func (s *Store) GetSuperuserTOTPSettings(ctx context.Context, superuserID string) (*store.TOTPSettings, error) {
	if !isID(superuserID) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetSuperuserTOTPSettings(ctx, superuserID)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.TOTPSettings{
		ID: r.ID, UserID: r.SuperuserID, SecretEncrypted: r.SecretEncrypted, Enabled: r.Enabled,
		VerifiedAt: r.VerifiedAt, RecoveryCodeHashes: r.RecoveryCodeHashes,
		RecoveryCodesUsed: int(r.RecoveryCodesUsed), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}, nil
}

func (s *Store) UpdateSuperuserTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	if !isID(t.UserID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateSuperuserTOTPSettings(ctx, db.UpdateSuperuserTOTPSettingsParams{
		SuperuserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled, VerifiedAt: t.VerifiedAt,
		RecoveryCodeHashes: nonNil(t.RecoveryCodeHashes), RecoveryCodesUsed: int32(t.RecoveryCodesUsed),
		UpdatedAt: t.UpdatedAt,
	}))
}

func (s *Store) DeleteSuperuserTOTPSettings(ctx context.Context, superuserID string) error {
	if !isID(superuserID) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteSuperuserTOTPSettings(ctx, superuserID))
}

func (s *Store) CreateSuperuserPendingTwoFactorSession(ctx context.Context, p *store.PendingTwoFactorSession) error {
	return mapErr(s.q(ctx).CreateSuperuserPendingTwoFactorSession(ctx, db.CreateSuperuserPendingTwoFactorSessionParams{
		ID: p.ID, SuperuserID: p.UserID, TokenHash: p.TokenHash, ExpiresAt: p.ExpiresAt, CreatedAt: p.CreatedAt,
	}))
}

func (s *Store) GetSuperuserPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	r, err := s.q(ctx).GetSuperuserPendingTwoFactorSessionByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.PendingTwoFactorSession{
		ID: r.ID, UserID: r.SuperuserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) DeleteSuperuserPendingTwoFactorSession(ctx context.Context, id string) error {
	if !isID(id) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteSuperuserPendingTwoFactorSession(ctx, id))
}
