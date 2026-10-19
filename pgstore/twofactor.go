package pgstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

func (s *Store) CreateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return mapErr(s.q(ctx).CreateTOTPSettings(ctx, db.CreateTOTPSettingsParams{
		ID: t.ID, UserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled,
		VerifiedAt: t.VerifiedAt, RecoveryCodeHashes: nonNil(t.RecoveryCodeHashes),
		RecoveryCodesUsed: int32(t.RecoveryCodesUsed), CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}))
}

func (s *Store) GetTOTPSettingsByUserID(ctx context.Context, userID string) (*store.TOTPSettings, error) {
	if !isID(userID) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetTOTPSettingsByUserID(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.TOTPSettings{
		ID: r.ID, UserID: r.UserID, SecretEncrypted: r.SecretEncrypted, Enabled: r.Enabled,
		VerifiedAt: r.VerifiedAt, RecoveryCodeHashes: r.RecoveryCodeHashes,
		RecoveryCodesUsed: int(r.RecoveryCodesUsed), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}, nil
}

func (s *Store) UpdateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	if !isID(t.UserID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateTOTPSettings(ctx, db.UpdateTOTPSettingsParams{
		UserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled, VerifiedAt: t.VerifiedAt,
		RecoveryCodeHashes: nonNil(t.RecoveryCodeHashes), RecoveryCodesUsed: int32(t.RecoveryCodesUsed),
		UpdatedAt: t.UpdatedAt,
	}))
}

func (s *Store) DeleteTOTPSettings(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteTOTPSettings(ctx, userID))
}

func (s *Store) CreatePendingTwoFactorSession(ctx context.Context, p *store.PendingTwoFactorSession) error {
	return mapErr(s.q(ctx).CreatePendingTwoFactorSession(ctx, db.CreatePendingTwoFactorSessionParams{
		ID: p.ID, UserID: p.UserID, TokenHash: p.TokenHash, ExpiresAt: p.ExpiresAt, CreatedAt: p.CreatedAt,
	}))
}

func (s *Store) GetPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	r, err := s.q(ctx).GetPendingTwoFactorSessionByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.PendingTwoFactorSession{
		ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) DeletePendingTwoFactorSession(ctx context.Context, id string) error {
	if !isID(id) {
		return nil
	}
	return mapErr(s.q(ctx).DeletePendingTwoFactorSession(ctx, id))
}

func (s *Store) RecordFailedLoginAttempt(ctx context.Context, a *store.FailedLoginAttempt) error {
	return mapErr(s.q(ctx).RecordFailedLoginAttempt(ctx, db.RecordFailedLoginAttemptParams{
		ID: a.ID, Email: a.Email, IpAddress: a.IPAddress, CreatedAt: a.CreatedAt,
	}))
}

func (s *Store) CountRecentFailedLoginAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	n, err := s.q(ctx).CountRecentFailedLoginAttempts(ctx, db.CountRecentFailedLoginAttemptsParams{
		Email: email, CreatedAt: since,
	})
	return int(n), mapErr(err)
}

func (s *Store) ClearFailedLoginAttempts(ctx context.Context, email string) error {
	return mapErr(s.q(ctx).ClearFailedLoginAttempts(ctx, email))
}

func (s *Store) LockAccount(ctx context.Context, userID string) error {
	return mapErr(s.q(ctx).LockAccount(ctx, userID))
}

func (s *Store) IsAccountLocked(ctx context.Context, userID string) (bool, error) {
	if !isID(userID) {
		return false, nil
	}
	locked, err := s.q(ctx).IsAccountLocked(ctx, userID)
	return locked, mapErr(err)
}

func (s *Store) UnlockAccount(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).UnlockAccount(ctx, userID))
}

// nonNil keeps a nil slice from binding as NULL into a NOT NULL array column.
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
