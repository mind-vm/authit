package sqlitestore

import (
	"context"
	"fmt"
	"time"

	"github.com/mind-vm/authit/store"
)

// The user and operator planes keep TOTP settings and pending two-factor
// sessions in separate tables of one shape, told apart by the table and the
// column naming the owner. Both names are constants from this package.

const totpCols = `id, %s, secret_encrypted, enabled, verified_at, recovery_code_hashes, recovery_codes_used, created_at, updated_at`

func totpColsFor(owner string) string { return fmt.Sprintf(totpCols, owner) }

func scanTOTP(r scanner) (*store.TOTPSettings, error) {
	var t store.TOTPSettings
	err := r.Scan(&t.ID, &t.UserID, &t.SecretEncrypted, &t.Enabled, tmPtr{&t.VerifiedAt},
		strs{&t.RecoveryCodeHashes}, &t.RecoveryCodesUsed, tm{&t.CreatedAt}, tm{&t.UpdatedAt})
	return &t, err
}

func (s *Store) createTOTP(ctx context.Context, table, owner string, t *store.TOTPSettings) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	ownerID, err := ref(t.UserID)
	if err != nil {
		return err
	}
	t.UserID = ownerID
	codes, err := list(t.RecoveryCodeHashes)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO `+table+` (`+totpColsFor(owner)+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.SecretEncrypted, t.Enabled, tsPtr(t.VerifiedAt), codes, t.RecoveryCodesUsed,
		ts(t.CreatedAt), ts(t.UpdatedAt))
}

func (s *Store) getTOTP(ctx context.Context, table, owner, ownerID string) (*store.TOTPSettings, error) {
	ownerID, ok := canon(ownerID)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanTOTP, `SELECT `+totpColsFor(owner)+` FROM `+table+` WHERE `+owner+` = ?`, ownerID)
}

func (s *Store) updateTOTP(ctx context.Context, table, owner string, t *store.TOTPSettings) error {
	ownerID, ok := canon(t.UserID)
	if !ok {
		return store.ErrNotFound
	}
	codes, err := list(t.RecoveryCodeHashes)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE `+table+`
		SET secret_encrypted = ?, enabled = ?, verified_at = ?, recovery_code_hashes = ?,
		    recovery_codes_used = ?, updated_at = ?
		WHERE `+owner+` = ?`,
		t.SecretEncrypted, t.Enabled, tsPtr(t.VerifiedAt), codes, t.RecoveryCodesUsed, ts(t.UpdatedAt), ownerID)
}

func (s *Store) deleteTOTP(ctx context.Context, table, owner, ownerID string) error {
	ownerID, ok := canon(ownerID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM `+table+` WHERE `+owner+` = ?`, ownerID)
}

const pendingCols = `id, %s, token_hash, expires_at, created_at`

func scanPending(r scanner) (*store.PendingTwoFactorSession, error) {
	var p store.PendingTwoFactorSession
	err := r.Scan(&p.ID, &p.UserID, &p.TokenHash, tm{&p.ExpiresAt}, tm{&p.CreatedAt})
	return &p, err
}

func (s *Store) createPending(ctx context.Context, table, owner string, p *store.PendingTwoFactorSession) error {
	if err := newID(&p.ID); err != nil {
		return err
	}
	ownerID, err := ref(p.UserID)
	if err != nil {
		return err
	}
	p.UserID = ownerID
	return s.exec(ctx, `INSERT INTO `+table+` (`+fmt.Sprintf(pendingCols, owner)+`) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.TokenHash, ts(p.ExpiresAt), ts(p.CreatedAt))
}

func (s *Store) getPending(ctx context.Context, table, owner, hash string) (*store.PendingTwoFactorSession, error) {
	return one(ctx, s.q(ctx), scanPending,
		`SELECT `+fmt.Sprintf(pendingCols, owner)+` FROM `+table+` WHERE token_hash = ?`, hash)
}

func (s *Store) deletePending(ctx context.Context, table, id string) error {
	id, ok := canon(id)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM `+table+` WHERE id = ?`, id)
}

func (s *Store) CreateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.createTOTP(ctx, "auth_totp_settings", "user_id", t)
}

func (s *Store) GetTOTPSettingsByUserID(ctx context.Context, userID string) (*store.TOTPSettings, error) {
	return s.getTOTP(ctx, "auth_totp_settings", "user_id", userID)
}

func (s *Store) UpdateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return s.updateTOTP(ctx, "auth_totp_settings", "user_id", t)
}

func (s *Store) DeleteTOTPSettings(ctx context.Context, userID string) error {
	return s.deleteTOTP(ctx, "auth_totp_settings", "user_id", userID)
}

func (s *Store) CreatePendingTwoFactorSession(ctx context.Context, p *store.PendingTwoFactorSession) error {
	return s.createPending(ctx, "auth_pending_two_factor_sessions", "user_id", p)
}

func (s *Store) GetPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	return s.getPending(ctx, "auth_pending_two_factor_sessions", "user_id", hash)
}

func (s *Store) DeletePendingTwoFactorSession(ctx context.Context, id string) error {
	return s.deletePending(ctx, "auth_pending_two_factor_sessions", id)
}

func (s *Store) RecordFailedLoginAttempt(ctx context.Context, a *store.FailedLoginAttempt) error {
	if err := newID(&a.ID); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_failed_login_attempts (id, email, ip_address, created_at) VALUES (?, ?, ?, ?)`,
		a.ID, a.Email, a.IPAddress, ts(a.CreatedAt))
}

func (s *Store) CountRecentFailedLoginAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	var n int
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT count(*) FROM auth_failed_login_attempts WHERE email = ? AND created_at > ?`, email, ts(since)).Scan(&n)
	return n, mapErr(err)
}

func (s *Store) ClearFailedLoginAttempts(ctx context.Context, email string) error {
	return s.exec(ctx, `DELETE FROM auth_failed_login_attempts WHERE email = ?`, email)
}

func (s *Store) LockAccount(ctx context.Context, userID string) error {
	userID, err := ref(userID)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_account_locks (user_id, locked_at) VALUES (?, ?)
		ON CONFLICT (user_id) DO NOTHING`, userID, now())
}

func (s *Store) IsAccountLocked(ctx context.Context, userID string) (bool, error) {
	userID, ok := canon(userID)
	if !ok {
		return false, nil
	}
	var locked bool
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth_account_locks WHERE user_id = ?)`, userID).Scan(&locked)
	return locked, mapErr(err)
}

func (s *Store) UnlockAccount(ctx context.Context, userID string) error {
	userID, ok := canon(userID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM auth_account_locks WHERE user_id = ?`, userID)
}
