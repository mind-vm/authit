package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// ChangePassword updates an authenticated user's password after verifying
// their current one.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	u, err := sqlb.Query[store.User]().
		Where(store.UserCols.ID.Eq(userID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if !authitcrypto.CheckPassword(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	hash, err := authitcrypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = store.UpdateUser().
		SetPasswordHash(hash).
		SetUpdatedAt(time.Now()).
		Where(store.UserCols.ID.Eq(userID)).
		Stmt().Exec(ctx, s.db)
	return err
}

// RequestPasswordReset generates a reset token and emails it to the given
// address. It always succeeds regardless of whether the address is
// registered, so callers can return the same response either way and avoid
// leaking account existence.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	u, err := sqlb.Query[store.User]().
		Where(store.UserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return nil
		}
		return err
	}

	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return err
	}
	if err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		// Superseding the outstanding tokens and issuing the replacement are
		// one unit of work, so a failure cannot leave the user with none.
		if _, err := sqlb.DeleteRows[store.PasswordResetToken]().
			Where(store.PasswordResetTokenCols.UserID.Eq(u.ID)).
			Exec(ctx, tx); err != nil {
			return err
		}
		row := store.PasswordResetToken{
			UserID: u.ID, TokenHash: hash,
			ExpiresAt: time.Now().Add(s.cfg.PasswordResetTTL),
		}
		_, err := sqlb.InsertRows(&row).Exec(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	return s.emailer.SendPasswordReset(ctx, u.Email, raw)
}

// ValidatePasswordResetToken reports whether a reset token is still valid,
// without consuming it — used to give the UI an early error before the
// user types a new password.
func (s *Service) ValidatePasswordResetToken(ctx context.Context, rawToken string) error {
	t, err := sqlb.Query[store.PasswordResetToken]().
		Where(store.PasswordResetTokenCols.TokenHash.Eq(authitcrypto.HashToken(rawToken))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return ErrInvalidToken
		}
		return err
	}
	if t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return ErrInvalidToken
	}
	return nil
}

// ResetPassword consumes a password reset token and sets a new password.
// Every session for the user is revoked, forcing re-login everywhere.
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	hash, err := authitcrypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	// All four writes are one unit of work. A password changed without the
	// sessions being revoked is the case this exists to prevent: the whole
	// point of a reset is that whoever held the old credential is locked out.
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		t, err := sqlb.Query[store.PasswordResetToken]().
			Where(store.PasswordResetTokenCols.TokenHash.Eq(authitcrypto.HashToken(rawToken))).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
		if t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
			return ErrInvalidToken
		}

		now := time.Now()
		if _, err := store.UpdateUser().
			SetPasswordHash(hash).
			SetUpdatedAt(now).
			Where(store.UserCols.ID.Eq(t.UserID)).
			Stmt().Exec(ctx, tx); err != nil {
			return err
		}
		if _, err := store.UpdatePasswordResetToken().
			SetUsedAt(&now).
			Where(store.PasswordResetTokenCols.ID.Eq(t.ID)).
			Stmt().Exec(ctx, tx); err != nil {
			return err
		}
		_, err = store.UpdateRefreshToken().
			SetRevokedAt(&now).
			Where(
				store.RefreshTokenCols.UserID.Eq(t.UserID),
				store.RefreshTokenCols.RevokedAt.IsNull(),
			).
			Stmt().Exec(ctx, tx)
		return err
	})
}
