package user

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// ChangePassword updates an authenticated user's password after verifying
// their current one.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !s.cfg.PasswordHasher.Verify(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	if err := s.cfg.PasswordValidator(ctx, u.Email, newPassword); err != nil {
		return err
	}
	hash, err := s.cfg.PasswordHasher.Hash(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now()
	if err := s.stores.Users.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserPasswordChanged, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email})
	return nil
}

// RequestPasswordReset generates a reset token and emails it to the given
// address. It always succeeds regardless of whether the address is
// registered, so callers can return the same response either way and avoid
// leaking account existence.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	u, err := s.stores.Users.GetUserByEmail(ctx, store.NormalizeEmail(email))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}

	if err := s.stores.PasswordResets.DeleteUserPasswordResetTokens(ctx, u.ID); err != nil {
		return err
	}
	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return err
	}
	now := time.Now()
	if err := s.stores.PasswordResets.CreatePasswordResetToken(ctx, &store.PasswordResetToken{
		ID: id, UserID: u.ID, TokenHash: hash, ExpiresAt: now.Add(s.cfg.PasswordResetTTL), CreatedAt: now,
	}); err != nil {
		return err
	}
	return s.emailer.SendPasswordReset(ctx, u.Email, raw)
}

// ValidatePasswordResetToken reports whether a reset token is still valid,
// without consuming it — used to give the UI an early error before the
// user types a new password.
func (s *Service) ValidatePasswordResetToken(ctx context.Context, rawToken string) error {
	t, err := s.stores.PasswordResets.GetPasswordResetTokenByHash(ctx, authitcrypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
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
// Every other session for the user is revoked, forcing re-login everywhere
// else.
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	t, err := s.stores.PasswordResets.GetPasswordResetTokenByHash(ctx, authitcrypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		return err
	}
	if t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return ErrInvalidToken
	}
	u, err := s.stores.Users.GetUserByID(ctx, t.UserID)
	if err != nil {
		return err
	}
	if err := s.cfg.PasswordValidator(ctx, u.Email, newPassword); err != nil {
		return err
	}
	hash, err := s.cfg.PasswordHasher.Hash(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now()
	if err := s.stores.Users.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := s.stores.PasswordResets.MarkPasswordResetTokenUsed(ctx, t.ID); err != nil {
		return err
	}
	if err := s.stores.RefreshTokens.RevokeAllUserRefreshTokens(ctx, u.ID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserPasswordReset, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email})
	return nil
}
