package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
)

// RequestEmailVerification generates a verification token for userID and
// emails it.
func (s *Service) RequestEmailVerification(ctx context.Context, userID string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	return s.sendEmailVerification(ctx, u)
}

// RequestEmailVerificationByEmail is the public, unauthenticated variant
// used for a "resend verification email" form. Like RequestPasswordReset,
// it always succeeds regardless of whether the address is registered or
// already verified, to avoid leaking account existence.
func (s *Service) RequestEmailVerificationByEmail(ctx context.Context, email string) error {
	u, err := s.stores.Users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if u.EmailVerified {
		return nil
	}
	return s.sendEmailVerification(ctx, u)
}

func (s *Service) sendEmailVerification(ctx context.Context, u *store.User) error {
	if err := s.stores.EmailVerifications.DeleteUserEmailVerificationTokens(ctx, u.ID); err != nil {
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
	if err := s.stores.EmailVerifications.CreateEmailVerificationToken(ctx, &store.EmailVerificationToken{
		ID: id, UserID: u.ID, TokenHash: hash, ExpiresAt: now.Add(s.cfg.EmailVerificationTTL), CreatedAt: now,
	}); err != nil {
		return err
	}
	return s.emailer.SendEmailVerification(ctx, u.Email, raw)
}

// VerifyEmail consumes a verification token and marks the user's email
// verified.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	t, err := s.stores.EmailVerifications.GetEmailVerificationTokenByHash(ctx, authitcrypto.HashToken(rawToken))
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
	now := time.Now()
	u.EmailVerified = true
	u.EmailVerifiedAt = &now
	u.UpdatedAt = now
	if err := s.stores.Users.UpdateUser(ctx, u); err != nil {
		return err
	}
	return s.stores.EmailVerifications.MarkEmailVerificationTokenUsed(ctx, t.ID)
}
