package user

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/audit"
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

// MarkEmailVerified marks userID's address verified directly, without
// minting and redeeming a token. It is the trusted-caller counterpart to
// VerifyEmail, for the paths where the address is already proven and a
// round-trip through an email would be ceremony: a seeder provisioning demo
// or test accounts, a tokenised B2B invite the recipient just followed, or
// SSO/IdP provisioning that arrives pre-verified.
//
// Never call this from an unauthenticated, user-supplied path — it is
// exactly the check VerifyEmail exists to perform.
//
// It is idempotent: on an already-verified user it is a no-op and leaves
// EmailVerifiedAt at the original time. Any outstanding verification tokens
// for the user are deleted, so a link already in an inbox can't be redeemed
// afterwards.
func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.EmailVerified {
		now := time.Now()
		u.EmailVerified = true
		u.EmailVerifiedAt = &now
		u.UpdatedAt = now
		if err := s.stores.Users.UpdateUser(ctx, u); err != nil {
			return err
		}
	}
	return s.stores.EmailVerifications.DeleteUserEmailVerificationTokens(ctx, u.ID)
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
	if err := s.stores.EmailVerifications.MarkEmailVerificationTokenUsed(ctx, t.ID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserEmailVerified, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email})
	return nil
}
