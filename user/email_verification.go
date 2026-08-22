package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// RequestEmailVerification generates a verification token for userID and
// emails it.
func (s *Service) RequestEmailVerification(ctx context.Context, userID string) error {
	u, err := sqlb.Query[store.User]().
		Where(store.UserCols.ID.Eq(userID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.sendEmailVerification(ctx, u)
}

// RequestEmailVerificationByEmail is the public, unauthenticated variant
// used for a "resend verification email" form. Like RequestPasswordReset,
// it always succeeds regardless of whether the address is registered or
// already verified, to avoid leaking account existence.
func (s *Service) RequestEmailVerificationByEmail(ctx context.Context, email string) error {
	u, err := sqlb.Query[store.User]().
		Where(store.UserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return nil
		}
		return err
	}
	if u.EmailVerified {
		return nil
	}
	return s.sendEmailVerification(ctx, u)
}

func (s *Service) sendEmailVerification(ctx context.Context, u store.User) error {
	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return err
	}
	// Replacing the outstanding tokens and creating the new one is one unit of
	// work, so a failure can't leave the user with no live token at all.
	if err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		if _, err := sqlb.DeleteRows[store.EmailVerificationToken]().
			Where(store.EmailVerificationTokenCols.UserID.Eq(u.ID)).
			Exec(ctx, tx); err != nil {
			return err
		}
		row := store.EmailVerificationToken{
			UserID: u.ID, TokenHash: hash,
			ExpiresAt: time.Now().Add(s.cfg.EmailVerificationTTL),
		}
		_, err := sqlb.InsertRows(&row).Exec(ctx, tx)
		return err
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
// It is idempotent: on an already-verified user it leaves EmailVerifiedAt at
// the original time. Any outstanding verification tokens for the user are
// deleted, so a link already in an inbox can't be redeemed afterwards.
func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		u, err := sqlb.Query[store.User]().
			Where(store.UserCols.ID.Eq(userID)).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		if !u.EmailVerified {
			now := time.Now()
			if _, err := store.UpdateUser().
				SetEmailVerified(true).
				SetEmailVerifiedAt(&now).
				SetUpdatedAt(now).
				Where(store.UserCols.ID.Eq(userID)).
				Stmt().Exec(ctx, tx); err != nil {
				return err
			}
		}
		_, err = sqlb.DeleteRows[store.EmailVerificationToken]().
			Where(store.EmailVerificationTokenCols.UserID.Eq(userID)).
			Exec(ctx, tx)
		return err
	})
}

// VerifyEmail consumes a verification token and marks the user's email
// verified.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		t, err := sqlb.Query[store.EmailVerificationToken]().
			Where(store.EmailVerificationTokenCols.TokenHash.Eq(authitcrypto.HashToken(rawToken))).
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
			SetEmailVerified(true).
			SetEmailVerifiedAt(&now).
			SetUpdatedAt(now).
			Where(store.UserCols.ID.Eq(t.UserID)).
			Stmt().Exec(ctx, tx); err != nil {
			return err
		}
		// Marking the token used and marking the address verified are one unit
		// of work: a token that was spent without verifying anything is a dead
		// link the user cannot retry.
		_, err = store.UpdateEmailVerificationToken().
			SetUsedAt(&now).
			Where(store.EmailVerificationTokenCols.ID.Eq(t.ID)).
			Stmt().Exec(ctx, tx)
		return err
	})
}
