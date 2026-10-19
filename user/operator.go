package user

import (
	"context"
	"errors"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// What an operator does to someone else's account, for the support cases a
// person cannot solve alone: locked out, lost their authenticator, signed in
// somewhere they should not be. Each takes the operator's id so the host's
// trail names who did it, and none needs anything from the account holder.

// AccountState is what an operator sees of one account.
type AccountState struct {
	Email         string
	EmailVerified bool
	// Locked is an explicit lock (store.LockoutStore.LockAccount).
	Locked bool
	// Throttled is the temporary lockout derived from recent failures.
	Throttled bool
	TwoFactor bool
}

// AccountState reports userID's state. An id with no account is
// store.ErrNotFound.
func (s *Service) AccountState(ctx context.Context, userID string) (AccountState, error) {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return AccountState{}, err
	}
	locked, err := s.stores.Lockouts.IsAccountLocked(ctx, u.ID)
	if err != nil {
		return AccountState{}, err
	}
	throttled, err := s.throttled(ctx, u.Email)
	if err != nil {
		return AccountState{}, err
	}
	twoFactor, err := s.TwoFactorStatus(ctx, u.ID)
	if err != nil {
		return AccountState{}, err
	}
	return AccountState{
		Email: u.Email, EmailVerified: u.EmailVerified, Locked: locked, Throttled: throttled,
		TwoFactor: twoFactor.Enabled,
	}, nil
}

// Unlock lifts both kinds of lockout: the explicit lock and the failure
// count the temporary one is derived from.
func (s *Service) Unlock(ctx context.Context, operatorID, userID string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.stores.Lockouts.UnlockAccount(ctx, u.ID); err != nil {
		return err
	}
	if err := s.stores.Lockouts.ClearFailedLoginAttempts(ctx, u.Email); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserUnlocked, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: u.ID, Email: u.Email,
	})
	return nil
}

// ResetTwoFactor removes the account's second factor without a code, for
// someone who lost both the app and the backup codes. The next sign-in is
// by password alone, so pair it with RevokeAllSessions when the account may
// be compromised.
func (s *Service) ResetTwoFactor(ctx context.Context, operatorID, userID string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if _, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, u.ID); errors.Is(err, store.ErrNotFound) {
		return ErrTwoFactorNotEnabled
	} else if err != nil {
		return err
	}
	if err := s.stores.TOTP.DeleteTOTPSettings(ctx, u.ID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserTwoFactorDisabled, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: u.ID, Email: u.Email,
		Metadata: map[string]any{"by": "operator"},
	})
	return nil
}

// RevokeAllSessions ends every session the account has and reports how
// many. Access tokens already issued live out their TTL.
func (s *Service) RevokeAllSessions(ctx context.Context, operatorID, userID string) (int, error) {
	tokens, err := s.stores.RefreshTokens.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return 0, err
	}
	for _, t := range tokens {
		if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
			return 0, err
		}
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserSessionRevoked, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: userID,
		Metadata: map[string]any{"by": "operator", "count": len(tokens)},
	})
	return len(tokens), nil
}

// SendPasswordReset mails the account holder a reset link through the
// host's EmailSender, as if they had asked. The operator never sees the
// link, so a reset never passes through anyone but the owner of the inbox.
func (s *Service) SendPasswordReset(ctx context.Context, userID string) error {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	return s.RequestPasswordReset(ctx, u.Email)
}
