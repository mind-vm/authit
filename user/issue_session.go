package user

import (
	"context"
	"errors"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// LoginMethod names how a caller of IssueSession established who the user
// is. It is recorded in the audit trail, and decides one rule: see
// ProvesEmail.
//
// The constants cover the methods authit ships. A host with a method of its
// own passes its own name; any non-empty value is accepted.
type LoginMethod string

const (
	// LoginMethodMagicLink is emaillogin.RedeemMagicLink.
	LoginMethodMagicLink LoginMethod = "magic_link"
	// LoginMethodSignInCode is emaillogin.RedeemSignInCode.
	LoginMethodSignInCode LoginMethod = "sign_in_code"
	// LoginMethodPasskey is a passkey assertion.
	LoginMethodPasskey LoginMethod = "passkey"
	// LoginMethodOIDC is an oidc sign-in.
	LoginMethodOIDC LoginMethod = "oidc"
)

// ProvesEmail reports whether the method itself proved the user controls
// the account's address: a magic link or a sign-in code was delivered to it
// and came back. Under EmailVerificationRequired, IssueSession lets those
// methods through for an account still marked unverified -- the address was
// proven just now, by the sign-in -- and refuses every other method, as
// Authenticate does.
func (m LoginMethod) ProvesEmail() bool {
	return m == LoginMethodMagicLink || m == LoginMethodSignInCode
}

// errLoginMethodRequired is a programming error, so it is not a sentinel.
var errLoginMethodRequired = errors.New("authit/user: IssueSession needs the LoginMethod that verified the user")

// IssueSession signs in a user whose identity something else has already
// verified -- emaillogin, passkey, oidc, or a method of the host's own --
// and returns what Authenticate returns after a correct password.
//
// emaillogin, passkey and oidc each answer "who is this" and stop there.
// This is the other half, and it puts those sign-ins through the same
// session model a password login gets, rather than each host minting
// something of its own:
//
//   - The session follows Config.SessionMode: an access token and a
//     refresh token in SessionModeJWT, one opaque session token in
//     SessionModeOpaque. Either way it is a row ListSessions shows and
//     RevokeSession ends.
//   - An account an operator has locked (LockoutStore.LockAccount) is
//     refused with ErrAccountLocked.
//   - Under EmailVerificationRequired an unverified account is refused
//     with ErrEmailNotVerified, unless method.ProvesEmail().
//   - Hooks.BeforeAuthenticate gates it, and Hooks.AfterAuthenticate runs
//     with the session, in one transaction when Stores.Tx is set.
//   - An account with two-factor enabled gets RequiresTwoFactor and a
//     PendingTwoFactorToken instead of tokens, exactly as from
//     Authenticate: finish with VerifyTwoFactorLogin. A second factor the
//     user turned on is not waived because the first one was not a
//     password.
//   - The outcome is audited as a login, with the method in the event's
//     metadata under "method".
//
// What it does not do is verify anything. userID is taken as proven: pass
// the id the identity package returned, never one from the request.
//
// The temporary lockout that failed passwords build up is not consulted.
// It throttles password guessing, and refusing a passkey because someone
// else has been guessing the password would hand that someone a way to
// lock the owner out.
//
// An unknown userID is ErrInvalidCredentials. method must not be empty.
func (s *Service) IssueSession(ctx context.Context, userID string, method LoginMethod, userAgent, ipAddress string) (AuthResult, error) {
	if method == "" {
		return AuthResult{}, errLoginMethodRequired
	}
	// A fresh map per event: a Logger may keep the one it is given.
	meta := func(reason string) map[string]any {
		m := map[string]any{"method": string(method)}
		if reason != "" {
			m["reason"] = reason
		}
		return m
	}

	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The identity resolved to an account that is gone -- deleted
			// between the ceremony and now. Refused as a login would be.
			s.audit.Log(ctx, audit.Event{
				Type: audit.EventUserLoginFailed, Result: audit.ResultFailure,
				ActorID: userID, UserAgent: userAgent, IPAddress: ipAddress,
				Metadata: meta("unknown_user"),
			})
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, err
	}

	locked, err := s.stores.Lockouts.IsAccountLocked(ctx, u.ID)
	if err != nil {
		return AuthResult{}, err
	}
	if locked {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginLocked, Result: audit.ResultDenied,
			ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: meta(""),
		})
		return AuthResult{}, ErrAccountLocked
	}
	if err := s.cfg.Hooks.beforeAuthenticate(ctx, u.Email); err != nil {
		return AuthResult{}, err
	}
	if s.cfg.EmailVerification == EmailVerificationRequired && !u.EmailVerified && !method.ProvesEmail() {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginFailed, Result: audit.ResultDenied,
			ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: meta("email_not_verified"),
		})
		return AuthResult{}, ErrEmailNotVerified
	}

	totpSettings, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, u.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return AuthResult{}, err
	}
	if totpSettings != nil && totpSettings.Enabled {
		pendingToken, err := s.createPendingTwoFactorSession(ctx, u.ID)
		if err != nil {
			return AuthResult{}, err
		}
		return AuthResult{User: *u, RequiresTwoFactor: true, PendingTwoFactorToken: pendingToken}, nil
	}

	var tokens TokenPair
	if err := s.txIf(ctx, s.cfg.Hooks.AfterAuthenticate != nil, func(ctx context.Context) error {
		var err error
		tokens, err = s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
		if err != nil {
			return err
		}
		return s.cfg.Hooks.afterAuthenticate(ctx, *u)
	}); err != nil {
		return AuthResult{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserLoginSucceeded, Result: audit.ResultSuccess,
		ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: meta(""),
	})
	return AuthResult{User: *u, Tokens: &tokens}, nil
}
