package user

import (
	"context"
	"errors"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// LoginMethod names how a caller of IssueSession established who the user
// is. It is recorded in the audit trail, and decides two rules: see
// ProvesEmail and SatisfiesTwoFactor.
//
// The constants cover the methods authit ships. A host with a method of its
// own passes its own name; any non-empty value is accepted.
type LoginMethod string

const (
	// LoginMethodMagicLink is emaillogin.RedeemMagicLink. It proves the
	// address, so IssueSession marks it verified; it is one factor, so an
	// account with TOTP still owes its code.
	LoginMethodMagicLink LoginMethod = "magic_link"
	// LoginMethodSignInCode is emaillogin.RedeemSignInCode, and is treated
	// exactly as LoginMethodMagicLink.
	LoginMethodSignInCode LoginMethod = "sign_in_code"
	// LoginMethodPasskey is a passkey assertion with user verification:
	// possession of the authenticator plus the PIN or biometric it checked.
	// That is two factors, so IssueSession issues the session without
	// asking for TOTP.
	//
	// Pass it only when passkey.Result.UserVerified is true. A passkey
	// service configured to accept assertions without user verification
	// can produce one that is possession alone; pass a name of your own
	// for those (say "passkey_unverified"), and TOTP stays required.
	LoginMethodPasskey LoginMethod = "passkey"
	// LoginMethodOIDC is an oidc sign-in. One factor, as far as authit can
	// tell, so an account with TOTP still owes its code.
	LoginMethodOIDC LoginMethod = "oidc"
)

// ProvesEmail reports whether the method itself proved the user controls
// the account's address: a magic link or a sign-in code was delivered to it
// and came back. Under EmailVerificationRequired, IssueSession lets those
// methods through for an account still marked unverified -- the address was
// proven just now, by the sign-in -- and refuses every other method, as
// Authenticate does. IssueSession also marks the address verified for
// these methods, as MarkEmailVerified does.
func (m LoginMethod) ProvesEmail() bool {
	return m == LoginMethodMagicLink || m == LoginMethodSignInCode
}

// SatisfiesTwoFactor reports whether the method is two factors on its own,
// so that IssueSession does not ask an account with TOTP enabled for its
// code. Only LoginMethodPasskey is: see its documentation for the
// condition that holds on.
func (m LoginMethod) SatisfiesTwoFactor() bool {
	return m == LoginMethodPasskey
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
//     with ErrEmailNotVerified, unless method.ProvesEmail(). For those
//     methods an unverified address is marked verified, as
//     MarkEmailVerified does -- the sign-in just proved it -- in the
//     session's transaction when Stores.Tx is set. A later password login
//     then passes the verification gate too.
//   - Hooks.BeforeAuthenticate gates it, and Hooks.AfterAuthenticate runs
//     with the session, in one transaction when Stores.Tx is set.
//   - An account with two-factor enabled gets RequiresTwoFactor and a
//     PendingTwoFactorToken instead of tokens, exactly as from
//     Authenticate: finish with VerifyTwoFactorLogin. A second factor the
//     user turned on is not waived because the first one was not a
//     password -- except for LoginMethodPasskey, which is two factors
//     already (method.SatisfiesTwoFactor()) and gets the session directly.
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

	// The address was proven by this sign-in. Marked once, not on every
	// sign-in after: an already-verified account costs no write.
	verify := method.ProvesEmail() && !u.EmailVerified
	markVerified := func(ctx context.Context) error {
		if !verify {
			return nil
		}
		if err := s.MarkEmailVerified(ctx, u.ID); err != nil {
			return err
		}
		// MarkEmailVerified read and wrote its own copy; this one is what
		// the hook and the caller see.
		u, err = s.stores.Users.GetUserByID(ctx, u.ID)
		return err
	}

	twoFactorOwed := false
	if !method.SatisfiesTwoFactor() {
		totpSettings, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, u.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return AuthResult{}, err
		}
		twoFactorOwed = totpSettings != nil && totpSettings.Enabled
	}
	if twoFactorOwed {
		// The address is proven whether or not the second factor follows,
		// so it is marked here too, with the pending session.
		var pendingToken string
		if err := s.txIf(ctx, verify, func(ctx context.Context) error {
			if err := markVerified(ctx); err != nil {
				return err
			}
			var err error
			pendingToken, err = s.createPendingTwoFactorSession(ctx, u.ID)
			return err
		}); err != nil {
			return AuthResult{}, err
		}
		s.auditVerified(ctx, verify, u, method)
		return AuthResult{User: *u, RequiresTwoFactor: true, PendingTwoFactorToken: pendingToken}, nil
	}

	var tokens TokenPair
	if err := s.txIf(ctx, verify || s.cfg.Hooks.AfterAuthenticate != nil, func(ctx context.Context) error {
		if err := markVerified(ctx); err != nil {
			return err
		}
		var err error
		tokens, err = s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
		if err != nil {
			return err
		}
		return s.cfg.Hooks.afterAuthenticate(ctx, *u)
	}); err != nil {
		return AuthResult{}, err
	}
	s.auditVerified(ctx, verify, u, method)
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserLoginSucceeded, Result: audit.ResultSuccess,
		ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: meta(""),
	})
	return AuthResult{User: *u, Tokens: &tokens}, nil
}

// auditVerified records the address IssueSession marked verified, after the
// write committed.
func (s *Service) auditVerified(ctx context.Context, verified bool, u *store.User, method LoginMethod) {
	if !verified {
		return
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserEmailVerified, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email,
		Metadata: map[string]any{"method": string(method)},
	})
}
