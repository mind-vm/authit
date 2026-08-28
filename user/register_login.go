package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// Register creates a new user with the given email/password. The password
// is hashed before storage; the plaintext never leaves this call.
func (s *Service) Register(ctx context.Context, email, password string) (store.User, error) {
	email = store.NormalizeEmail(email)
	if err := s.cfg.PasswordValidator(ctx, email, password); err != nil {
		return store.User{}, err
	}
	if err := s.cfg.Hooks.beforeRegister(ctx, email); err != nil {
		return store.User{}, err
	}
	if _, err := s.stores.Users.GetUserByEmail(ctx, email); err == nil {
		return store.User{}, ErrEmailTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	hash, err := s.cfg.PasswordHasher.Hash(password)
	if err != nil {
		return store.User{}, err
	}

	id, err := authitcrypto.NewID()
	if err != nil {
		return store.User{}, err
	}

	now := time.Now()
	u := &store.User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	// The insert and the hook share a transaction when both a TxRunner and
	// an AfterRegister hook are configured, so a host that provisions
	// something there can refuse and leave no account behind. With no
	// hook, this is a single insert and needs no transaction.
	if err := s.txIf(ctx, s.cfg.Hooks.AfterRegister != nil, func(ctx context.Context) error {
		if err := s.stores.Users.CreateUser(ctx, u); err != nil {
			return err
		}
		return s.cfg.Hooks.afterRegister(ctx, *u)
	}); err != nil {
		return store.User{}, err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserRegistered, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email})
	return *u, nil
}

// Authenticate verifies email/password and, if the account has no 2FA
// enabled, issues a token pair. If 2FA is enabled, it returns a pending
// two-factor token instead — call VerifyTwoFactorLogin to complete login.
//
// Under the default Config.EmailVerification (EmailVerificationRequired) an
// account whose address is unverified is refused with ErrEmailNotVerified;
// see EmailVerificationPolicy for when to relax that.
func (s *Service) Authenticate(ctx context.Context, email, password, userAgent, ipAddress string) (AuthResult, error) {
	// Normalised once, here, so that the account lookup and the
	// failed-login counter -- which is keyed by email -- agree. If they
	// disagreed, varying the case would reset the throttle.
	email = store.NormalizeEmail(email)

	// Consulted before anything expensive happens. The lockout below is
	// account-scoped and only bites after several failures; this bites
	// first and is scoped to the source address too, which is what keeps
	// an attacker from making the server run Argon2id thousands of times.
	if err := s.limit(ctx, "login:ip:"+ipAddress, "login:email:"+email); err != nil {
		s.auditRateLimited(ctx, audit.EventUserLoginFailed, "", email, userAgent, ipAddress)
		return AuthResult{}, err
	}

	locked, u, err := s.checkLockoutAndFetchUser(ctx, email)
	if err != nil {
		return AuthResult{}, err
	}
	if locked {
		// u may be nil here: the temporary lockout is keyed by email and
		// is deliberately evaluated before the account is known to exist,
		// so that an unknown address and a locked one behave identically.
		actorID := ""
		if u != nil {
			actorID = u.ID
		}
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginLocked, Result: audit.ResultDenied,
			ActorID: actorID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
		})
		return AuthResult{}, ErrAccountLocked
	}
	// After the rate limit and the lockout, so a hook cannot be used to
	// bypass either, and before the hash comparison, so refusing here
	// costs no KDF work.
	if err := s.cfg.Hooks.beforeAuthenticate(ctx, email); err != nil {
		return AuthResult{}, err
	}

	if u == nil || !s.cfg.PasswordHasher.Verify(password, u.PasswordHash) {
		s.recordFailedLogin(ctx, email, ipAddress)
		actorID := ""
		if u != nil {
			actorID = u.ID
		}
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginFailed, Result: audit.ResultFailure,
			ActorID: actorID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
		})
		return AuthResult{}, ErrInvalidCredentials
	}
	// The password is correct, so this is the one moment the plaintext is
	// available to upgrade a hash written by an older or weaker algorithm.
	// Done before the email-verification and 2FA gates deliberately: those
	// can reject the login, but the password itself was still proven.
	s.rehashIfNeeded(ctx, u, password)

	if s.cfg.EmailVerification == EmailVerificationRequired && !u.EmailVerified {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginFailed, Result: audit.ResultDenied,
			ActorID: u.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: map[string]any{"reason": "email_not_verified"},
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

	// The failed-attempt counter is cleared here, and in
	// VerifyTwoFactorLogin -- but NOT after the password step alone. A
	// correct password that still owes a second factor must not reset the
	// counter, or an attacker holding the password would get unlimited
	// guesses at the second factor.
	_ = s.stores.Lockouts.ClearFailedLoginAttempts(ctx, email)

	// This is a completed login -- no second factor is owed -- so the
	// session and the hook go in together. AfterAuthenticate is reached
	// here and in VerifyTwoFactorLogin, and nowhere else: a login that
	// stopped at the password step has not succeeded.
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
	})
	return AuthResult{User: *u, Tokens: &tokens}, nil
}

// limit consults the configured rate limiter for each key in turn,
// skipping any whose value ends in an empty component -- an absent IP
// address must not collapse every caller into one shared bucket.
//
// Every key is consulted even though the first refusal returns, so budget
// is charged consistently: an attacker cannot exhaust one dimension and
// leave another untouched by racing.
func (s *Service) limit(ctx context.Context, keys ...string) error {
	var refusal error
	for _, key := range keys {
		if strings.HasSuffix(key, ":") {
			continue
		}
		if err := s.cfg.RateLimiter.Allow(ctx, key); err != nil {
			if !errors.Is(err, ratelimit.ErrRateLimited) {
				// The limiter itself failed. Fail closed rather than
				// silently removing the control, and report it as its own
				// error so a host can distinguish it from a refusal.
				return err
			}
			if refusal == nil {
				refusal = err
			}
		}
	}
	return refusal
}

// auditRateLimited records a refusal. It is a denial, not a credential
// failure, so it is logged as one -- an operator reading the trail should
// be able to tell "wrong password" from "too many attempts".
func (s *Service) auditRateLimited(ctx context.Context, t audit.EventType, actorID, email, userAgent, ipAddress string) {
	s.audit.Log(ctx, audit.Event{
		Type: t, Result: audit.ResultDenied, ActorID: actorID, Email: email,
		UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: map[string]any{"reason": "rate_limited"},
	})
}

// throttled reports whether email is currently in temporary lockout:
// MaxFailedLoginAttempts or more failures inside FailedLoginWindow.
//
// The lockout is *derived* from the attempts table rather than stored as a
// flag, which is what makes it self-healing -- it lifts on its own as the
// recorded attempts age out of the window, with nothing to unlock and no
// expiry column to keep. store.LockoutStore's LockAccount/UnlockAccount are
// a separate, operator-driven concern and are no longer reached by a failed
// login; see their documentation.
//
// It is keyed by email, not user ID, precisely so it can be evaluated
// before the account is known to exist.
func (s *Service) throttled(ctx context.Context, email string) (bool, error) {
	count, err := s.stores.Lockouts.CountRecentFailedLoginAttempts(ctx, email, time.Now().Add(-s.cfg.FailedLoginWindow))
	if err != nil {
		return false, err
	}
	return count >= s.cfg.MaxFailedLoginAttempts, nil
}

// checkLockoutAndFetchUser looks up the user without leaking, via error
// shape or timing, whether the email exists: it checks the temporary
// lockout by email *before* the user lookup, so an unknown address takes
// the same path as a known one, and returns a nil user (not an error) if
// the account doesn't exist.
func (s *Service) checkLockoutAndFetchUser(ctx context.Context, email string) (locked bool, u *store.User, err error) {
	locked, err = s.throttled(ctx, email)
	if err != nil {
		return false, nil, err
	}

	u, err = s.stores.Users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return locked, nil, nil
		}
		return false, nil, err
	}
	if locked {
		return true, u, nil
	}
	// Not throttled, but an operator may still have locked the account
	// administratively.
	locked, err = s.stores.Lockouts.IsAccountLocked(ctx, u.ID)
	if err != nil {
		return false, nil, err
	}
	return locked, u, nil
}

// recordFailedLogin records one failed attempt against email. It no longer
// locks the account: a permanent, remotely-triggerable lock let anyone who
// knew an address disable it with a handful of wrong passwords. The
// temporary lockout that replaces it is computed by throttled.
func (s *Service) recordFailedLogin(ctx context.Context, email, ipAddress string) {
	id, err := authitcrypto.NewID()
	if err != nil {
		return
	}
	_ = s.stores.Lockouts.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{
		ID: id, Email: email, IPAddress: ipAddress, CreatedAt: time.Now(),
	})
}

// revokeFamilyOnReuse handles a replayed refresh token: it revokes every
// refresh token the principal holds and records the event.
//
// The caller still returns ErrInvalidToken, the same error a garbage token
// gets. Reporting reuse distinctly would tell an attacker holding a stolen
// token that it was genuine and had already been spent, which is precisely
// the thing worth not confirming.
//
// Revocation is best-effort in the sense that its failure is recorded and
// does not change the returned error -- the request is being refused
// either way.
func (s *Service) revokeFamilyOnReuse(ctx context.Context, t *store.RefreshToken, userAgent, ipAddress string) {
	result := audit.ResultSuccess
	if err := s.stores.RefreshTokens.RevokeAllUserRefreshTokens(ctx, t.UserID); err != nil {
		result = audit.ResultFailure
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserTokenReuse, Result: result, ActorID: t.UserID,
		UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: map[string]any{"refresh_token_id": t.ID},
	})
}

// rehashIfNeeded re-hashes u's password with the configured hasher when the
// stored hash is weaker than current settings, so a corpus migrates itself
// as users log in. Best-effort: a failure here must never fail a login that
// has otherwise succeeded, since the stored hash remains valid either way.
func (s *Service) rehashIfNeeded(ctx context.Context, u *store.User, password string) {
	if !s.cfg.PasswordHasher.NeedsRehash(u.PasswordHash) {
		return
	}
	hash, err := s.cfg.PasswordHasher.Hash(password)
	if err != nil {
		return
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now()
	_ = s.stores.Users.UpdateUser(ctx, u)
}

// Refresh exchanges a valid, unrevoked refresh token for a new token pair,
// rotating the refresh token (the old one is revoked).
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (TokenPair, error) {
	hash := authitcrypto.HashToken(refreshToken)
	t, err := s.stores.RefreshTokens.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	if time.Now().After(t.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	if t.RevokedAt != nil {
		// A revoked but unexpired token was just presented. Refresh
		// rotates -- it revokes the token it consumes -- so the legitimate
		// holder never has a reason to send this one again. Somebody has a
		// copy of a token somebody else already spent, and there is no way
		// to tell from here which of the two is the attacker. Revoking the
		// whole family ends both sessions and forces a fresh login, which
		// only the party who knows the password can complete.
		//
		// This also fires when a token revoked by Logout is replayed, which
		// is harmless (that session is already over) but will show up in
		// the audit trail -- it is worth knowing about either way.
		s.revokeFamilyOnReuse(ctx, t, userAgent, ipAddress)
		return TokenPair{}, ErrInvalidToken
	}
	u, err := s.stores.Users.GetUserByID(ctx, t.UserID)
	if err != nil {
		return TokenPair{}, err
	}

	// Rotation is two writes -- revoke the old, create the new -- and a
	// crash between them logs the user out of a session they were in the
	// middle of renewing. Note that the reuse handling above is
	// deliberately outside this: it must commit even though the call goes
	// on to return an error, and rolling it back would undo the revocation
	// that is the entire response to a stolen token.
	var tokens TokenPair
	err = store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
			return err
		}
		var err error
		tokens, err = s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}

	// Audit outside the transaction: a TxRunner is permitted to retry fn,
	// and an event recorded from inside would then be recorded twice --
	// or, on rollback, recorded for something that never happened.
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserTokenRefreshed, Result: audit.ResultSuccess,
		ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
	})
	return tokens, nil
}

// Logout revokes a single refresh token. It is idempotent: revoking an
// already-revoked or unknown token is not an error.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := authitcrypto.HashToken(refreshToken)
	t, err := s.stores.RefreshTokens.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserLogout, Result: audit.ResultSuccess, ActorID: t.UserID})
	return nil
}

func (s *Service) issueTokenPair(ctx context.Context, userID, email, userAgent, ipAddress string) (TokenPair, error) {
	rawRefresh, refreshHash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := &store.RefreshToken{
		ID:        id,
		UserID:    userID,
		TokenHash: refreshHash,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		UserAgent: userAgent,
		IPAddress: ipAddress,
		CreatedAt: now,
	}
	if err := s.stores.RefreshTokens.CreateRefreshToken(ctx, rt); err != nil {
		return TokenPair{}, err
	}

	expiresAt := now.Add(s.cfg.AccessTokenTTL)
	access, err := s.signer.Generate(newAccessClaims(userID, email, expiresAt))
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: rawRefresh, ExpiresAt: expiresAt}, nil
}
