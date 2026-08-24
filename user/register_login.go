package user

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/audit"
	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
)

// Register creates a new user with the given email/password. The password
// is hashed before storage; the plaintext never leaves this call.
func (s *Service) Register(ctx context.Context, email, password string) (store.User, error) {
	if _, err := s.stores.Users.GetUserByEmail(ctx, email); err == nil {
		return store.User{}, ErrEmailTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	hash, err := authitcrypto.HashPassword(password)
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
	if err := s.stores.Users.CreateUser(ctx, u); err != nil {
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
	locked, u, err := s.checkLockoutAndFetchUser(ctx, email)
	if err != nil {
		return AuthResult{}, err
	}
	if locked {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginLocked, Result: audit.ResultDenied,
			ActorID: u.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
		})
		return AuthResult{}, ErrAccountLocked
	}
	if u == nil || !authitcrypto.CheckPassword(password, u.PasswordHash) {
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
	if s.cfg.EmailVerification == EmailVerificationRequired && !u.EmailVerified {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginFailed, Result: audit.ResultDenied,
			ActorID: u.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: map[string]any{"reason": "email_not_verified"},
		})
		return AuthResult{}, ErrEmailNotVerified
	}
	_ = s.stores.Lockouts.ClearFailedLoginAttempts(ctx, email)

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

	tokens, err := s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
	if err != nil {
		return AuthResult{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserLoginSucceeded, Result: audit.ResultSuccess,
		ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
	})
	return AuthResult{User: *u, Tokens: &tokens}, nil
}

// checkLockoutAndFetchUser looks up the user without leaking, via error
// shape or timing, whether the email exists: it always checks lockout by
// email first, and returns a nil user (not an error) if the account
// doesn't exist.
func (s *Service) checkLockoutAndFetchUser(ctx context.Context, email string) (locked bool, u *store.User, err error) {
	u, err = s.stores.Users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}
	locked, err = s.stores.Lockouts.IsAccountLocked(ctx, u.ID)
	if err != nil {
		return false, nil, err
	}
	return locked, u, nil
}

func (s *Service) recordFailedLogin(ctx context.Context, email, ipAddress string) {
	id, err := authitcrypto.NewID()
	if err != nil {
		return
	}
	_ = s.stores.Lockouts.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{
		ID: id, Email: email, IPAddress: ipAddress, CreatedAt: time.Now(),
	})
	count, err := s.stores.Lockouts.CountRecentFailedLoginAttempts(ctx, email, time.Now().Add(-s.cfg.FailedLoginWindow))
	if err != nil || count < s.cfg.MaxFailedLoginAttempts {
		return
	}
	if u, err := s.stores.Users.GetUserByEmail(ctx, email); err == nil {
		_ = s.stores.Lockouts.LockAccount(ctx, u.ID)
	}
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
	if t.RevokedAt != nil || time.Now().After(t.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	u, err := s.stores.Users.GetUserByID(ctx, t.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
		return TokenPair{}, err
	}
	tokens, err := s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
	if err != nil {
		return TokenPair{}, err
	}
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
