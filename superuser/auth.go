package superuser

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// Authenticate verifies email/password against the superuser table and
// issues a token pair scoped to this plane's audience.
func (s *Service) Authenticate(ctx context.Context, email, password, userAgent, ipAddress string) (TokenPair, error) {
	su, err := s.stores.Superusers.GetSuperuserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.recordFailedLogin(ctx, email)
			s.audit.Log(ctx, audit.Event{
				Type: audit.EventSuperuserLoginFailed, Result: audit.ResultFailure,
				Email: email, UserAgent: userAgent, IPAddress: ipAddress,
			})
			return TokenPair{}, ErrInvalidCredentials
		}
		return TokenPair{}, err
	}
	if s.stores.Lockouts != nil {
		locked, err := s.stores.Lockouts.IsAccountLocked(ctx, su.ID)
		if err != nil {
			return TokenPair{}, err
		}
		if locked {
			s.audit.Log(ctx, audit.Event{
				Type: audit.EventSuperuserLoginLocked, Result: audit.ResultDenied,
				ActorID: su.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
			})
			return TokenPair{}, ErrAccountLocked
		}
	}
	if !authitcrypto.CheckPassword(password, su.PasswordHash) {
		s.recordFailedLogin(ctx, email)
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventSuperuserLoginFailed, Result: audit.ResultFailure,
			ActorID: su.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
		})
		return TokenPair{}, ErrInvalidCredentials
	}
	if !su.IsActive {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventSuperuserLoginFailed, Result: audit.ResultDenied,
			ActorID: su.ID, Email: email, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: map[string]any{"reason": "inactive"},
		})
		return TokenPair{}, ErrInactive
	}
	if s.stores.Lockouts != nil {
		_ = s.stores.Lockouts.ClearFailedLoginAttempts(ctx, email)
	}

	now := time.Now()
	su.LastLoginAt = &now
	_ = s.stores.Superusers.UpdateSuperuser(ctx, su)

	tokens, err := s.issueTokenPair(ctx, su.ID, su.Email, userAgent, ipAddress)
	if err != nil {
		return TokenPair{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserLoginSucceeded, Result: audit.ResultSuccess,
		ActorID: su.ID, Email: su.Email, UserAgent: userAgent, IPAddress: ipAddress,
	})
	return tokens, nil
}

func (s *Service) recordFailedLogin(ctx context.Context, email string) {
	if s.stores.Lockouts == nil {
		return
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return
	}
	_ = s.stores.Lockouts.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{
		ID: id, Email: email, CreatedAt: time.Now(),
	})
	count, err := s.stores.Lockouts.CountRecentFailedLoginAttempts(ctx, email, time.Now().Add(-s.cfg.FailedLoginWindow))
	if err != nil || count < s.cfg.MaxFailedLoginAttempts {
		return
	}
	if su, err := s.stores.Superusers.GetSuperuserByEmail(ctx, email); err == nil {
		_ = s.stores.Lockouts.LockAccount(ctx, su.ID)
	}
}

// Refresh exchanges a valid, unrevoked superuser refresh token for a new
// token pair, rotating it.
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (TokenPair, error) {
	hash := authitcrypto.HashToken(refreshToken)
	t, err := s.stores.RefreshTokens.GetSuperuserRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	if t.RevokedAt != nil || time.Now().After(t.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	su, err := s.stores.Superusers.GetSuperuserByID(ctx, t.SuperuserID)
	if err != nil {
		return TokenPair{}, err
	}
	if !su.IsActive {
		return TokenPair{}, ErrInactive
	}
	if err := s.stores.RefreshTokens.RevokeSuperuserRefreshToken(ctx, t.ID); err != nil {
		return TokenPair{}, err
	}
	tokens, err := s.issueTokenPair(ctx, su.ID, su.Email, userAgent, ipAddress)
	if err != nil {
		return TokenPair{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserTokenRefreshed, Result: audit.ResultSuccess,
		ActorID: su.ID, Email: su.Email, UserAgent: userAgent, IPAddress: ipAddress,
	})
	return tokens, nil
}

// Logout revokes a single refresh token. Idempotent.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := authitcrypto.HashToken(refreshToken)
	t, err := s.stores.RefreshTokens.GetSuperuserRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := s.stores.RefreshTokens.RevokeSuperuserRefreshToken(ctx, t.ID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserLogout, Result: audit.ResultSuccess, ActorID: t.SuperuserID})
	return nil
}

func (s *Service) issueTokenPair(ctx context.Context, superuserID, email, userAgent, ipAddress string) (TokenPair, error) {
	rawRefresh, refreshHash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := &store.SuperuserRefreshToken{
		ID: id, SuperuserID: superuserID, TokenHash: refreshHash,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL), UserAgent: userAgent, IPAddress: ipAddress,
		CreatedAt: now,
	}
	if err := s.stores.RefreshTokens.CreateSuperuserRefreshToken(ctx, rt); err != nil {
		return TokenPair{}, err
	}

	expiresAt := now.Add(s.cfg.AccessTokenTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   superuserID,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Email: email,
	}
	access, err := s.signer.Sign(&claims)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: rawRefresh, ExpiresAt: expiresAt}, nil
}

// Verify validates a superuser access token, additionally requiring the
// configured audience so a valid user-plane token can never be accepted
// here.
func (s *Service) Verify(token string) (Claims, error) {
	var claims Claims
	if err := s.signer.Verify(token, &claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if !claims.HasAudience(s.cfg.Audience) {
		return Claims{}, ErrInvalidToken
	}
	return claims, nil
}
