package superuser

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// Authenticate verifies email/password against the superuser table and
// issues a token pair scoped to this plane's audience.
func (s *Service) Authenticate(ctx context.Context, email, password, userAgent, ipAddress string) (TokenPair, error) {
	su, err := sqlb.Query[store.Superuser]().
		Where(store.SuperuserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			s.recordFailedLogin(ctx, email, ipAddress)
			return TokenPair{}, ErrInvalidCredentials
		}
		return TokenPair{}, err
	}

	locked, err := sqlb.Query[store.SuperuserAccountLock]().
		Where(store.SuperuserAccountLockCols.SuperuserID.Eq(su.ID)).
		Exists(ctx, s.db)
	if err != nil {
		return TokenPair{}, err
	}
	if locked {
		return TokenPair{}, ErrAccountLocked
	}

	if !authitcrypto.CheckPassword(password, su.PasswordHash) {
		s.recordFailedLogin(ctx, email, ipAddress)
		return TokenPair{}, ErrInvalidCredentials
	}
	if !su.IsActive {
		return TokenPair{}, ErrInactive
	}
	if _, err := sqlb.DeleteRows[store.SuperuserFailedLoginAttempt]().
		Where(store.SuperuserFailedLoginAttemptCols.Email.Eq(email)).
		Exec(ctx, s.db); err != nil {
		return TokenPair{}, err
	}

	now := time.Now()
	_, _ = store.UpdateSuperuser().
		SetLastLoginAt(&now).
		Where(store.SuperuserCols.ID.Eq(su.ID)).
		Stmt().Exec(ctx, s.db)

	return s.issueTokenPair(ctx, su.ID, su.Email, userAgent, ipAddress)
}

// recordFailedLogin is best-effort throughout: a lockout that fails to record
// must not turn a wrong password into a 500, which would itself leak that the
// address exists.
func (s *Service) recordFailedLogin(ctx context.Context, email, ipAddress string) {
	attempt := store.SuperuserFailedLoginAttempt{Email: email, IPAddress: ipAddress}
	if _, err := sqlb.InsertRows(&attempt).Exec(ctx, s.db); err != nil {
		return
	}
	count, err := sqlb.Query[store.SuperuserFailedLoginAttempt]().
		Where(
			store.SuperuserFailedLoginAttemptCols.Email.Eq(email),
			store.SuperuserFailedLoginAttemptCols.CreatedAt.Gt(time.Now().Add(-s.cfg.FailedLoginWindow)),
		).
		Count(ctx, s.db)
	if err != nil || count < int64(s.cfg.MaxFailedLoginAttempts) {
		return
	}
	su, err := sqlb.Query[store.Superuser]().
		Where(store.SuperuserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		return
	}
	// OnConflictDoNothing rather than check-then-insert: locking an
	// already-locked account is idempotent, and the primary key is what
	// decides.
	lock := store.SuperuserAccountLock{SuperuserID: su.ID}
	_, _ = sqlb.InsertRows(&lock).OnConflictDoNothing("superuser_id").Exec(ctx, s.db)
}

// Unlock clears an operator's lockout and its recorded failures. There is no
// automatic expiry: an operator lockout is meant to need a human.
func (s *Service) Unlock(ctx context.Context, superuserID string) error {
	if _, err := sqlb.DeleteRows[store.SuperuserAccountLock]().
		Where(store.SuperuserAccountLockCols.SuperuserID.Eq(superuserID)).
		Exec(ctx, s.db); err != nil {
		return err
	}
	su, err := sqlb.Query[store.Superuser]().
		Where(store.SuperuserCols.ID.Eq(superuserID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	_, err = sqlb.DeleteRows[store.SuperuserFailedLoginAttempt]().
		Where(store.SuperuserFailedLoginAttemptCols.Email.Eq(su.Email)).
		Exec(ctx, s.db)
	return err
}

// Refresh exchanges a valid, unrevoked superuser refresh token for a new
// token pair, rotating it.
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (TokenPair, error) {
	t, err := sqlb.Query[store.SuperuserRefreshToken]().
		Where(store.SuperuserRefreshTokenCols.TokenHash.Eq(authitcrypto.HashToken(refreshToken))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	if t.RevokedAt != nil || time.Now().After(t.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	su, err := sqlb.Query[store.Superuser]().
		Where(store.SuperuserCols.ID.Eq(t.SuperuserID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	if !su.IsActive {
		return TokenPair{}, ErrInactive
	}
	if err := s.revoke(ctx, t.ID); err != nil {
		return TokenPair{}, err
	}
	return s.issueTokenPair(ctx, su.ID, su.Email, userAgent, ipAddress)
}

// Logout revokes a single refresh token. Idempotent: revoking an
// already-revoked or unknown token is not an error.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	t, err := sqlb.Query[store.SuperuserRefreshToken]().
		Where(store.SuperuserRefreshTokenCols.TokenHash.Eq(authitcrypto.HashToken(refreshToken))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return nil
		}
		return err
	}
	return s.revoke(ctx, t.ID)
}

func (s *Service) revoke(ctx context.Context, id string) error {
	now := time.Now()
	_, err := store.UpdateSuperuserRefreshToken().
		SetRevokedAt(&now).
		Where(store.SuperuserRefreshTokenCols.ID.Eq(id)).
		Stmt().Exec(ctx, s.db)
	return err
}

func (s *Service) issueTokenPair(ctx context.Context, superuserID, email, userAgent, ipAddress string) (TokenPair, error) {
	rawRefresh, refreshHash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := store.SuperuserRefreshToken{
		SuperuserID: superuserID, TokenHash: refreshHash,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL), UserAgent: userAgent, IPAddress: ipAddress,
	}
	if _, err := sqlb.InsertRows(&rt).Exec(ctx, s.db); err != nil {
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
