package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// Register creates a new user with the given email/password. The password
// is hashed before storage; the plaintext never leaves this call.
func (s *Service) Register(ctx context.Context, email, password string) (store.User, error) {
	hash, err := authitcrypto.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}

	row := store.User{Email: email, PasswordHash: hash}
	inserted, err := sqlb.InsertRows(&row).Exec(ctx, s.db)
	if err != nil {
		// The unique index on email is the arbiter, rather than a
		// does-this-exist query first. Checking beforehand is a read-then-write
		// race: two simultaneous signups on one address both find it free and
		// both proceed. Letting the constraint decide has no such window, and
		// it is the constraint that was going to be authoritative anyway.
		var c *sqlb.ConstraintError
		if errors.As(err, &c) && c.Kind == sqlb.ConstraintUnique {
			return store.User{}, ErrEmailTaken
		}
		return store.User{}, err
	}
	return inserted[0], nil
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
		return AuthResult{}, ErrAccountLocked
	}
	if u == nil || !authitcrypto.CheckPassword(password, u.PasswordHash) {
		s.recordFailedLogin(ctx, email, ipAddress)
		return AuthResult{}, ErrInvalidCredentials
	}
	if s.cfg.EmailVerification == EmailVerificationRequired && !u.EmailVerified {
		return AuthResult{}, ErrEmailNotVerified
	}
	if _, err := sqlb.DeleteRows[store.FailedLoginAttempt]().
		Where(store.FailedLoginAttemptCols.Email.Eq(email)).
		Exec(ctx, s.db); err != nil {
		return AuthResult{}, err
	}

	totp, err := sqlb.Query[store.TotpSetting]().
		Where(store.TotpSettingCols.UserID.Eq(u.ID)).
		One(ctx, s.db)
	if err != nil && !errors.Is(err, sqlb.ErrNotFound) {
		return AuthResult{}, err
	}
	if err == nil && totp.Enabled {
		pendingToken, err := s.createPendingTwoFactorSession(ctx, u.ID)
		if err != nil {
			return AuthResult{}, err
		}
		return AuthResult{User: *u, RequiresTwoFactor: true, PendingTwoFactorToken: pendingToken}, nil
	}

	tokens, err := s.issueTokenPair(ctx, s.db, u.ID, u.Email, userAgent, ipAddress)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: *u, Tokens: &tokens}, nil
}

// checkLockoutAndFetchUser looks up the user without leaking, via error
// shape or timing, whether the email exists: it returns a nil user (not an
// error) if the account doesn't exist, so the caller falls through to the
// same password-check-failed path either way.
func (s *Service) checkLockoutAndFetchUser(ctx context.Context, email string) (locked bool, u *store.User, err error) {
	found, err := sqlb.Query[store.User]().
		Where(store.UserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}
	locked, err = sqlb.Query[store.AccountLock]().
		Where(store.AccountLockCols.UserID.Eq(found.ID)).
		Exists(ctx, s.db)
	if err != nil {
		return false, nil, err
	}
	return locked, &found, nil
}

// recordFailedLogin is best-effort throughout: a lockout that fails to record
// must not turn a wrong password into a 500, which would itself leak that the
// address exists.
func (s *Service) recordFailedLogin(ctx context.Context, email, ipAddress string) {
	attempt := store.FailedLoginAttempt{Email: email, IPAddress: ipAddress}
	if _, err := sqlb.InsertRows(&attempt).Exec(ctx, s.db); err != nil {
		return
	}
	count, err := sqlb.Query[store.FailedLoginAttempt]().
		Where(
			store.FailedLoginAttemptCols.Email.Eq(email),
			store.FailedLoginAttemptCols.CreatedAt.Gt(time.Now().Add(-s.cfg.FailedLoginWindow)),
		).
		Count(ctx, s.db)
	if err != nil || count < int64(s.cfg.MaxFailedLoginAttempts) {
		return
	}
	u, err := sqlb.Query[store.User]().
		Where(store.UserCols.Email.Eq(email)).
		One(ctx, s.db)
	if err != nil {
		return
	}
	// OnConflictDoNothing rather than check-then-insert: locking an
	// already-locked account is idempotent, and the primary key is what
	// decides.
	lock := store.AccountLock{UserID: u.ID}
	_, _ = sqlb.InsertRows(&lock).OnConflictDoNothing("user_id").Exec(ctx, s.db)
}

// Unlock clears an account's lockout and the failures that caused it.
func (s *Service) Unlock(ctx context.Context, userID string) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		if _, err := sqlb.DeleteRows[store.AccountLock]().
			Where(store.AccountLockCols.UserID.Eq(userID)).
			Exec(ctx, tx); err != nil {
			return err
		}
		u, err := sqlb.Query[store.User]().
			Where(store.UserCols.ID.Eq(userID)).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		_, err = sqlb.DeleteRows[store.FailedLoginAttempt]().
			Where(store.FailedLoginAttemptCols.Email.Eq(u.Email)).
			Exec(ctx, tx)
		return err
	})
}

// Refresh exchanges a valid, unrevoked refresh token for a new token pair,
// rotating the refresh token (the old one is revoked).
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (TokenPair, error) {
	var pair TokenPair
	err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		// Revoking the old token and issuing the new one is one unit of work:
		// a failure between them would leave the caller holding a revoked
		// token and no replacement, i.e. logged out by a transient error.
		t, err := sqlb.Query[store.RefreshToken]().
			Where(store.RefreshTokenCols.TokenHash.Eq(authitcrypto.HashToken(refreshToken))).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
		if t.RevokedAt != nil || time.Now().After(t.ExpiresAt) {
			return ErrInvalidToken
		}
		u, err := sqlb.Query[store.User]().
			Where(store.UserCols.ID.Eq(t.UserID)).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
		if err := revokeRefreshToken(ctx, tx, t.ID); err != nil {
			return err
		}
		pair, err = s.issueTokenPair(ctx, tx, u.ID, u.Email, userAgent, ipAddress)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}
	return pair, nil
}

// Logout revokes a single refresh token. It is idempotent: revoking an
// already-revoked or unknown token is not an error.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	t, err := sqlb.Query[store.RefreshToken]().
		Where(store.RefreshTokenCols.TokenHash.Eq(authitcrypto.HashToken(refreshToken))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return nil
		}
		return err
	}
	return revokeRefreshToken(ctx, s.db, t.ID)
}

func revokeRefreshToken(ctx context.Context, db *sqlb.DB, id string) error {
	now := time.Now()
	_, err := store.UpdateRefreshToken().
		SetRevokedAt(&now).
		Where(store.RefreshTokenCols.ID.Eq(id)).
		Stmt().Exec(ctx, db)
	return err
}

func (s *Service) issueTokenPair(ctx context.Context, db *sqlb.DB, userID, email, userAgent, ipAddress string) (TokenPair, error) {
	rawRefresh, refreshHash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := store.RefreshToken{
		UserID: userID, TokenHash: refreshHash,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		UserAgent: userAgent, IPAddress: ipAddress,
	}
	if _, err := sqlb.InsertRows(&rt).Exec(ctx, db); err != nil {
		return TokenPair{}, err
	}

	expiresAt := now.Add(s.cfg.AccessTokenTTL)
	access, err := s.signer.Generate(newAccessClaims(userID, email, expiresAt))
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: rawRefresh, ExpiresAt: expiresAt}, nil
}
