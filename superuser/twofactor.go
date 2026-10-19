package superuser

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// An operator's second factor. The flows mirror the user plane's, over the
// operator plane's own tables; an enrolled factor is always asked for at
// sign-in, never merely recorded.

// TwoFactorSetup is what BeginTwoFactorSetup returns for the operator's
// authenticator app.
type TwoFactorSetup struct {
	Secret     string
	OTPAuthURL string
}

// TwoFactorStatus is an operator's second-factor state.
type TwoFactorStatus struct {
	Available            bool
	Enabled              bool
	VerifiedAt           *time.Time
	RemainingBackupCodes int
}

// TwoFactorStatus reports whether superuserID has a second factor.
func (s *Service) TwoFactorStatus(ctx context.Context, superuserID string) (TwoFactorStatus, error) {
	if s.stores.TwoFactor == nil {
		return TwoFactorStatus{}, nil
	}
	settings, err := s.stores.TwoFactor.GetSuperuserTOTPSettings(ctx, superuserID)
	if errors.Is(err, store.ErrNotFound) {
		return TwoFactorStatus{Available: true}, nil
	}
	if err != nil {
		return TwoFactorStatus{}, err
	}
	return TwoFactorStatus{
		Available: true, Enabled: settings.Enabled, VerifiedAt: settings.VerifiedAt,
		RemainingBackupCodes: len(settings.RecoveryCodeHashes),
	}, nil
}

// BeginTwoFactorSetup stores a fresh secret, not yet enabled; nothing changes
// at sign-in until ConfirmTwoFactorSetup proves the app holds it.
func (s *Service) BeginTwoFactorSetup(ctx context.Context, superuserID, email string) (TwoFactorSetup, error) {
	if s.stores.TwoFactor == nil {
		return TwoFactorSetup{}, ErrTwoFactorUnavailable
	}
	existing, err := s.stores.TwoFactor.GetSuperuserTOTPSettings(ctx, superuserID)
	switch {
	case err == nil && existing.Enabled:
		return TwoFactorSetup{}, ErrTwoFactorEnabled
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return TwoFactorSetup{}, err
	}

	key, err := authitcrypto.GenerateTOTPSecret(s.cfg.TOTPIssuer, email)
	if err != nil {
		return TwoFactorSetup{}, err
	}
	encrypted, err := authitcrypto.EncryptSecret(s.cfg.TOTPEncryptionKey, key.Secret())
	if err != nil {
		return TwoFactorSetup{}, err
	}
	now := time.Now()
	if existing != nil {
		existing.SecretEncrypted, existing.UpdatedAt = encrypted, now
		err = s.stores.TwoFactor.UpdateSuperuserTOTPSettings(ctx, existing)
	} else {
		id, idErr := authitcrypto.NewID()
		if idErr != nil {
			return TwoFactorSetup{}, idErr
		}
		err = s.stores.TwoFactor.CreateSuperuserTOTPSettings(ctx, &store.TOTPSettings{
			ID: id, UserID: superuserID, SecretEncrypted: encrypted, CreatedAt: now, UpdatedAt: now,
		})
	}
	if err != nil {
		return TwoFactorSetup{}, err
	}
	return TwoFactorSetup{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

// ConfirmTwoFactorSetup enables the factor from BeginTwoFactorSetup and
// returns the backup codes, in plaintext, once.
func (s *Service) ConfirmTwoFactorSetup(ctx context.Context, superuserID, code string) ([]string, error) {
	settings, secret, err := s.totp(ctx, superuserID)
	if err != nil {
		return nil, err
	}
	if settings.Enabled {
		return nil, ErrTwoFactorEnabled
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) {
		return nil, ErrInvalidTwoFactor
	}
	codes, err := s.newBackupCodes(settings)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	settings.Enabled, settings.VerifiedAt, settings.UpdatedAt = true, &now, now
	if err := s.stores.TwoFactor.UpdateSuperuserTOTPSettings(ctx, settings); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserTwoFactorEnabled, Result: audit.ResultSuccess, ActorID: superuserID})
	return codes, nil
}

// DisableTwoFactor removes the factor, given a current code or a backup code,
// so an operator who lost the app can still turn it off.
func (s *Service) DisableTwoFactor(ctx context.Context, superuserID, code string) error {
	settings, secret, err := s.enabledTOTP(ctx, superuserID)
	if err != nil {
		return err
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) && !consumeBackupCode(settings, code) {
		s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserTwoFactorDisabled, Result: audit.ResultFailure, ActorID: superuserID})
		return ErrInvalidTwoFactor
	}
	if err := s.stores.TwoFactor.DeleteSuperuserTOTPSettings(ctx, superuserID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserTwoFactorDisabled, Result: audit.ResultSuccess, ActorID: superuserID})
	return nil
}

// RegenerateBackupCodes replaces the backup codes. It takes an app code
// only, so a stolen backup code cannot mint more.
func (s *Service) RegenerateBackupCodes(ctx context.Context, superuserID, code string) ([]string, error) {
	settings, secret, err := s.enabledTOTP(ctx, superuserID)
	if err != nil {
		return nil, err
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) {
		return nil, ErrInvalidTwoFactor
	}
	codes, err := s.newBackupCodes(settings)
	if err != nil {
		return nil, err
	}
	settings.UpdatedAt = time.Now()
	if err := s.stores.TwoFactor.UpdateSuperuserTOTPSettings(ctx, settings); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserBackupCodesRegenerated, Result: audit.ResultSuccess, ActorID: superuserID})
	return codes, nil
}

// beginTwoFactorLogin returns a pending token when superuserID has an
// enabled factor, and the empty string when the password alone suffices.
func (s *Service) beginTwoFactorLogin(ctx context.Context, superuserID string) (string, error) {
	if s.stores.TwoFactor == nil {
		return "", nil
	}
	settings, err := s.stores.TwoFactor.GetSuperuserTOTPSettings(ctx, superuserID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !settings.Enabled {
		return "", nil
	}
	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	if err := s.stores.TwoFactor.CreateSuperuserPendingTwoFactorSession(ctx, &store.PendingTwoFactorSession{
		ID: id, UserID: superuserID, TokenHash: hash, ExpiresAt: now.Add(s.cfg.PendingTwoFactorTTL), CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// VerifyTwoFactorLogin completes a sign-in Authenticate left pending,
// exchanging the pending token and an app or backup code for tokens.
func (s *Service) VerifyTwoFactorLogin(ctx context.Context, pendingToken, code, userAgent, ipAddress string) (TokenPair, error) {
	if s.stores.TwoFactor == nil {
		return TokenPair{}, ErrInvalidToken
	}
	pending, err := s.stores.TwoFactor.GetSuperuserPendingTwoFactorSessionByHash(ctx, authitcrypto.HashToken(pendingToken))
	if errors.Is(err, store.ErrNotFound) {
		return TokenPair{}, ErrInvalidToken
	}
	if err != nil {
		return TokenPair{}, err
	}
	if time.Now().After(pending.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	su, err := s.stores.Superusers.GetSuperuserByID(ctx, pending.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	if !su.IsActive {
		return TokenPair{}, ErrInactive
	}

	// The code is metered on the same counter as the password, which
	// Authenticate left standing, so a fresh pending token buys no guesses.
	if err := ratelimit.AllowEach(ctx, s.cfg.RateLimiter, "superuser-two-factor:ip:"+ipAddress, "superuser-two-factor:superuser:"+su.ID); err != nil {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventSuperuserLoginFailed, Result: audit.ResultDenied, ActorID: su.ID, Email: su.Email,
			UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"reason": "rate_limited", "stage": "two_factor"},
		})
		return TokenPair{}, err
	}
	throttled, err := s.throttled(ctx, su.Email)
	if err != nil {
		return TokenPair{}, err
	}
	if throttled {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventSuperuserLoginLocked, Result: audit.ResultDenied, ActorID: su.ID, Email: su.Email,
			UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"stage": "two_factor"},
		})
		return TokenPair{}, ErrAccountLocked
	}

	settings, secret, err := s.enabledTOTP(ctx, su.ID)
	if err != nil {
		return TokenPair{}, err
	}
	valid := authitcrypto.ValidateTOTPCode(secret, code)
	usedBackupCode := false
	if !valid && consumeBackupCode(settings, code) {
		valid, usedBackupCode = true, true
	}
	if !valid {
		s.recordFailedLogin(ctx, su.Email)
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventSuperuserLoginFailed, Result: audit.ResultFailure, ActorID: su.ID, Email: su.Email,
			UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"reason": "invalid_two_factor"},
		})
		return TokenPair{}, ErrInvalidTwoFactor
	}

	// Spending a backup code, retiring the pending token and issuing the
	// session land together: a spent code with no session is a lockout.
	var tokens TokenPair
	err = store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		if usedBackupCode {
			settings.UpdatedAt = time.Now()
			if err := s.stores.TwoFactor.UpdateSuperuserTOTPSettings(ctx, settings); err != nil {
				return err
			}
		}
		if err := s.stores.TwoFactor.DeleteSuperuserPendingTwoFactorSession(ctx, pending.ID); err != nil {
			return err
		}
		var err error
		tokens, err = s.issueTokenPair(ctx, su.ID, su.Email, userAgent, ipAddress)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}

	if s.stores.Lockouts != nil {
		_ = s.stores.Lockouts.ClearFailedLoginAttempts(ctx, su.Email)
	}
	now := time.Now()
	su.LastLoginAt = &now
	_ = s.stores.Superusers.UpdateSuperuser(ctx, su)
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserLoginSucceeded, Result: audit.ResultSuccess, ActorID: su.ID, Email: su.Email,
		UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: map[string]any{"via": "two_factor", "backup_code": usedBackupCode},
	})
	return tokens, nil
}

func (s *Service) totp(ctx context.Context, superuserID string) (*store.TOTPSettings, string, error) {
	if s.stores.TwoFactor == nil {
		return nil, "", ErrTwoFactorUnavailable
	}
	settings, err := s.stores.TwoFactor.GetSuperuserTOTPSettings(ctx, superuserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", ErrTwoFactorNotEnabled
	}
	if err != nil {
		return nil, "", err
	}
	secret, err := authitcrypto.DecryptSecret(s.cfg.TOTPEncryptionKey, settings.SecretEncrypted)
	if err != nil {
		return nil, "", err
	}
	return settings, secret, nil
}

func (s *Service) enabledTOTP(ctx context.Context, superuserID string) (*store.TOTPSettings, string, error) {
	settings, secret, err := s.totp(ctx, superuserID)
	if err != nil {
		return nil, "", err
	}
	if !settings.Enabled {
		return nil, "", ErrTwoFactorNotEnabled
	}
	return settings, secret, nil
}

// newBackupCodes replaces settings' codes in place and returns the plaintext.
func (s *Service) newBackupCodes(settings *store.TOTPSettings) ([]string, error) {
	codes, err := authitcrypto.GenerateBackupCodes(s.cfg.BackupCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = authitcrypto.HashBackupCode(c)
	}
	settings.RecoveryCodeHashes, settings.RecoveryCodesUsed = hashes, 0
	return codes, nil
}

// consumeBackupCode removes a matching code from settings in place; the
// caller persists it.
func consumeBackupCode(settings *store.TOTPSettings, code string) bool {
	hash := []byte(authitcrypto.HashBackupCode(code))
	for i, h := range settings.RecoveryCodeHashes {
		if subtle.ConstantTimeCompare([]byte(h), hash) == 1 {
			settings.RecoveryCodeHashes = append(settings.RecoveryCodeHashes[:i], settings.RecoveryCodeHashes[i+1:]...)
			settings.RecoveryCodesUsed++
			return true
		}
	}
	return false
}
