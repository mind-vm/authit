package user

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/audit"
	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
)

// BeginTwoFactorSetup generates a new TOTP secret for userID and stores it
// (encrypted) with Enabled=false. The caller must call
// ConfirmTwoFactorSetup with a valid code before 2FA takes effect.
func (s *Service) BeginTwoFactorSetup(ctx context.Context, userID, accountEmail string) (TwoFactorSetup, error) {
	if existing, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, userID); err == nil && existing.Enabled {
		return TwoFactorSetup{}, ErrTwoFactorEnabled
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return TwoFactorSetup{}, err
	}

	key, err := authitcrypto.GenerateTOTPSecret(s.cfg.TOTPIssuer, accountEmail)
	if err != nil {
		return TwoFactorSetup{}, err
	}
	encrypted, err := authitcrypto.EncryptSecret(s.cfg.TOTPEncryptionKey, key.Secret())
	if err != nil {
		return TwoFactorSetup{}, err
	}

	id, err := authitcrypto.NewID()
	if err != nil {
		return TwoFactorSetup{}, err
	}
	now := time.Now()
	settings := &store.TOTPSettings{
		ID: id, UserID: userID, SecretEncrypted: encrypted, Enabled: false,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.upsertTOTPSettings(ctx, userID, settings); err != nil {
		return TwoFactorSetup{}, err
	}
	return TwoFactorSetup{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

func (s *Service) upsertTOTPSettings(ctx context.Context, userID string, settings *store.TOTPSettings) error {
	if _, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, userID); err == nil {
		return s.stores.TOTP.UpdateTOTPSettings(ctx, settings)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.stores.TOTP.CreateTOTPSettings(ctx, settings)
}

// ConfirmTwoFactorSetup verifies a code against the pending secret from
// BeginTwoFactorSetup, enables 2FA, and returns freshly generated backup
// codes (plaintext, shown once).
func (s *Service) ConfirmTwoFactorSetup(ctx context.Context, userID, code string) (TwoFactorEnrollment, error) {
	settings, secret, err := s.getDecryptedTOTPSettings(ctx, userID)
	if err != nil {
		return TwoFactorEnrollment{}, err
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) {
		return TwoFactorEnrollment{}, ErrInvalidTwoFactor
	}

	codes, err := authitcrypto.GenerateBackupCodes(s.cfg.BackupCodeCount)
	if err != nil {
		return TwoFactorEnrollment{}, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = authitcrypto.HashBackupCode(c)
	}

	now := time.Now()
	settings.Enabled = true
	settings.VerifiedAt = &now
	settings.RecoveryCodeHashes = hashes
	settings.RecoveryCodesUsed = 0
	settings.UpdatedAt = now
	if err := s.stores.TOTP.UpdateTOTPSettings(ctx, settings); err != nil {
		return TwoFactorEnrollment{}, err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserTwoFactorEnabled, Result: audit.ResultSuccess, ActorID: userID})
	return TwoFactorEnrollment{BackupCodes: codes}, nil
}

// DisableTwoFactor turns off 2FA, accepting either a TOTP code or a backup
// code (so a user who lost their authenticator can still disable it).
func (s *Service) DisableTwoFactor(ctx context.Context, userID, code string) error {
	settings, secret, err := s.getDecryptedTOTPSettings(ctx, userID)
	if err != nil {
		return err
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) && !consumeBackupCode(settings, code) {
		return ErrInvalidTwoFactor
	}
	if err := s.stores.TOTP.DeleteTOTPSettings(ctx, userID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventUserTwoFactorDisabled, Result: audit.ResultSuccess, ActorID: userID})
	return nil
}

// RegenerateBackupCodes invalidates existing backup codes and issues a new
// set. Requires a valid TOTP code (not a backup code, to stop a stolen
// backup code from being used to mint fresh ones).
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	settings, secret, err := s.getDecryptedTOTPSettings(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !authitcrypto.ValidateTOTPCode(secret, totpCode) {
		return nil, ErrInvalidTwoFactor
	}
	codes, err := authitcrypto.GenerateBackupCodes(s.cfg.BackupCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = authitcrypto.HashBackupCode(c)
	}
	settings.RecoveryCodeHashes = hashes
	settings.RecoveryCodesUsed = 0
	settings.UpdatedAt = time.Now()
	if err := s.stores.TOTP.UpdateTOTPSettings(ctx, settings); err != nil {
		return nil, err
	}
	return codes, nil
}

// TwoFactorStatus reports whether 2FA is enabled and how many backup codes
// remain.
func (s *Service) TwoFactorStatus(ctx context.Context, userID string) (TwoFactorStatus, error) {
	settings, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return TwoFactorStatus{}, nil
		}
		return TwoFactorStatus{}, err
	}
	return TwoFactorStatus{
		Enabled:              settings.Enabled,
		VerifiedAt:           settings.VerifiedAt,
		RemainingBackupCodes: len(settings.RecoveryCodeHashes),
	}, nil
}

func (s *Service) getDecryptedTOTPSettings(ctx context.Context, userID string) (*store.TOTPSettings, string, error) {
	settings, err := s.stores.TOTP.GetTOTPSettingsByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", ErrTwoFactorNotEnabled
		}
		return nil, "", err
	}
	secret, err := authitcrypto.DecryptSecret(s.cfg.TOTPEncryptionKey, settings.SecretEncrypted)
	if err != nil {
		return nil, "", err
	}
	return settings, secret, nil
}

// consumeBackupCode checks code against settings' stored hashes and, on a
// match, removes it (single use) and bumps the used counter. It mutates
// settings in place but does not persist the change — callers that need
// the consumption to stick must call UpdateTOTPSettings themselves.
func consumeBackupCode(settings *store.TOTPSettings, code string) bool {
	hash := authitcrypto.HashBackupCode(code)
	for i, h := range settings.RecoveryCodeHashes {
		if h == hash {
			settings.RecoveryCodeHashes = append(settings.RecoveryCodeHashes[:i], settings.RecoveryCodeHashes[i+1:]...)
			settings.RecoveryCodesUsed++
			return true
		}
	}
	return false
}

// createPendingTwoFactorSession issues the short-lived token returned by
// Authenticate when 2FA is required.
func (s *Service) createPendingTwoFactorSession(ctx context.Context, userID string) (string, error) {
	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	if err := s.stores.PendingTwoFactor.CreatePendingTwoFactorSession(ctx, &store.PendingTwoFactorSession{
		ID: id, UserID: userID, TokenHash: hash, ExpiresAt: now.Add(s.cfg.PendingTwoFactorTTL), CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// VerifyTwoFactorLogin completes a login that Authenticate flagged as
// RequiresTwoFactor: it exchanges the pending token plus a valid TOTP or
// backup code for a real token pair.
func (s *Service) VerifyTwoFactorLogin(ctx context.Context, pendingToken, code, userAgent, ipAddress string) (AuthResult, error) {
	pending, err := s.stores.PendingTwoFactor.GetPendingTwoFactorSessionByHash(ctx, authitcrypto.HashToken(pendingToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return AuthResult{}, ErrInvalidToken
		}
		return AuthResult{}, err
	}
	if time.Now().After(pending.ExpiresAt) {
		return AuthResult{}, ErrInvalidToken
	}

	settings, secret, err := s.getDecryptedTOTPSettings(ctx, pending.UserID)
	if err != nil {
		return AuthResult{}, err
	}
	valid := authitcrypto.ValidateTOTPCode(secret, code)
	if !valid && consumeBackupCode(settings, code) {
		valid = true
		if err := s.stores.TOTP.UpdateTOTPSettings(ctx, settings); err != nil {
			return AuthResult{}, err
		}
	}
	if !valid {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserLoginFailed, Result: audit.ResultFailure, ActorID: pending.UserID,
			UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"reason": "invalid_two_factor"},
		})
		return AuthResult{}, ErrInvalidTwoFactor
	}

	_ = s.stores.PendingTwoFactor.DeletePendingTwoFactorSession(ctx, pending.ID)

	u, err := s.stores.Users.GetUserByID(ctx, pending.UserID)
	if err != nil {
		return AuthResult{}, err
	}
	tokens, err := s.issueTokenPair(ctx, u.ID, u.Email, userAgent, ipAddress)
	if err != nil {
		return AuthResult{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserLoginSucceeded, Result: audit.ResultSuccess, ActorID: u.ID, Email: u.Email,
		UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"via": "two_factor"},
	})
	return AuthResult{User: *u, Tokens: &tokens}, nil
}
