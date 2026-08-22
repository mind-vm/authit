package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// BeginTwoFactorSetup generates a new TOTP secret for userID and stores it
// (encrypted) with Enabled=false. The caller must call
// ConfirmTwoFactorSetup with a valid code before 2FA takes effect.
func (s *Service) BeginTwoFactorSetup(ctx context.Context, userID, accountEmail string) (TwoFactorSetup, error) {
	key, err := authitcrypto.GenerateTOTPSecret(s.cfg.TOTPIssuer, accountEmail)
	if err != nil {
		return TwoFactorSetup{}, err
	}
	encrypted, err := authitcrypto.EncryptSecret(s.cfg.TOTPEncryptionKey, key.Secret())
	if err != nil {
		return TwoFactorSetup{}, err
	}

	err = s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		existing, err := sqlb.Query[store.TotpSetting]().
			Where(store.TotpSettingCols.UserID.Eq(userID)).
			One(ctx, tx)
		switch {
		case err == nil && existing.Enabled:
			// Re-enrolling would silently invalidate the authenticator the
			// user is currently relying on. Disabling first is deliberate.
			return ErrTwoFactorEnabled
		case err == nil:
			// An unconfirmed enrollment from an abandoned attempt: replace its
			// secret rather than accumulating rows the unique index forbids.
			_, err = store.UpdateTotpSetting().
				SetSecretEncrypted(encrypted).
				SetUpdatedAt(time.Now()).
				Where(store.TotpSettingCols.UserID.Eq(userID)).
				Stmt().Exec(ctx, tx)
			return err
		case errors.Is(err, sqlb.ErrNotFound):
			row := store.TotpSetting{UserID: userID, SecretEncrypted: encrypted}
			_, err = sqlb.InsertRows(&row).Exec(ctx, tx)
			return err
		default:
			return err
		}
	})
	if err != nil {
		return TwoFactorSetup{}, err
	}
	return TwoFactorSetup{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

// ConfirmTwoFactorSetup verifies a code against the pending secret from
// BeginTwoFactorSetup, enables 2FA, and returns freshly generated backup
// codes (plaintext, shown once).
func (s *Service) ConfirmTwoFactorSetup(ctx context.Context, userID, code string) (TwoFactorEnrollment, error) {
	settings, secret, err := s.decryptedTOTP(ctx, s.db, userID)
	if err != nil {
		return TwoFactorEnrollment{}, err
	}
	if !authitcrypto.ValidateTOTPCode(secret, code) {
		return TwoFactorEnrollment{}, ErrInvalidTwoFactor
	}

	codes, hashes, err := s.newBackupCodes()
	if err != nil {
		return TwoFactorEnrollment{}, err
	}
	now := time.Now()
	if _, err := store.UpdateTotpSetting().
		SetEnabled(true).
		SetVerifiedAt(&now).
		SetRecoveryCodeHashes(hashes).
		SetRecoveryCodesUsed(0).
		SetUpdatedAt(now).
		Where(store.TotpSettingCols.ID.Eq(settings.ID)).
		Stmt().Exec(ctx, s.db); err != nil {
		return TwoFactorEnrollment{}, err
	}
	return TwoFactorEnrollment{BackupCodes: codes}, nil
}

// DisableTwoFactor turns off 2FA, accepting either a TOTP code or a backup
// code (so a user who lost their authenticator can still disable it).
func (s *Service) DisableTwoFactor(ctx context.Context, userID, code string) error {
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		settings, secret, err := s.decryptedTOTP(ctx, tx, userID)
		if err != nil {
			return err
		}
		if !authitcrypto.ValidateTOTPCode(secret, code) && !consumeBackupCode(&settings, code) {
			return ErrInvalidTwoFactor
		}
		_, err = sqlb.DeleteRows[store.TotpSetting]().
			Where(store.TotpSettingCols.UserID.Eq(userID)).
			Exec(ctx, tx)
		return err
	})
}

// RegenerateBackupCodes invalidates existing backup codes and issues a new
// set. Requires a valid TOTP code (not a backup code, to stop a stolen
// backup code from being used to mint fresh ones).
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	settings, secret, err := s.decryptedTOTP(ctx, s.db, userID)
	if err != nil {
		return nil, err
	}
	if !authitcrypto.ValidateTOTPCode(secret, totpCode) {
		return nil, ErrInvalidTwoFactor
	}
	codes, hashes, err := s.newBackupCodes()
	if err != nil {
		return nil, err
	}
	if _, err := store.UpdateTotpSetting().
		SetRecoveryCodeHashes(hashes).
		SetRecoveryCodesUsed(0).
		SetUpdatedAt(time.Now()).
		Where(store.TotpSettingCols.ID.Eq(settings.ID)).
		Stmt().Exec(ctx, s.db); err != nil {
		return nil, err
	}
	return codes, nil
}

// newBackupCodes generates a fresh set, returning the plaintext codes to show
// the user once and the hashes to store.
func (s *Service) newBackupCodes() (codes, hashes []string, err error) {
	codes, err = authitcrypto.GenerateBackupCodes(s.cfg.BackupCodeCount)
	if err != nil {
		return nil, nil, err
	}
	hashes = make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = authitcrypto.HashBackupCode(c)
	}
	return codes, hashes, nil
}

// TwoFactorStatus reports whether 2FA is enabled and how many backup codes
// remain.
func (s *Service) TwoFactorStatus(ctx context.Context, userID string) (TwoFactorStatus, error) {
	settings, err := sqlb.Query[store.TotpSetting]().
		Where(store.TotpSettingCols.UserID.Eq(userID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
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

func (s *Service) decryptedTOTP(ctx context.Context, db *sqlb.DB, userID string) (store.TotpSetting, string, error) {
	settings, err := sqlb.Query[store.TotpSetting]().
		Where(store.TotpSettingCols.UserID.Eq(userID)).
		One(ctx, db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return store.TotpSetting{}, "", ErrTwoFactorNotEnabled
		}
		return store.TotpSetting{}, "", err
	}
	secret, err := authitcrypto.DecryptSecret(s.cfg.TOTPEncryptionKey, settings.SecretEncrypted)
	if err != nil {
		return store.TotpSetting{}, "", err
	}
	return settings, secret, nil
}

// consumeBackupCode checks code against settings' stored hashes and, on a
// match, removes it (single use) and bumps the used counter. It mutates
// settings in place but does not persist the change — callers that need the
// consumption to stick must write settings back themselves.
func consumeBackupCode(settings *store.TotpSetting, code string) bool {
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
	row := store.PendingTwoFactorSession{
		UserID: userID, TokenHash: hash,
		ExpiresAt: time.Now().Add(s.cfg.PendingTwoFactorTTL),
	}
	if _, err := sqlb.InsertRows(&row).Exec(ctx, s.db); err != nil {
		return "", err
	}
	return raw, nil
}

// VerifyTwoFactorLogin completes a login that Authenticate flagged as
// RequiresTwoFactor: it exchanges the pending token plus a valid TOTP or
// backup code for a real token pair.
func (s *Service) VerifyTwoFactorLogin(ctx context.Context, pendingToken, code, userAgent, ipAddress string) (AuthResult, error) {
	var result AuthResult
	err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		pending, err := sqlb.Query[store.PendingTwoFactorSession]().
			Where(store.PendingTwoFactorSessionCols.TokenHash.Eq(authitcrypto.HashToken(pendingToken))).
			One(ctx, tx)
		if err != nil {
			if errors.Is(err, sqlb.ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
		if time.Now().After(pending.ExpiresAt) {
			return ErrInvalidToken
		}

		settings, secret, err := s.decryptedTOTP(ctx, tx, pending.UserID)
		if err != nil {
			return err
		}
		valid := authitcrypto.ValidateTOTPCode(secret, code)
		if !valid && consumeBackupCode(&settings, code) {
			valid = true
			// Spending the backup code, consuming the pending session and
			// issuing the tokens are one unit of work — a code that was
			// consumed without a session being issued is one the user has lost
			// for nothing.
			if _, err := store.UpdateTotpSetting().
				SetRecoveryCodeHashes(settings.RecoveryCodeHashes).
				SetRecoveryCodesUsed(settings.RecoveryCodesUsed).
				SetUpdatedAt(time.Now()).
				Where(store.TotpSettingCols.ID.Eq(settings.ID)).
				Stmt().Exec(ctx, tx); err != nil {
				return err
			}
		}
		if !valid {
			return ErrInvalidTwoFactor
		}

		if _, err := sqlb.DeleteRows[store.PendingTwoFactorSession]().
			Where(store.PendingTwoFactorSessionCols.ID.Eq(pending.ID)).
			Exec(ctx, tx); err != nil {
			return err
		}

		u, err := sqlb.Query[store.User]().
			Where(store.UserCols.ID.Eq(pending.UserID)).
			One(ctx, tx)
		if err != nil {
			return err
		}
		tokens, err := s.issueTokenPair(ctx, tx, u.ID, u.Email, userAgent, ipAddress)
		if err != nil {
			return err
		}
		result = AuthResult{User: u, Tokens: &tokens}
		return nil
	})
	if err != nil {
		return AuthResult{}, err
	}
	return result, nil
}
