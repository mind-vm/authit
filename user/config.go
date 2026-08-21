package user

import "time"

// Config tunes the user package's flows. Zero-value fields are replaced
// with sane defaults by NewService.
type Config struct {
	// AccessTokenTTL is how long an issued access JWT is valid for.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh token (session) stays valid if
	// never revoked.
	RefreshTokenTTL time.Duration
	// PasswordResetTTL is how long a password reset link stays valid.
	PasswordResetTTL time.Duration
	// EmailVerificationTTL is how long an email verification link stays
	// valid.
	EmailVerificationTTL time.Duration
	// PendingTwoFactorTTL is how long a caller has to complete the 2FA step
	// after a correct password before having to log in again.
	PendingTwoFactorTTL time.Duration
	// MaxFailedLoginAttempts is how many recent failed logins lock the
	// account.
	MaxFailedLoginAttempts int
	// FailedLoginWindow is the lookback window used when counting recent
	// failed attempts.
	FailedLoginWindow time.Duration
	// TOTPIssuer is the issuer name embedded in generated TOTP QR codes.
	TOTPIssuer string
	// TOTPEncryptionKey encrypts TOTP secrets at rest (AES-256-GCM). Must be
	// exactly 32 bytes. Required if 2FA methods are used.
	TOTPEncryptionKey []byte
	// BackupCodeCount is how many backup codes are generated on 2FA setup.
	BackupCodeCount int
}

func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if c.PasswordResetTTL <= 0 {
		c.PasswordResetTTL = time.Hour
	}
	if c.EmailVerificationTTL <= 0 {
		c.EmailVerificationTTL = 24 * time.Hour
	}
	if c.PendingTwoFactorTTL <= 0 {
		c.PendingTwoFactorTTL = 5 * time.Minute
	}
	if c.MaxFailedLoginAttempts <= 0 {
		c.MaxFailedLoginAttempts = 5
	}
	if c.FailedLoginWindow <= 0 {
		c.FailedLoginWindow = 15 * time.Minute
	}
	if c.TOTPIssuer == "" {
		c.TOTPIssuer = "authit"
	}
	if c.BackupCodeCount <= 0 {
		c.BackupCodeCount = 10
	}
	return c
}
