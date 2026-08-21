package store

import (
	"context"
	"time"
)

// User is a login-capable identity. Host applications are free to store
// additional profile fields elsewhere and join on ID; authit only needs the
// fields below to authenticate.
type User struct {
	ID              string
	Email           string
	PasswordHash    string
	EmailVerified   bool
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// UserStore persists User records.
type UserStore interface {
	CreateUser(ctx context.Context, u *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, u *User) error
}

// RefreshToken is a server-side session record. The raw token is only ever
// returned to the caller once, at issuance; only TokenHash is persisted.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	UserAgent string
	IPAddress string
	CreatedAt time.Time
}

// RefreshTokenStore persists refresh tokens, which double as the list of a
// user's active sessions.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	ListActiveRefreshTokens(ctx context.Context, userID string) ([]*RefreshToken, error)
}

// PasswordResetToken is a single-use, time-limited token e-mailed to a user
// who requested a password reset. Only its hash is persisted.
type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// PasswordResetStore persists password reset tokens.
type PasswordResetStore interface {
	CreatePasswordResetToken(ctx context.Context, t *PasswordResetToken) error
	GetPasswordResetTokenByHash(ctx context.Context, hash string) (*PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, id string) error
	DeleteUserPasswordResetTokens(ctx context.Context, userID string) error
}

// EmailVerificationToken is a single-use, time-limited token e-mailed to a
// user to prove ownership of their address. Only its hash is persisted.
type EmailVerificationToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// EmailVerificationStore persists email verification tokens.
type EmailVerificationStore interface {
	CreateEmailVerificationToken(ctx context.Context, t *EmailVerificationToken) error
	GetEmailVerificationTokenByHash(ctx context.Context, hash string) (*EmailVerificationToken, error)
	MarkEmailVerificationTokenUsed(ctx context.Context, id string) error
	DeleteUserEmailVerificationTokens(ctx context.Context, userID string) error
}

// TOTPSettings holds a user's TOTP secret (encrypted at rest by the caller
// before it reaches the store) and backup codes (hashed).
type TOTPSettings struct {
	ID                 string
	UserID             string
	SecretEncrypted    []byte
	Enabled            bool
	VerifiedAt         *time.Time
	RecoveryCodeHashes []string
	RecoveryCodesUsed  int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// TOTPStore persists TOTP enrollment state.
type TOTPStore interface {
	CreateTOTPSettings(ctx context.Context, t *TOTPSettings) error
	GetTOTPSettingsByUserID(ctx context.Context, userID string) (*TOTPSettings, error)
	UpdateTOTPSettings(ctx context.Context, t *TOTPSettings) error
	DeleteTOTPSettings(ctx context.Context, userID string) error
}

// PendingTwoFactorSession is the short-lived token issued after a correct
// password when the account has TOTP enabled; it must be exchanged for a
// real session by presenting a valid TOTP or backup code.
type PendingTwoFactorSession struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PendingTwoFactorStore persists pending 2FA sessions.
type PendingTwoFactorStore interface {
	CreatePendingTwoFactorSession(ctx context.Context, s *PendingTwoFactorSession) error
	GetPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*PendingTwoFactorSession, error)
	DeletePendingTwoFactorSession(ctx context.Context, id string) error
}

// FailedLoginAttempt records one bad login attempt, keyed by email so
// lockout can be checked before a matching user is even confirmed to exist
// (this avoids leaking account existence through timing/behavior).
type FailedLoginAttempt struct {
	ID        string
	Email     string
	IPAddress string
	CreatedAt time.Time
}

// LockoutStore tracks failed logins and account lockout state.
type LockoutStore interface {
	RecordFailedLoginAttempt(ctx context.Context, a *FailedLoginAttempt) error
	CountRecentFailedLoginAttempts(ctx context.Context, email string, since time.Time) (int, error)
	ClearFailedLoginAttempts(ctx context.Context, email string) error
	LockAccount(ctx context.Context, userID string) error
	IsAccountLocked(ctx context.Context, userID string) (bool, error)
	UnlockAccount(ctx context.Context, userID string) error
}
