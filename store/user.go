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
//
// The field names are worth reading before writing the table: the obvious
// guesses (`confirmed`, `backup_codes`) are not what this type has. Enabled
// is the on/off flag, VerifiedAt records when enrollment was confirmed, and
// the backup codes are RecoveryCodeHashes plus a RecoveryCodesUsed counter.
//
// RecoveryCodeHashes is a []string with no single obvious storage: a
// Postgres text[], a join table and a JSON column are all defensible, and the
// choice is yours -- see schema.sql, which uses text[].
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
//
// It needs TWO tables, which is not visible from the types above, and they
// back two DIFFERENT concepts -- do not conflate them:
//
//  1. The attempts table (FailedLoginAttempt rows, keyed by email) backs the
//     *temporary* lockout. authit does not store that lockout anywhere: it
//     derives it by counting recent attempts, so it lifts on its own as they
//     age out of the window. This is the automatic brute-force control, and
//     it is the only one a failed login triggers.
//
//  2. The locks table backs the *administrative* lock -- an operator
//     disabling an account until an operator re-enables it. It has no
//     canonical authit type at all: LockAccount, IsAccountLocked and
//     UnlockAccount are insert/exists/delete over a set of user ids, not CRUD
//     over a struct, so its shape is entirely yours. All authit requires is
//     that its user-id column is UNIQUE, so locking an already-locked account
//     is idempotent rather than an error.
//
// Nothing inside authit calls LockAccount or UnlockAccount; they exist for
// the host to call. Earlier versions locked an account automatically after
// MaxFailedLoginAttempts, which -- because the lock had no expiry and nothing
// ever cleared it -- let anyone who knew an address disable it permanently
// with a handful of wrong passwords. If you are upgrading, note that rows
// written to your locks table by that behaviour are still honoured and must
// be cleared manually.
//
// Implementing only the attempts table compiles cleanly, and every automatic
// control still works; IsAccountLocked is then the only method reached, on
// every login. See schema.sql (`account_locks`).
type LockoutStore interface {
	RecordFailedLoginAttempt(ctx context.Context, a *FailedLoginAttempt) error
	// CountRecentFailedLoginAttempts is called on every login attempt, not
	// only on failures -- it is what the temporary lockout is derived from.
	// Index (email, created_at).
	CountRecentFailedLoginAttempts(ctx context.Context, email string, since time.Time) (int, error)
	ClearFailedLoginAttempts(ctx context.Context, email string) error
	LockAccount(ctx context.Context, userID string) error
	IsAccountLocked(ctx context.Context, userID string) (bool, error)
	UnlockAccount(ctx context.Context, userID string) error
}
