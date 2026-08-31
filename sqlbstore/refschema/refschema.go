// Package refschema is a working Postgres binding for the reference
// schema.sql, ready to hand to authit's services.
//
// sqlbstore is generic over a row type the host defines, which is right --
// authit does not own your tables. But it means a host starting from the
// reference schema had nowhere to start *from*: the row types existed only
// inside sqlbstore's own test binary, so the way to use them was to copy
// them out of a _test.go file.
//
// That is not a hypothetical cost. The first time the reference wiring ran
// against a real database it was wrong: ToRow dropped the caller's
// CreatedAt on failed_login_attempts, so every attempt landed at the
// database's clock rather than the one the lockout counts against, and an
// hour-old failure counted as recent. Copied as it stood, it rebuilt the
// permanent lockout Tier 0 was written to remove. Code nobody imports is
// code nobody checks.
//
// So this package is the same wiring, exported, and sqlbstore's conformance
// suite now runs against *it* rather than against a private copy of it.
// What the suite verifies and what a host imports are the same lines.
//
// # Use it only if your tables match
//
// Every row type here names a table and a column set from schema.sql
// exactly. If your schema differs in any respect -- a renamed column, an
// extra NOT NULL, a bigint id -- do not adapt this package. Write your own
// row types against sqlbstore.Table, which is the supported path and is
// what this package is itself an instance of. Read it as the worked
// example it is.
//
// Nothing here is required to use authit, and nothing in authit imports it.
package refschema

import (
	"time"

	"github.com/mind-vm/authit/sqlbstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
	"github.com/mind-vm/sqlb"
)

type User struct {
	ID              string     `db:"id" sqlb:"type:uuid,pk,default"`
	Email           string     `db:"email" sqlb:"type:text"`
	PasswordHash    string     `db:"password_hash" sqlb:"type:text"`
	EmailVerified   bool       `db:"email_verified" sqlb:"type:boolean,default"`
	EmailVerifiedAt *time.Time `db:"email_verified_at" sqlb:"type:timestamptz"`
	CreatedAt       time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt       time.Time  `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (User) TableName() string { return "users" }

type RefreshToken struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	RevokedAt *time.Time `db:"revoked_at" sqlb:"type:timestamptz"`
	UserAgent string     `db:"user_agent" sqlb:"type:text,default"`
	IPAddress string     `db:"ip_address" sqlb:"type:text,default"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

type PasswordResetToken struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	UsedAt    *time.Time `db:"used_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (PasswordResetToken) TableName() string { return "password_reset_tokens" }

type EmailVerificationToken struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	UsedAt    *time.Time `db:"used_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (EmailVerificationToken) TableName() string { return "email_verification_tokens" }

// TOTPSettings is the one worth reading closely: store.TOTPSettings does not
// use the field names the obvious table would ("confirmed", "backup_codes").
// Enabled/VerifiedAt/RecoveryCodeHashes/RecoveryCodesUsed are what the type
// actually has, and RecoveryCodeHashes is a []string whose storage is your
// choice -- text[] here, a join table or a JSON column elsewhere.
type TOTPSettings struct {
	ID                 string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID             string     `db:"user_id" sqlb:"type:uuid"`
	SecretEncrypted    []byte     `db:"secret_encrypted" sqlb:"type:bytea"`
	Enabled            bool       `db:"enabled" sqlb:"type:boolean,default"`
	VerifiedAt         *time.Time `db:"verified_at" sqlb:"type:timestamptz"`
	RecoveryCodeHashes []string   `db:"recovery_code_hashes" sqlb:"type:text,default"`
	RecoveryCodesUsed  int        `db:"recovery_codes_used" sqlb:"type:integer,default"`
	CreatedAt          time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt          time.Time  `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (TOTPSettings) TableName() string { return "totp_settings" }

type PendingTwoFactorSession struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string    `db:"user_id" sqlb:"type:uuid"`
	TokenHash string    `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time `db:"expires_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (PendingTwoFactorSession) TableName() string { return "pending_two_factor_sessions" }

type FailedLoginAttempt struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	Email     string    `db:"email" sqlb:"type:text"`
	IPAddress string    `db:"ip_address" sqlb:"type:text,default"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (FailedLoginAttempt) TableName() string { return "failed_login_attempts" }

type WebAuthnChallenge struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	TokenHash string    `db:"token_hash" sqlb:"type:text"`
	UserID    *string   `db:"user_id" sqlb:"type:uuid"`
	Data      []byte    `db:"data" sqlb:"type:bytea"`
	ExpiresAt time.Time `db:"expires_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (WebAuthnChallenge) TableName() string { return "webauthn_challenges" }

// WebAuthnChallenges is separate from UserStores because the
// challenge port belongs to passkey.Stores, not user.Stores -- the passkey
// flow is not part of the user plane.
func WebAuthnChallenges(db sqlb.Executor) store.WebAuthnChallengeStore {
	return sqlbstore.WebAuthnChallengeAdapter[WebAuthnChallenge]{
		Table: sqlbstore.Table[WebAuthnChallenge, store.WebAuthnChallenge]{
			ToRow: func(c store.WebAuthnChallenge) WebAuthnChallenge {
				return WebAuthnChallenge{
					TokenHash: c.TokenHash, UserID: c.UserID,
					Data: c.Data, ExpiresAt: c.ExpiresAt,
				}
			},
			FromRow: func(r WebAuthnChallenge) store.WebAuthnChallenge {
				return store.WebAuthnChallenge{
					ID: r.ID, TokenHash: r.TokenHash, UserID: r.UserID,
					Data: r.Data, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
				}
			},
			GetID:    func(c store.WebAuthnChallenge) string { return c.ID },
			SetID:    func(r WebAuthnChallenge, id string) WebAuthnChallenge { r.ID = id; return r },
			IDColumn: "id",
			// A challenge is written once and destroyed by the only
			// read of it. There is nothing to update.
			ToUpdateColumns: func(store.WebAuthnChallenge) map[string]any { return nil },
		},
		DB:              db,
		TokenHashColumn: "token_hash",
	}
}

// AccountLock is the table with no authit type. LockoutStore needs
// two tables, and only this one -- the set of currently-locked user ids --
// is invisible from store/user.go. Its shape is entirely yours; all authit
// asks is that a user id can be inserted, tested for, and deleted, and that
// the id column is UNIQUE so a repeat lock is idempotent instead of an error.
type AccountLock struct {
	UserID   string    `db:"user_id" sqlb:"type:uuid,pk"`
	LockedAt time.Time `db:"locked_at" sqlb:"type:timestamptz,default"`
}

func (AccountLock) TableName() string { return "account_locks" }

// ---------------------------------------------------------------------------
// Wiring -- every store in user.Stores.
// ---------------------------------------------------------------------------

// UserStores builds the full set of ports user.NewService requires.
// Note the shape each adapter repeats: a Table[R, T] carrying the two-way
// conversion, then the handful of column names the adapter needs beyond the
// primary key in order to filter.
func UserStores(db sqlb.Executor) user.Stores {
	return user.Stores{
		Users: sqlbstore.UserAdapter[User]{
			Table: sqlbstore.Table[User, store.User]{
				ToRow: func(u store.User) User {
					return User{
						Email: u.Email, PasswordHash: u.PasswordHash,
						EmailVerified: u.EmailVerified, EmailVerifiedAt: u.EmailVerifiedAt,
					}
				},
				FromRow: func(r User) store.User {
					return store.User{
						ID: r.ID, Email: r.Email, PasswordHash: r.PasswordHash,
						EmailVerified: r.EmailVerified, EmailVerifiedAt: r.EmailVerifiedAt,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(u store.User) string { return u.ID },
				SetID:    func(r User, id string) User { r.ID = id; return r },
				IDColumn: "id",
				// Every column an update may legitimately change, written as
				// an explicit bound parameter -- including the booleans, which
				// is the whole reason this isn't derived from ToRow.
				ToUpdateColumns: func(u store.User) map[string]any {
					return map[string]any{
						"email": u.Email, "password_hash": u.PasswordHash,
						"email_verified": u.EmailVerified, "email_verified_at": u.EmailVerifiedAt,
						"updated_at": u.UpdatedAt,
					}
				},
			},
			DB:          db,
			EmailColumn: "email",
		},

		RefreshTokens: sqlbstore.RefreshTokenAdapter[RefreshToken]{
			Table: sqlbstore.Table[RefreshToken, store.RefreshToken]{
				ToRow: func(t store.RefreshToken) RefreshToken {
					return RefreshToken{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt,
						RevokedAt: t.RevokedAt, UserAgent: t.UserAgent, IPAddress: t.IPAddress,
					}
				},
				FromRow: func(r RefreshToken) store.RefreshToken {
					return store.RefreshToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
						RevokedAt: r.RevokedAt, UserAgent: r.UserAgent, IPAddress: r.IPAddress,
						CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.RefreshToken) string { return t.ID },
				SetID:    func(r RefreshToken, id string) RefreshToken { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(t store.RefreshToken) map[string]any {
					return map[string]any{"revoked_at": t.RevokedAt, "expires_at": t.ExpiresAt}
				},
			},
			DB:              db,
			UserIDColumn:    "user_id",
			TokenHashColumn: "token_hash",
			RevokedAtColumn: "revoked_at",
			ExpiresAtColumn: "expires_at",
		},

		PasswordResets: sqlbstore.PasswordResetAdapter[PasswordResetToken]{
			Table: sqlbstore.Table[PasswordResetToken, store.PasswordResetToken]{
				ToRow: func(t store.PasswordResetToken) PasswordResetToken {
					return PasswordResetToken{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt,
					}
				},
				FromRow: func(r PasswordResetToken) store.PasswordResetToken {
					return store.PasswordResetToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.PasswordResetToken) string { return t.ID },
				SetID:    func(r PasswordResetToken, id string) PasswordResetToken { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(t store.PasswordResetToken) map[string]any {
					return map[string]any{"used_at": t.UsedAt}
				},
			},
			DB:              db,
			UserIDColumn:    "user_id",
			TokenHashColumn: "token_hash",
			UsedAtColumn:    "used_at",
		},

		EmailVerifications: sqlbstore.EmailVerificationAdapter[EmailVerificationToken]{
			Table: sqlbstore.Table[EmailVerificationToken, store.EmailVerificationToken]{
				ToRow: func(t store.EmailVerificationToken) EmailVerificationToken {
					return EmailVerificationToken{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt,
					}
				},
				FromRow: func(r EmailVerificationToken) store.EmailVerificationToken {
					return store.EmailVerificationToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.EmailVerificationToken) string { return t.ID },
				SetID:    func(r EmailVerificationToken, id string) EmailVerificationToken { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(t store.EmailVerificationToken) map[string]any {
					return map[string]any{"used_at": t.UsedAt}
				},
			},
			DB:              db,
			UserIDColumn:    "user_id",
			TokenHashColumn: "token_hash",
			UsedAtColumn:    "used_at",
		},

		TOTP: sqlbstore.TOTPAdapter[TOTPSettings]{
			Table: sqlbstore.Table[TOTPSettings, store.TOTPSettings]{
				ToRow: func(t store.TOTPSettings) TOTPSettings {
					return TOTPSettings{
						UserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled,
						VerifiedAt: t.VerifiedAt, RecoveryCodeHashes: t.RecoveryCodeHashes,
						RecoveryCodesUsed: t.RecoveryCodesUsed,
					}
				},
				FromRow: func(r TOTPSettings) store.TOTPSettings {
					return store.TOTPSettings{
						ID: r.ID, UserID: r.UserID, SecretEncrypted: r.SecretEncrypted, Enabled: r.Enabled,
						VerifiedAt: r.VerifiedAt, RecoveryCodeHashes: r.RecoveryCodeHashes,
						RecoveryCodesUsed: r.RecoveryCodesUsed, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(t store.TOTPSettings) string { return t.ID },
				SetID:    func(r TOTPSettings, id string) TOTPSettings { r.ID = id; return r },
				IDColumn: "id",
				// enabled is the trap in miniature: confirming enrollment
				// flips it true, disabling 2FA flips it back to false, and an
				// update that can't write an explicit false silently leaves
				// 2FA on.
				ToUpdateColumns: func(t store.TOTPSettings) map[string]any {
					return map[string]any{
						"secret_encrypted": t.SecretEncrypted, "enabled": t.Enabled,
						"verified_at": t.VerifiedAt, "recovery_code_hashes": t.RecoveryCodeHashes,
						"recovery_codes_used": t.RecoveryCodesUsed, "updated_at": t.UpdatedAt,
					}
				},
			},
			DB:           db,
			UserIDColumn: "user_id",
		},

		PendingTwoFactor: sqlbstore.PendingTwoFactorAdapter[PendingTwoFactorSession]{
			Table: sqlbstore.Table[PendingTwoFactorSession, store.PendingTwoFactorSession]{
				ToRow: func(s store.PendingTwoFactorSession) PendingTwoFactorSession {
					return PendingTwoFactorSession{UserID: s.UserID, TokenHash: s.TokenHash, ExpiresAt: s.ExpiresAt}
				},
				FromRow: func(r PendingTwoFactorSession) store.PendingTwoFactorSession {
					return store.PendingTwoFactorSession{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(s store.PendingTwoFactorSession) string { return s.ID },
				SetID:    func(r PendingTwoFactorSession, id string) PendingTwoFactorSession { r.ID = id; return r },
				IDColumn: "id",
				// Nothing about a pending session is ever updated: it is
				// created, read once, and deleted.
				ToUpdateColumns: func(store.PendingTwoFactorSession) map[string]any { return nil },
			},
			DB:              db,
			TokenHashColumn: "token_hash",
		},

		// The two-table one. Attempts fit Table like everything else; the
		// locks side is configured with a row constructor instead, because
		// there is no authit type to convert to or from.
		Lockouts: sqlbstore.LockoutAdapter[FailedLoginAttempt, AccountLock]{
			Attempts: sqlbstore.Table[FailedLoginAttempt, store.FailedLoginAttempt]{
				ToRow: func(f store.FailedLoginAttempt) FailedLoginAttempt {
					// CreatedAt is carried through, unlike the other row
					// types here that let the column default. It is not
					// decoration on this table: the temporary lockout is
					// derived by counting attempts newer than a `since`
					// the caller computes from its own clock, so the row
					// has to carry that same clock's timestamp. Dropping
					// it makes every attempt land at the database's
					// now(), which counts an hour-old failure as recent
					// and turns a 15-minute throttle back into a
					// permanent lock. The `default` tag still applies:
					// sqlb writes DEFAULT for a zero time, so a host that
					// genuinely wants now() can leave it unset.
					return FailedLoginAttempt{Email: f.Email, IPAddress: f.IPAddress, CreatedAt: f.CreatedAt}
				},
				FromRow: func(r FailedLoginAttempt) store.FailedLoginAttempt {
					return store.FailedLoginAttempt{
						ID: r.ID, Email: r.Email, IPAddress: r.IPAddress, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(f store.FailedLoginAttempt) string { return f.ID },
				SetID:    func(r FailedLoginAttempt, id string) FailedLoginAttempt { r.ID = id; return r },
				IDColumn: "id",
				// Attempts are only ever inserted, counted, and deleted.
				ToUpdateColumns: func(store.FailedLoginAttempt) map[string]any { return nil },
			},
			AttemptsDB:             db,
			AttemptEmailColumn:     "email",
			AttemptCreatedAtColumn: "created_at",

			LocksDB:          db,
			NewLockRow:       func(userID string) AccountLock { return AccountLock{UserID: userID} },
			LockUserIDColumn: "user_id",
		},
	}
}
