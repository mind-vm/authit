package sqlbstore_test

// This file is the worked example the README's wiring snippet stops short
// of: every store in user.Stores, wired through sqlbstore against the
// table set in authit's reference schema.sql, ending in a working
// user.Service.
//
// Two things it is deliberately not: a package you can import (it is a test
// file, so the row types below are yours to copy and rename), and a claim
// that these column names are required. Nothing in authit reads schema.sql;
// the adapters below are exactly where your names get mapped onto authit's
// fields, which is why every ToRow/FromRow pair is spelled out rather than
// hidden behind a helper.
//
// TestExampleUserStoresAgainstReferenceSchema applies ../schema.sql verbatim
// and runs the real flows over it, so the reference schema is checked by
// this suite rather than merely believed. It skips when no Postgres DSN is
// configured.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/sqlbstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
	"github.com/mind-vm/sqlb"
)

// ---------------------------------------------------------------------------
// Row types -- one per table in schema.sql's user plane.
// ---------------------------------------------------------------------------

type exampleUser struct {
	ID              string     `db:"id" sqlb:"type:uuid,pk,default"`
	Email           string     `db:"email" sqlb:"type:text"`
	PasswordHash    string     `db:"password_hash" sqlb:"type:text"`
	EmailVerified   bool       `db:"email_verified" sqlb:"type:boolean,default"`
	EmailVerifiedAt *time.Time `db:"email_verified_at" sqlb:"type:timestamptz"`
	CreatedAt       time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt       time.Time  `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (exampleUser) TableName() string { return "users" }

type exampleRefreshToken struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	RevokedAt *time.Time `db:"revoked_at" sqlb:"type:timestamptz"`
	UserAgent string     `db:"user_agent" sqlb:"type:text,default"`
	IPAddress string     `db:"ip_address" sqlb:"type:text,default"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (exampleRefreshToken) TableName() string { return "refresh_tokens" }

type examplePasswordReset struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	UsedAt    *time.Time `db:"used_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (examplePasswordReset) TableName() string { return "password_reset_tokens" }

type exampleEmailVerification struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	TokenHash string     `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	UsedAt    *time.Time `db:"used_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (exampleEmailVerification) TableName() string { return "email_verification_tokens" }

// exampleTOTP is the one worth reading closely: store.TOTPSettings does not
// use the field names the obvious table would ("confirmed", "backup_codes").
// Enabled/VerifiedAt/RecoveryCodeHashes/RecoveryCodesUsed are what the type
// actually has, and RecoveryCodeHashes is a []string whose storage is your
// choice -- text[] here, a join table or a JSON column elsewhere.
type exampleTOTP struct {
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

func (exampleTOTP) TableName() string { return "totp_settings" }

type examplePendingTwoFactor struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string    `db:"user_id" sqlb:"type:uuid"`
	TokenHash string    `db:"token_hash" sqlb:"type:text"`
	ExpiresAt time.Time `db:"expires_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (examplePendingTwoFactor) TableName() string { return "pending_two_factor_sessions" }

type exampleFailedLogin struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	Email     string    `db:"email" sqlb:"type:text"`
	IPAddress string    `db:"ip_address" sqlb:"type:text,default"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (exampleFailedLogin) TableName() string { return "failed_login_attempts" }

type exampleWebAuthnChallenge struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	TokenHash string    `db:"token_hash" sqlb:"type:text"`
	UserID    *string   `db:"user_id" sqlb:"type:uuid"`
	Data      []byte    `db:"data" sqlb:"type:bytea"`
	ExpiresAt time.Time `db:"expires_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (exampleWebAuthnChallenge) TableName() string { return "webauthn_challenges" }

// exampleWebAuthnChallenges is separate from exampleUserStores because the
// challenge port belongs to passkey.Stores, not user.Stores -- the passkey
// flow is not part of the user plane.
func exampleWebAuthnChallenges(db sqlb.Executor) store.WebAuthnChallengeStore {
	return sqlbstore.WebAuthnChallengeAdapter[exampleWebAuthnChallenge]{
		Table: sqlbstore.Table[exampleWebAuthnChallenge, store.WebAuthnChallenge]{
			ToRow: func(c store.WebAuthnChallenge) exampleWebAuthnChallenge {
				return exampleWebAuthnChallenge{
					TokenHash: c.TokenHash, UserID: c.UserID,
					Data: c.Data, ExpiresAt: c.ExpiresAt,
				}
			},
			FromRow: func(r exampleWebAuthnChallenge) store.WebAuthnChallenge {
				return store.WebAuthnChallenge{
					ID: r.ID, TokenHash: r.TokenHash, UserID: r.UserID,
					Data: r.Data, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
				}
			},
			GetID:    func(c store.WebAuthnChallenge) string { return c.ID },
			SetID:    func(r exampleWebAuthnChallenge, id string) exampleWebAuthnChallenge { r.ID = id; return r },
			IDColumn: "id",
			// A challenge is written once and destroyed by the only
			// read of it. There is nothing to update.
			ToUpdateColumns: func(store.WebAuthnChallenge) map[string]any { return nil },
		},
		DB:              db,
		TokenHashColumn: "token_hash",
	}
}

// exampleAccountLock is the table with no authit type. LockoutStore needs
// two tables, and only this one -- the set of currently-locked user ids --
// is invisible from store/user.go. Its shape is entirely yours; all authit
// asks is that a user id can be inserted, tested for, and deleted, and that
// the id column is UNIQUE so a repeat lock is idempotent instead of an error.
type exampleAccountLock struct {
	UserID   string    `db:"user_id" sqlb:"type:uuid,pk"`
	LockedAt time.Time `db:"locked_at" sqlb:"type:timestamptz,default"`
}

func (exampleAccountLock) TableName() string { return "account_locks" }

// ---------------------------------------------------------------------------
// Wiring -- every store in user.Stores.
// ---------------------------------------------------------------------------

// exampleUserStores builds the full set of ports user.NewService requires.
// Note the shape each adapter repeats: a Table[R, T] carrying the two-way
// conversion, then the handful of column names the adapter needs beyond the
// primary key in order to filter.
func exampleUserStores(db sqlb.Executor) user.Stores {
	return user.Stores{
		Users: sqlbstore.UserAdapter[exampleUser]{
			Table: sqlbstore.Table[exampleUser, store.User]{
				ToRow: func(u store.User) exampleUser {
					return exampleUser{
						Email: u.Email, PasswordHash: u.PasswordHash,
						EmailVerified: u.EmailVerified, EmailVerifiedAt: u.EmailVerifiedAt,
					}
				},
				FromRow: func(r exampleUser) store.User {
					return store.User{
						ID: r.ID, Email: r.Email, PasswordHash: r.PasswordHash,
						EmailVerified: r.EmailVerified, EmailVerifiedAt: r.EmailVerifiedAt,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(u store.User) string { return u.ID },
				SetID:    func(r exampleUser, id string) exampleUser { r.ID = id; return r },
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

		RefreshTokens: sqlbstore.RefreshTokenAdapter[exampleRefreshToken]{
			Table: sqlbstore.Table[exampleRefreshToken, store.RefreshToken]{
				ToRow: func(t store.RefreshToken) exampleRefreshToken {
					return exampleRefreshToken{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt,
						RevokedAt: t.RevokedAt, UserAgent: t.UserAgent, IPAddress: t.IPAddress,
					}
				},
				FromRow: func(r exampleRefreshToken) store.RefreshToken {
					return store.RefreshToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
						RevokedAt: r.RevokedAt, UserAgent: r.UserAgent, IPAddress: r.IPAddress,
						CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.RefreshToken) string { return t.ID },
				SetID:    func(r exampleRefreshToken, id string) exampleRefreshToken { r.ID = id; return r },
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

		PasswordResets: sqlbstore.PasswordResetAdapter[examplePasswordReset]{
			Table: sqlbstore.Table[examplePasswordReset, store.PasswordResetToken]{
				ToRow: func(t store.PasswordResetToken) examplePasswordReset {
					return examplePasswordReset{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt,
					}
				},
				FromRow: func(r examplePasswordReset) store.PasswordResetToken {
					return store.PasswordResetToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.PasswordResetToken) string { return t.ID },
				SetID:    func(r examplePasswordReset, id string) examplePasswordReset { r.ID = id; return r },
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

		EmailVerifications: sqlbstore.EmailVerificationAdapter[exampleEmailVerification]{
			Table: sqlbstore.Table[exampleEmailVerification, store.EmailVerificationToken]{
				ToRow: func(t store.EmailVerificationToken) exampleEmailVerification {
					return exampleEmailVerification{
						UserID: t.UserID, TokenHash: t.TokenHash, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt,
					}
				},
				FromRow: func(r exampleEmailVerification) store.EmailVerificationToken {
					return store.EmailVerificationToken{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(t store.EmailVerificationToken) string { return t.ID },
				SetID:    func(r exampleEmailVerification, id string) exampleEmailVerification { r.ID = id; return r },
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

		TOTP: sqlbstore.TOTPAdapter[exampleTOTP]{
			Table: sqlbstore.Table[exampleTOTP, store.TOTPSettings]{
				ToRow: func(t store.TOTPSettings) exampleTOTP {
					return exampleTOTP{
						UserID: t.UserID, SecretEncrypted: t.SecretEncrypted, Enabled: t.Enabled,
						VerifiedAt: t.VerifiedAt, RecoveryCodeHashes: t.RecoveryCodeHashes,
						RecoveryCodesUsed: t.RecoveryCodesUsed,
					}
				},
				FromRow: func(r exampleTOTP) store.TOTPSettings {
					return store.TOTPSettings{
						ID: r.ID, UserID: r.UserID, SecretEncrypted: r.SecretEncrypted, Enabled: r.Enabled,
						VerifiedAt: r.VerifiedAt, RecoveryCodeHashes: r.RecoveryCodeHashes,
						RecoveryCodesUsed: r.RecoveryCodesUsed, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(t store.TOTPSettings) string { return t.ID },
				SetID:    func(r exampleTOTP, id string) exampleTOTP { r.ID = id; return r },
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

		PendingTwoFactor: sqlbstore.PendingTwoFactorAdapter[examplePendingTwoFactor]{
			Table: sqlbstore.Table[examplePendingTwoFactor, store.PendingTwoFactorSession]{
				ToRow: func(s store.PendingTwoFactorSession) examplePendingTwoFactor {
					return examplePendingTwoFactor{UserID: s.UserID, TokenHash: s.TokenHash, ExpiresAt: s.ExpiresAt}
				},
				FromRow: func(r examplePendingTwoFactor) store.PendingTwoFactorSession {
					return store.PendingTwoFactorSession{
						ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash,
						ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(s store.PendingTwoFactorSession) string { return s.ID },
				SetID:    func(r examplePendingTwoFactor, id string) examplePendingTwoFactor { r.ID = id; return r },
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
		Lockouts: sqlbstore.LockoutAdapter[exampleFailedLogin, exampleAccountLock]{
			Attempts: sqlbstore.Table[exampleFailedLogin, store.FailedLoginAttempt]{
				ToRow: func(f store.FailedLoginAttempt) exampleFailedLogin {
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
					return exampleFailedLogin{Email: f.Email, IPAddress: f.IPAddress, CreatedAt: f.CreatedAt}
				},
				FromRow: func(r exampleFailedLogin) store.FailedLoginAttempt {
					return store.FailedLoginAttempt{
						ID: r.ID, Email: r.Email, IPAddress: r.IPAddress, CreatedAt: r.CreatedAt,
					}
				},
				GetID:    func(f store.FailedLoginAttempt) string { return f.ID },
				SetID:    func(r exampleFailedLogin, id string) exampleFailedLogin { r.ID = id; return r },
				IDColumn: "id",
				// Attempts are only ever inserted, counted, and deleted.
				ToUpdateColumns: func(store.FailedLoginAttempt) map[string]any { return nil },
			},
			AttemptsDB:             db,
			AttemptEmailColumn:     "email",
			AttemptCreatedAtColumn: "created_at",

			LocksDB:          db,
			NewLockRow:       func(userID string) exampleAccountLock { return exampleAccountLock{UserID: userID} },
			LockUserIDColumn: "user_id",
		},
	}
}

func exampleSigner(t *testing.T) authitjwt.Signer {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-example", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	return signer
}

// TestExampleUserStoresSatisfyUserService needs no database: it checks that
// the wiring above is a complete, correctly-typed set of ports, which is the
// part a reader is most likely to get wrong by omission.
func TestExampleUserStoresSatisfyUserService(t *testing.T) {
	if _, err := user.NewService(exampleUserStores(nil), exampleSigner(t), nil, user.Config{}); err != nil {
		t.Fatalf("the example wiring should satisfy user.NewService: %v", err)
	}
}

// referenceSchemaPool applies ../schema.sql into a throwaway Postgres schema
// and returns an executor scoped to it, so the reference schema is exercised
// under its real table names without colliding with anything in the target
// database.
func referenceSchemaPool(t *testing.T) (sqlb.Executor, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("MYBRAIN_DATABASE_URL")
	if dsn == "" {
		t.Skip("MYBRAIN_DATABASE_URL not set; skipping reference-schema integration test")
		return nil, nil
	}
	ddl, err := os.ReadFile("../schema.sql")
	if err != nil {
		t.Fatalf("reading ../schema.sql: %v", err)
	}

	const schema = "authit_reference_schema_test"
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	// Every table in schema.sql is created and resolved inside this schema.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatalf("dropping stale schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("creating schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if _, err := pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatalf("applying ../schema.sql: %v", err)
	}
	// The raw pool comes back too, so a caller can truncate between
	// subtests and insert fixture rows that foreign keys require.
	return sqlb.New(pool), pool
}

// TestExampleUserStoresAgainstReferenceSchema drives the real user flows
// through the example wiring against ../schema.sql, so a drift between the
// two -- a renamed column, a missing table, a type that won't round-trip --
// fails here rather than in a consumer's port.
func TestExampleUserStoresAgainstReferenceSchema(t *testing.T) {
	db, _ := referenceSchemaPool(t)
	svc, err := user.NewService(exampleUserStores(db), exampleSigner(t), nil, user.Config{
		MaxFailedLoginAttempts: 3,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	// users: insert, read back by email, and a DB-assigned id.
	u, err := svc.Register(ctx, "example@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() {
		t.Fatalf("expected DB-defaulted id/created_at, got %+v", u)
	}

	// The strict default is in force, so login is refused until verified.
	if _, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1"); !errors.Is(err, user.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	// users UPDATE: the boolean must actually reach the column.
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	// refresh_tokens INSERT + failed_login_attempts DELETE on success.
	result, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.Tokens == nil {
		t.Fatal("expected a token pair")
	}

	// refresh_tokens SELECT by hash, UPDATE revoked_at, INSERT replacement.
	rotated, err := svc.Refresh(ctx, result.Tokens.RefreshToken, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// refresh_tokens SELECT by user_id, filtered on revoked_at/expires_at.
	// This runs BEFORE the reuse below, deliberately: replaying a rotated
	// token is treated as a compromise and revokes the whole family, so
	// afterwards there is correctly nothing left to list.
	sessions, err := svc.ListSessions(ctx, u.ID, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("expected exactly one current session, got %+v", sessions)
	}

	// Replaying the token that was already rotated away: refused, and the
	// refusal is indistinguishable from a garbage token.
	if _, err := svc.Refresh(ctx, result.Tokens.RefreshToken, "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatal("expected the rotated-away refresh token to be revoked")
	}

	// refresh_tokens UPDATE revoked_at across every row for the user --
	// the family revocation that reuse triggers. A replayed token means
	// either the old or the new one is in someone else's hands and there
	// is no way to tell which, so both go. Asserting it here is what
	// proves the bulk UPDATE reaches real rows and not just the one.
	sessions, err = svc.ListSessions(ctx, u.ID, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions after reuse: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("reuse must revoke the whole family, still have %+v", sessions)
	}

	// failed_login_attempts INSERT + COUNT, then account_locks INSERT --
	// the table with no authit type, and the one a port is most likely to
	// have missed entirely.
	for range 3 {
		if _, err := svc.Authenticate(ctx, "example@example.com", "wrong-password", "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	}
	if _, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked after 3 failures, got %v", err)
	}
}
