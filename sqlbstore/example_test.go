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
	"github.com/mind-vm/authit/team"
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
					return exampleFailedLogin{Email: f.Email, IPAddress: f.IPAddress}
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
func referenceSchemaPool(t *testing.T) sqlb.Executor {
	t.Helper()
	dsn := os.Getenv("MYBRAIN_DATABASE_URL")
	if dsn == "" {
		t.Skip("MYBRAIN_DATABASE_URL not set; skipping reference-schema integration test")
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
	return sqlb.New(pool)
}

// TestExampleUserStoresAgainstReferenceSchema drives the real user flows
// through the example wiring against ../schema.sql, so a drift between the
// two -- a renamed column, a missing table, a type that won't round-trip --
// fails here rather than in a consumer's port.
func TestExampleUserStoresAgainstReferenceSchema(t *testing.T) {
	db := referenceSchemaPool(t)
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
	if _, err := svc.Refresh(ctx, result.Tokens.RefreshToken, "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatal("expected the rotated-away refresh token to be revoked")
	}

	// refresh_tokens SELECT by user_id, filtered on revoked_at/expires_at.
	sessions, err := svc.ListSessions(ctx, u.ID, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("expected exactly one current session, got %+v", sessions)
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

// ---------------------------------------------------------------------------
// The team plane, against the same reference schema.
// ---------------------------------------------------------------------------

// exampleTeam / exampleMember / exampleInvitation mirror schema.sql's team
// plane. Note exampleInvitation.InvitedByID: it holds a MEMBER id, because
// team.CreateInvitation's parameter is invitedByMemberID. schema.sql pointed
// that foreign key at users until this test was written, which made every
// invitation fail against the reference schema.

type exampleTeam struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	Name      string    `db:"name" sqlb:"type:text"`
	Slug      string    `db:"slug" sqlb:"type:text"`
	OwnerID   string    `db:"owner_id" sqlb:"type:uuid"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt time.Time `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (exampleTeam) TableName() string { return "teams" }

type exampleMember struct {
	ID          string    `db:"id" sqlb:"type:uuid,pk,default"`
	TeamID      string    `db:"team_id" sqlb:"type:uuid"`
	UserID      *string   `db:"user_id" sqlb:"type:uuid"`
	Role        string    `db:"role" sqlb:"type:text"`
	DisplayName string    `db:"display_name" sqlb:"type:text,default"`
	Email       string    `db:"email" sqlb:"type:text,default"`
	IsActive    bool      `db:"is_active" sqlb:"type:boolean,default"`
	CreatedAt   time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt   time.Time `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (exampleMember) TableName() string { return "team_members" }

type exampleInvitation struct {
	ID          string     `db:"id" sqlb:"type:uuid,pk,default"`
	TeamID      string     `db:"team_id" sqlb:"type:uuid"`
	Email       string     `db:"email" sqlb:"type:text"`
	TokenHash   string     `db:"token_hash" sqlb:"type:text"`
	Role        string     `db:"role" sqlb:"type:text"`
	Status      string     `db:"status" sqlb:"type:text,default"`
	InvitedByID string     `db:"invited_by_id" sqlb:"type:uuid"`
	ExpiresAt   time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	AcceptedAt  *time.Time `db:"accepted_at" sqlb:"type:timestamptz"`
	CreatedAt   time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt   time.Time  `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (exampleInvitation) TableName() string { return "team_invitations" }

func exampleTeamStores(db sqlb.Executor) team.Stores {
	return team.Stores{
		Teams: sqlbstore.TeamAdapter[exampleTeam]{
			Table: sqlbstore.Table[exampleTeam, store.Team]{
				ToRow: func(t store.Team) exampleTeam {
					return exampleTeam{Name: t.Name, Slug: t.Slug, OwnerID: t.OwnerID}
				},
				FromRow: func(r exampleTeam) store.Team {
					return store.Team{
						ID: r.ID, Name: r.Name, Slug: r.Slug, OwnerID: r.OwnerID,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(t store.Team) string { return t.ID },
				SetID:    func(r exampleTeam, id string) exampleTeam { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(t store.Team) map[string]any {
					return map[string]any{"name": t.Name, "slug": t.Slug, "updated_at": t.UpdatedAt}
				},
			},
			DB:         db,
			SlugColumn: "slug",
		},
		Members: sqlbstore.MemberAdapter[exampleMember]{
			Table: sqlbstore.Table[exampleMember, store.Member]{
				ToRow: func(m store.Member) exampleMember {
					return exampleMember{
						TeamID: m.TeamID, UserID: m.UserID, Role: string(m.Role),
						DisplayName: m.DisplayName, Email: m.Email, IsActive: m.IsActive,
					}
				},
				FromRow: func(r exampleMember) store.Member {
					return store.Member{
						ID: r.ID, TeamID: r.TeamID, UserID: r.UserID, Role: store.Role(r.Role),
						DisplayName: r.DisplayName, Email: r.Email, IsActive: r.IsActive,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(m store.Member) string { return m.ID },
				SetID:    func(r exampleMember, id string) exampleMember { r.ID = id; return r },
				IDColumn: "id",
				// is_active again: a DEFAULT true column an update must be
				// able to write an explicit false to.
				ToUpdateColumns: func(m store.Member) map[string]any {
					return map[string]any{
						"role": string(m.Role), "display_name": m.DisplayName,
						"email": m.Email, "is_active": m.IsActive, "updated_at": m.UpdatedAt,
					}
				},
			},
			DB:           db,
			TeamIDColumn: "team_id",
			UserIDColumn: "user_id",
		},
		Invitations: sqlbstore.InvitationAdapter[exampleInvitation]{
			Table: sqlbstore.Table[exampleInvitation, store.Invitation]{
				ToRow: func(i store.Invitation) exampleInvitation {
					return exampleInvitation{
						TeamID: i.TeamID, Email: i.Email, TokenHash: i.TokenHash,
						Role: string(i.Role), Status: string(i.Status),
						InvitedByID: i.InvitedByID, ExpiresAt: i.ExpiresAt, AcceptedAt: i.AcceptedAt,
					}
				},
				FromRow: func(r exampleInvitation) store.Invitation {
					return store.Invitation{
						ID: r.ID, TeamID: r.TeamID, Email: r.Email, TokenHash: r.TokenHash,
						Role: store.Role(r.Role), Status: store.InvitationStatus(r.Status),
						InvitedByID: r.InvitedByID, ExpiresAt: r.ExpiresAt, AcceptedAt: r.AcceptedAt,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(i store.Invitation) string { return i.ID },
				SetID:    func(r exampleInvitation, id string) exampleInvitation { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(i store.Invitation) map[string]any {
					return map[string]any{
						"status": string(i.Status), "accepted_at": i.AcceptedAt,
						"role": string(i.Role), "updated_at": i.UpdatedAt,
					}
				},
			},
			DB:              db,
			TeamIDColumn:    "team_id",
			TokenHashColumn: "token_hash",
		},
	}
}

// TestExampleTeamStoresSatisfyTeamService needs no database, like its user
// counterpart: it checks the port set is complete and correctly typed.
func TestExampleTeamStoresSatisfyTeamService(t *testing.T) {
	if _, err := team.NewService(exampleTeamStores(nil), nil, team.Config{}); err != nil {
		t.Fatalf("the example wiring should satisfy team.NewService: %v", err)
	}
}

// TestExampleTeamStoresAgainstReferenceSchema runs the real team flows against
// schema.sql, so the reference file is checked for the team plane rather than
// merely asserted — which is how invited_by_id came to point at the wrong
// table and stay there.
func TestExampleTeamStoresAgainstReferenceSchema(t *testing.T) {
	db := referenceSchemaPool(t)
	ctx := context.Background()

	userSvc, err := user.NewService(exampleUserStores(db), exampleSigner(t), nil, user.Config{})
	if err != nil {
		t.Fatalf("user.NewService: %v", err)
	}
	teamSvc, err := team.NewService(exampleTeamStores(db), nil, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}

	owner, err := userSvc.Register(ctx, "owner@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register(owner): %v", err)
	}
	invitee, err := userSvc.Register(ctx, "invitee@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register(invitee): %v", err)
	}

	// teams INSERT, then team_members INSERT pointing at the id CreateTeam
	// generated — the pair that fails whenever Create substitutes an id.
	tm, err := teamSvc.CreateTeam(ctx, "Acme", "acme", owner.ID, "Owner", owner.Email)
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	members, err := teamSvc.ListMembersByTeam(ctx, tm.ID)
	if err != nil {
		t.Fatalf("ListMembersByTeam: %v", err)
	}
	if len(members) != 1 || members[0].Role != store.RoleOwner {
		t.Fatalf("expected exactly one owner member, got %+v", members)
	}

	// team_invitations INSERT — invited_by_id is a member id, and the
	// constraint has to agree.
	raw, inv, err := teamSvc.CreateInvitation(ctx, tm.ID, members[0].ID, invitee.Email, store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.InvitedByID != members[0].ID {
		t.Fatalf("InvitedByID = %q, want the inviting member %q", inv.InvitedByID, members[0].ID)
	}

	// team_invitations SELECT by hash + UPDATE status, team_members INSERT.
	joined, err := teamSvc.AcceptInvitation(ctx, raw, invitee.ID, invitee.Email, "Invitee")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if joined.TeamID != tm.ID {
		t.Fatalf("joined team %q, want %q", joined.TeamID, tm.ID)
	}

	// team_members UPDATE: is_active false must actually reach the column.
	if err := teamSvc.SetMemberActive(ctx, joined.ID, false); err != nil {
		t.Fatalf("SetMemberActive: %v", err)
	}
	got, err := teamSvc.GetMember(ctx, joined.ID)
	if err != nil {
		t.Fatalf("GetMember: %v", err)
	}
	if got.IsActive {
		t.Error("is_active is still true; the update reverted it to the column default")
	}
}
