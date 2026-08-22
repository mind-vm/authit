// Package authitschema is authit's table declaration: the single source of
// truth for what authit stores, written in sqlb's schema DSL.
//
// It lives in its own package because the declarations here and the row
// structs generated from them share names — authitschema.User is the table
// declaration, store.User is the row struct. Keeping them apart is what lets
// both be called User.
//
// # Why authit declares rather than abstracts
//
// authit used to define storage-port interfaces and leave the tables to the
// host. That bought two implementations, one of which was a test fake, at the
// cost of seven interfaces, ~40 methods, and six conversion functions per
// store in every host — and the glue turned out to be where the bugs were.
// Auth needs durable storage by definition; there is no plausible authit
// consumer with no database.
//
// The decisive argument is not the glue, though: it is foreign keys. A
// library that owns its own migration sequence cannot be pointed at. Tables in
// a sequence authit owns can carry no foreign key to the host's tables in
// either direction, so a host's `coaches.user_id` referencing authit's `users`
// is a bare UUID enforcing nothing — and "deleting an account takes its coach
// identity with it" stops being expressible. Declaring into the host's
// registry is what makes it a real reference with a real ON DELETE.
//
// # How a host uses it
//
//	reg := schema.NewRegistry()
//	auth := authitschema.Declare(reg)
//
//	var Coach = reg.Table("coaches",
//	    schema.UUIDv7("id").PrimaryKey(),
//	    schema.Ref("user", auth.User).OnDelete(schema.Cascade),
//	    schema.Timestamps(),
//	)
//
// One registry, one migration sequence, and the reference is enforced. See
// Declare for what it does and does not promise about names.
package authitschema

import "github.com/jryannel/sqlb/schema"

// decls is the registry authit builds its own declarations in. It is never
// the registry a host migrates from: Declare copies these table definitions
// into whatever registry the host passes, so the host gets one sequence.
//
// Building them here rather than in the default registry keeps authit's
// tables out of a host that merely imports this package without calling
// Declare.
var decls = schema.NewRegistry()

// id is authit's primary key column: a UUID defaulting to gen_random_uuid().
//
// Deliberately v4 rather than sqlb's conventional UUIDv7. v7's time-ordering
// buys index locality on large, insert-heavy tables, and authit has neither —
// these are small tables reached by point lookups on a hash or an email. What
// v4 buys instead is that gen_random_uuid() is built into Postgres 13 and
// later with no extension and no MinPostgres floor, so authit's tables impose
// no version requirement on a host that has its own.
func id() *schema.Field {
	return schema.UUID("id").PrimaryKey().Default(schema.GenUUIDv4())
}

// tokenHash is the storage for an opaque credential. authit never persists a
// raw token: crypto.GenerateOpaqueToken hands the raw value to the caller
// exactly once and only the SHA-256 hex digest is stored, which is what makes
// a database dump useless for replaying sessions. Unique because every one of
// these is looked up by hash on the hot path.
func tokenHash() *schema.Field {
	return schema.Text("token_hash").Unique()
}

// ---------------------------------------------------------------------------
// The user plane
// ---------------------------------------------------------------------------

// User is a login-capable identity, and nothing else. Profile data belongs in
// the host's own table joined by id — see the package doc on extension.
var User = decls.Table("users",
	id(),
	schema.Text("email").Unique(),
	// The bcrypt digest from crypto.HashPassword. WriteOnly so that if a host
	// ever exposes this table over sqlb's REST layer, the column cannot be
	// read back out of it.
	schema.Text("password_hash").WriteOnly(),
	schema.Bool("email_verified").Default(schema.Value(false)),
	schema.Timestamp("email_verified_at").Nullable(),
	schema.Timestamps(),
).Describe("A login-capable identity. Profile data joins by id.")

// RefreshToken is a server-side session record; it doubles as the list of a
// user's active sessions, which is why it carries a user agent and IP.
var RefreshToken = decls.Table("refresh_tokens",
	id(),
	schema.Ref("user", User).OnDelete(schema.Cascade),
	tokenHash(),
	schema.Timestamp("expires_at"),
	schema.Timestamp("revoked_at").Nullable(),
	schema.Text("user_agent").Default(schema.Value("")),
	schema.Text("ip_address").Default(schema.Value("")),
	schema.Timestamps(),
).
	// ListActiveRefreshTokens filters by user and then by liveness.
	Index("user_id", "revoked_at").
	Describe("A server-side session. Only the token's hash is stored.")

// PasswordResetToken is single-use and time-limited. Expiry is derived from
// expires_at at read time and single-use from used_at, so neither needs a
// sweeper to stay honest.
var PasswordResetToken = decls.Table("password_reset_tokens",
	id(),
	schema.Ref("user", User).OnDelete(schema.Cascade),
	tokenHash(),
	schema.Timestamp("expires_at"),
	schema.Timestamp("used_at").Nullable(),
	schema.Timestamps(),
).
	Index("user_id").
	Describe("A single-use password reset token. Only its hash is stored.")

// EmailVerificationToken proves ownership of an address.
var EmailVerificationToken = decls.Table("email_verification_tokens",
	id(),
	schema.Ref("user", User).OnDelete(schema.Cascade),
	tokenHash(),
	schema.Timestamp("expires_at"),
	schema.Timestamp("used_at").Nullable(),
	schema.Timestamps(),
).
	Index("user_id").
	Describe("A single-use email verification token. Only its hash is stored.")

// TOTPSettings is a user's second factor.
//
// The column names are the ones the flows actually need, and they are worth
// reading rather than guessing: enabled is the on/off switch, verified_at
// records when enrollment was confirmed, and the backup codes are a hashed
// array plus a used counter. recovery_code_hashes is a text[] rather than a
// join table because the codes are read and rewritten as a set, always
// together, and never queried individually.
var TOTPSettings = decls.Table("totp_settings",
	id(),
	// Unique: one enrollment per user, and GetByUserID depends on it.
	schema.Ref("user", User).OnDelete(schema.Cascade).Unique(),
	// AES-256-GCM ciphertext from crypto.EncryptSecret. The key never
	// reaches the database.
	schema.Bytes("secret_encrypted").WriteOnly(),
	schema.Bool("enabled").Default(schema.Value(false)),
	schema.Timestamp("verified_at").Nullable(),
	schema.Text("recovery_code_hashes").Array().Default(schema.Expr("'{}'")).WriteOnly(),
	schema.Int("recovery_codes_used").Default(schema.Value(0)),
	schema.Timestamps(),
).Describe("A user's TOTP enrollment and hashed backup codes.")

// PendingTwoFactorSession is the short-lived token issued after a correct
// password when TOTP is on, exchanged for a real session by presenting a code.
var PendingTwoFactorSession = decls.Table("pending_two_factor_sessions",
	id(),
	schema.Ref("user", User).OnDelete(schema.Cascade).Indexed(),
	tokenHash(),
	schema.Timestamp("expires_at"),
	schema.Timestamps(),
).Describe("A short-lived session awaiting its second factor.")

// FailedLoginAttempt is keyed by email rather than by user, deliberately: the
// lockout check runs before a matching user is confirmed to exist, so that a
// login against an unknown address is indistinguishable from one against a
// known address with a wrong password. That is also why there is no foreign
// key here — the address may belong to nobody.
var FailedLoginAttempt = decls.Table("failed_login_attempts",
	id(),
	schema.Text("email"),
	schema.Text("ip_address").Default(schema.Value("")),
	schema.Timestamps(),
).
	// CountRecentFailedLoginAttempts filters on both together.
	Index("email", "created_at").
	Describe("One failed login, keyed by email so lockout can't leak account existence.")

// AccountLock is the set of currently-locked accounts.
//
// It exists as a table of its own rather than a column on users because
// locking is a set membership, not a property: LockAccount, IsAccountLocked
// and UnlockAccount are insert, exists and delete. The user reference is the
// primary key, which is what makes locking an already-locked account
// idempotent rather than an error.
var AccountLock = decls.Table("account_locks",
	schema.Ref("user", User).OnDelete(schema.Cascade).PrimaryKey(),
	schema.Timestamp("locked_at").Default(schema.Now()),
).Describe("The set of currently locked-out accounts.")

// ---------------------------------------------------------------------------
// The team plane
// ---------------------------------------------------------------------------

// Team is an organization or tenant that users belong to via TeamMember.
var Team = decls.Table("teams",
	id(),
	schema.Text("name"),
	schema.Text("slug").Unique(),
	schema.Ref("owner", User).Indexed(),
	schema.Timestamps(),
).Describe("An organization users belong to via a membership.")

// TeamMember joins a user to a team, carrying the role that governs
// authorization within that team.
//
// The role is per-team, and that is a real limit rather than a gap: an
// identity that spans teams — a platform auditor, a consultant — has no home
// here and belongs in the host's own table joined by user id.
//
// user_id is nullable so a team can track a member before a login exists: an
// invited contact who has not registered yet.
var TeamMember = decls.Table("team_members",
	id(),
	schema.Ref("team", Team).OnDelete(schema.Cascade),
	schema.Ref("user", User).OnDelete(schema.Cascade).Nullable(),
	schema.Text("role"),
	schema.Text("display_name").Default(schema.Value("")),
	schema.Text("email").Default(schema.Value("")),
	schema.Bool("is_active").Default(schema.Value(true)),
	schema.Timestamps(),
).
	// One membership per (team, user). The lookup by both is how a host
	// resolves the caller's own role before authorizing anything.
	UniqueIndex("team_id", "user_id").
	// ListMembershipsByUser drives a multi-team team-selection step.
	Index("user_id").
	Describe("A user's membership of a team, and their role in it.")

// TeamInvitation offers an address a role in a team.
//
// There is deliberately no "expired" status: expiry is derived from
// expires_at at read time and never written back, so no sweeper job is needed
// to keep the column honest.
var TeamInvitation = decls.Table("team_invitations",
	id(),
	schema.Ref("team", Team).OnDelete(schema.Cascade),
	schema.Text("email"),
	tokenHash(),
	schema.Text("role"),
	schema.Enum("status", "pending", "accepted", "revoked").Default(schema.Value("pending")),
	schema.Ref("invited_by", User).Indexed(),
	schema.Timestamp("expires_at"),
	schema.Timestamp("accepted_at").Nullable(),
	schema.Timestamps(),
).
	Index("team_id").
	Describe("An offer for an address to join a team. Only the token's hash is stored.")

// ---------------------------------------------------------------------------
// The superuser plane
// ---------------------------------------------------------------------------

// Superuser is an operator identity, deliberately unrelated to teams and
// roles: it has no organization and no role column. A separate table from
// users rather than a flag on it, so a compromised user-facing registration
// flow has nothing to escalate into.
var Superuser = decls.Table("superusers",
	id(),
	schema.Text("email").Unique(),
	schema.Text("password_hash").WriteOnly(),
	schema.Text("display_name").Default(schema.Value("")),
	schema.Bool("is_active").Default(schema.Value(true)),
	schema.Timestamp("last_login_at").Nullable(),
	schema.Timestamps(),
).Describe("An operator identity, structurally separate from users.")

// created_by is added after the fact because it points at Superuser itself,
// and a var cannot refer to itself in its own initializer.
//
// Nullable because the bootstrap operator was created by nobody, and SetNull
// rather than Cascade because deleting the operator who created an account
// must not delete the account they created.
func init() {
	Superuser.AddField(
		schema.Ref("created_by", Superuser).OnDelete(schema.SetNull).Nullable().Indexed(),
	)
}

// SuperuserRefreshToken is the admin-plane session record. Its own table
// rather than a column on refresh_tokens, so a leaked dump of the user
// session table cannot be replayed as an admin session.
var SuperuserRefreshToken = decls.Table("superuser_refresh_tokens",
	id(),
	schema.Ref("superuser", Superuser).OnDelete(schema.Cascade),
	tokenHash(),
	schema.Timestamp("expires_at"),
	schema.Timestamp("revoked_at").Nullable(),
	schema.Text("user_agent").Default(schema.Value("")),
	schema.Text("ip_address").Default(schema.Value("")),
	schema.Timestamps(),
).
	Index("superuser_id", "revoked_at").
	Describe("An operator session. Kept apart from user sessions on purpose.")

// SuperuserFailedLoginAttempt and SuperuserAccountLock are the admin plane's
// own lockout tables.
//
// They are separate from the user plane's rather than shared, for the same
// reason the session tables are: the two planes are different identity spaces.
// Sharing them was a latent bug that only became visible once the references
// were real — account_locks.user_id points at users(id), and the superuser
// plane was writing superuser ids into it. Sharing the attempts table has a
// quieter version of the same problem: an address that exists as both a user
// and an operator would have had one plane's failures lock the other's account.
var SuperuserFailedLoginAttempt = decls.Table("superuser_failed_login_attempts",
	id(),
	schema.Text("email"),
	schema.Text("ip_address").Default(schema.Value("")),
	schema.Timestamps(),
).
	Index("email", "created_at").
	Describe("One failed operator login, keyed by email.")

// SuperuserAccountLock is the set of currently-locked operator accounts.
var SuperuserAccountLock = decls.Table("superuser_account_locks",
	schema.Ref("superuser", Superuser).OnDelete(schema.Cascade).PrimaryKey(),
	schema.Timestamp("locked_at").Default(schema.Now()),
).Describe("The set of currently locked-out operator accounts.")

// ---------------------------------------------------------------------------
// CLI and non-interactive auth
// ---------------------------------------------------------------------------

// PersonalAccessToken is a long-lived, named, scoped bearer credential a user
// creates for themselves. Unlike a refresh token it is not paired with a
// short-lived access token: the raw value is the credential, checked by hash
// on every request.
var PersonalAccessToken = decls.Table("personal_access_tokens",
	id(),
	schema.Ref("user", User).OnDelete(schema.Cascade),
	schema.Text("name").Default(schema.Value("")),
	tokenHash(),
	// Scope strings are opaque to authit; what they permit is the host's.
	schema.Text("scopes").Array().Default(schema.Expr("'{}'")),
	// Null means it never expires, which is why this is nullable rather than
	// defaulted far into the future.
	schema.Timestamp("expires_at").Nullable(),
	schema.Timestamp("last_used_at").Nullable(),
	schema.Timestamp("revoked_at").Nullable(),
	schema.Timestamps(),
).
	Index("user_id").
	Describe("A named, scoped, long-lived bearer credential for a CLI or script.")

// DeviceAuthorization is one in-flight RFC 8628 device-authorization-grant.
//
// Note the asymmetry between the two codes. device_code is the CLI's poll
// credential and is a secret, so only its hash is stored. user_code is stored
// in the clear: it is short and low-entropy by design, and its security comes
// from the host rate-limiting guesses at the verification endpoint, not from
// the code being unguessable.
var DeviceAuthorization = decls.Table("device_authorizations",
	id(),
	schema.Text("device_code_hash").Unique(),
	schema.Text("user_code").Unique(),
	schema.Text("client_id").Default(schema.Value("")),
	schema.Text("scope").Default(schema.Value("")),
	schema.Enum("status", "pending", "approved", "denied").Default(schema.Value("pending")),
	// Set only once the request is approved.
	schema.Ref("user", User).OnDelete(schema.Cascade).Nullable().Indexed(),
	schema.Timestamp("expires_at"),
	// Deliberately no database default, even though 5 is RFC 8628's
	// recommendation and would be the obvious one to write here. A defaulted
	// column is one sqlb leaves to the database whenever the Go value is zero,
	// and zero is a meaningful interval: a host configuring a sub-second
	// PollInterval truncates to 0, which would silently become 5. The service
	// always computes this value, so nothing needs a default and having one
	// can only overrule the caller.
	schema.Int("interval_seconds"),
	schema.Timestamp("last_polled_at").Nullable(),
	schema.Timestamps(),
).Describe("An in-flight device authorization grant.")
