# authit

A reusable Go library for user authentication, superuser (operator) authentication, and team/organization-based auth, built on [sqlb](https://github.com/jryannel/sqlb) and Postgres.

authit was designed by studying two existing implementations (a full-featured but Postgres-locked product auth system, and a modular monorepo's shared auth packages) and combining the best parts: the modular package split of the latter with the feature completeness of the former.

## Design

- **authit declares its tables into your registry.** It does not own a migration sequence and it does not hide storage behind interfaces. `authitschema.Declare(reg)` contributes authit's tables to the registry your application already migrates, and hands you back the `*schema.TableDef`s so your own tables can point real foreign keys at them.
- **Three independent planes, one shared crypto/JWT layer:**
  - `user` — registration, login, sessions, password reset, email verification, TOTP/2FA.
  - `team` — organizations, membership, roles, invitations.
  - `superuser` — a structurally separate operator identity, kept apart from `user` by JWT audience (not a separate secret), with impersonation.
- **No social/OAuth login.** Email + password (+ optional TOTP) only, by design, for now.
- **CLI/non-interactive auth is a separate concern from browser sessions.** `pat` (personal access tokens) and `device` (RFC 8628 device-authorization-grant) don't mint JWTs — they resolve *who* is asking, and leave it to the host application to decide what credential to hand back.
- **Authorization is the caller's job.** `team` methods that change roles or remove members do not check the caller's own role — a host application resolves the caller's membership (via `GetMemberByUserAndTeam`) and checks it before calling.
- **Roles are per-team, and only per-team.** A `Role` exists on a member, and a member exists in a team, so `team` cannot express a principal whose identity *spans* teams — a platform auditor, a consultant, a support engineer. That's deliberate: such an identity belongs in your own table, joined to authit by user id. Now that authit's tables are in your registry, that join is a real foreign key.

## Why a direct sqlb dependency

authit used to define seven storage-port interfaces (~40 methods), ship an in-memory implementation for tests, and offer a `sqlbstore` bridge module. It doesn't any more. Three reasons, in increasing order of weight:

**The glue was where the bugs were.** Every host wrote a row type plus `ToRow`, `FromRow`, `GetID`, `SetID`, `IDColumn` and `ToUpdateColumns` — six functions per store, seven times over — and the mistakes that surfaced were in that translation, not in authit's logic. sqlb generates typed columns and typed updates, so `store.UserCols.Email.Eq(...)` and `UpdateUser().SetEmailVerified(true)` make a wrong column name a compile error instead of a runtime surprise.

**A storage abstraction with one real implementation is cost without benefit.** It bought exactly two implementations, one of which was a test fake. Auth needs durable storage by definition; there is no plausible authit consumer with no database.

**And the decisive one: foreign keys.** A library that owns its own migration sequence cannot be pointed at, because the two sequences apply independently and nothing orders them. Every reference across the boundary was a bare UUID enforcing nothing — so "deleting an account takes its coach identity with it" was not expressible, at any level of glue quality. That one isn't a matter of taste.

The honest cost is that the test suite now needs a real Postgres. That turned out to be a net gain: the things authit most needs to be right about — counting failed logins over a window, expiring a token, a unique index refusing a second signup under contention, an `ON DELETE` cascading — are exactly where a hand-written fake's behaviour drifts from the database.

## Packages

| Package | Purpose |
|---|---|
| `authitschema` | authit's table declaration, and `Declare(reg)` — the entry point a host wires |
| `store` | Generated row types and typed columns (`sqlb generate`; do not edit) |
| `crypto` | Password hashing (bcrypt), opaque token generation/hashing, TOTP, AES-256-GCM secret encryption |
| `jwt` | JWT signing/verification (`Signer` interface, HMAC-SHA256 implementation), `Claims` |
| `user` | Registration, login/logout/refresh, sessions, password reset, email verification, TOTP/2FA |
| `team` | Teams, membership, roles, invitations |
| `superuser` | Operator accounts, login/refresh, deactivation, impersonation |
| `pat` | Personal access tokens — named, scoped, optionally-expiring bearer credentials for CLIs/scripts |
| `device` | RFC 8628 OAuth 2.0 Device Authorization Grant — "visit this URL, enter this code" CLI login |
| `authithttp` | The only HTTP wiring authit ships: RFC-correct bearer-token extraction, validation, and 401-vs-500 classification |

## Quick start

### 1. Compose the schema

```go
import (
	"github.com/jryannel/authit/authitschema"
	"github.com/jryannel/sqlb/schema"
)

var Registry = schema.NewRegistry()

// authit's tables join your registry, and Auth carries them back so your own
// tables can reference them.
var Auth = authitschema.Declare(Registry)

var Coach = Registry.Table("coaches",
	schema.UUIDv7("id").PrimaryKey(),
	// A real foreign key into authit's users: deleting the account takes the
	// coach identity with it.
	schema.Ref("user", Auth.User).OnDelete(schema.Cascade).Unique(),
	schema.Timestamps(),
)
```

Your existing `sqlb generate` / `sqlb migrate` run now covers authit's tables too — one registry, one migration sequence, `ON DELETE` chosen per relationship.

### 2. Wire the services

```go
import (
	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/user"
	"github.com/jryannel/sqlb"
)

db := sqlb.New(pool)
signer, _ := authitjwt.NewHMACSigner(jwtSecret, authitjwt.Defaults{Issuer: "myapp"})

svc, _ := user.NewService(db, signer, myEmailSender, user.Config{
	TOTPEncryptionKey: totpKey, // 32 bytes, required if you use 2FA
})

u, err := svc.Register(ctx, "alice@example.com", "correct horse battery staple")
result, err := svc.Authenticate(ctx, "alice@example.com", "password", userAgent, ip)
if result.RequiresTwoFactor {
	result, err = svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, code, userAgent, ip)
}
// result.Tokens.AccessToken / result.Tokens.RefreshToken
```

`team`, `superuser`, `pat` and `device` follow the same shape: `NewService(db, ...)`, then call methods.

Every constructor takes `*sqlb.DB` rather than the narrower `sqlb.Executor`, because several flows write more than one row and must do so atomically — rotating a refresh token revokes one and issues another; resetting a password consumes a token, rewrites the hash and revokes every session. `WithTx` joins an outer transaction rather than nesting, so if you already have one open, pass its tx-scoped `*sqlb.DB` and authit's writes land inside it.

### Email verification

By default `Authenticate` refuses an account whose address isn't verified, returning `ErrEmailNotVerified`. That's right for self-serve signup and wrong elsewhere — an emailed, tokenised B2B invite already proves the address, SSO provisioning arrives pre-verified, and seeded demo accounts want it off entirely. So it's a knob:

```go
user.Config{EmailVerification: user.EmailVerificationOptional} // default is ...Required
```

Relaxing the gate doesn't touch the flag — `User.EmailVerified` is still tracked, so your own features can still depend on it; only login stops doing so.

For paths where the address really is already proven, mark it directly instead of minting and redeeming a token:

```go
svc.MarkEmailVerified(ctx, u.ID) // seeders, accepted invites, SSO provisioning
```

It's idempotent, and it kills any verification link already sitting in an inbox. Never call it from an unauthenticated path — that's the check `VerifyEmail` exists to perform.

### CLI auth (`pat` / `device`)

```go
patSvc, _ := pat.NewService(db, pat.Config{Prefix: "mb_"})
raw, token, err := patSvc.CreateToken(ctx, userID, "laptop", []string{"read", "write"}, nil)
// raw is shown to the user once; only its hash is stored.
resolved, err := patSvc.Resolve(ctx, incomingBearerToken) // on every request

deviceSvc, _ := device.NewService(db, device.Config{})
auth, err := deviceSvc.StartDeviceAuthorization(ctx, "cli", "read write")
// show auth.UserCode + your own verification URL to the CLI user

// from an authenticated web session, once the user enters the code:
deviceSvc.ApproveDeviceAuthorization(ctx, callerUserID, userCode)

// the CLI polls:
userID, scope, err := deviceSvc.PollDeviceToken(ctx, auth.DeviceCode)
// on device.ErrAuthorizationPending / ErrSlowDown, wait auth.Interval (bumping it on
// ErrSlowDown) and poll again; on success, mint whatever credential you want.
```

### HTTP: extracting and validating a bearer token

authit is a service layer, not a web framework, with one exception. Pulling a bearer token off a request and validating it is identical in every consumer and quietly security-critical: `strings.TrimPrefix(h, "Bearer ")` turns a malformed header into a *token* rather than a rejection, the scheme is case-insensitive per RFC 7235 so a naive prefix check rejects valid requests, and "no token" and "bad token" are both 401 while "the signer can't verify anything" is a 500.

```go
claims, err := authithttp.Validate(signer, r)
if err != nil {
	w.WriteHeader(authithttp.StatusFor(err)) // 401 or 500 — body is yours
	return
}
// claims.Subject is the user ID.
```

That's the whole package: `BearerToken`, `Validate`, `StatusFor`. No `http.Handler`, no context key, no opinion about your error envelope. Note that `Validate` accepts an impersonation token (`claims.IsImpersonation()`, minted via `superuser.Impersonate`) — it's genuine, so whether acting-as is allowed on a given route is yours to check.

## Extending authit's tables

You can't add columns to them. Join your own table by user id instead — which is now a real foreign key rather than a convention. authit's `users` row is a credential and nothing more; everything about who someone *is* belongs in your own vertical.

That also means authit owns the name `users`. A host that already has a table by that name has a collision to resolve rather than a prefix to set: authit keeps its own names even in a `schema.NewModule` registry, because the generated row structs carry a fixed `TableName` and a name the host could vary would desynchronise them from the migration.

## Tests

authit's tests need a real Postgres. There is no in-memory mode, and a missing DSN is a hard failure rather than a skip — "no database, so everything passed" turns a gate into a decoration.

```bash
docker compose up -d
export AUTHIT_TEST_POSTGRES=postgres://postgres:authit@127.0.0.1:5459/postgres
go test ./...
```

Each test gets a database of its own, created and dropped around it, with authit's declared schema applied through the same `migrate.Diff` path a host's migration generation uses — so a declaration that can't be turned into DDL fails here rather than in a consumer's first migration.

## Regenerating `store/`

`store/` is generated from `authitschema`. After changing a declaration:

```bash
go generate ./authitschema
```

## What's deliberately not included

- **Migrations.** authit contributes a declaration, not a sequence. Yours applies it.
- **HTTP handlers/routing.** Wire it into your own router. `authithttp` is the one concession, and it stops at parsing and validating a bearer token.
- **Email delivery.** `user.EmailSender` is an interface; bring your own SMTP/API client.
- **Social/OAuth login, RBAC policy engines, audit logging.** Out of scope for now; roles are plain strings you can extend, and `superuser.Impersonate`'s doc comment notes where a host app should hook in its own audit trail.

## Status

Early. Core flows are implemented and tested against real Postgres (`go test ./...`), but this has not yet been used in a production app.

## License

Proprietary — see [LICENSE](LICENSE). This is not open source: it's a
reusable asset licensed to clients per-project via
[CLIENT-LICENSE-TEMPLATE.md](CLIENT-LICENSE-TEMPLATE.md), not for
independent public use.
