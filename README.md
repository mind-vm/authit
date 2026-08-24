# authit

A reusable Go library for user authentication, superuser (operator) authentication, and team/organization-based auth — with no assumption about which database you use.

authit was designed by studying two existing implementations (a full-featured but Postgres-locked product auth system, and a modular monorepo's shared auth packages) and combining the best parts: the modular package split of the latter, the feature completeness of the former, plus a storage-port layer neither of them had.

## Design

- **No database assumption.** Every package that touches persistence depends only on interfaces defined in `store`. A host application implements those interfaces against whatever it uses — Postgres, SQLite, DynamoDB, or nothing at all. `memstore` ships a reference in-memory implementation of every interface, so the library is usable and testable out of the box.
- **No social/OAuth login.** Email + password (+ optional TOTP) only, by design, for now.
- **Three independent planes, one shared crypto/JWT layer:**
  - `user` — registration, login, sessions, password reset, email verification, TOTP/2FA.
  - `team` — organizations, membership, roles, invitations.
  - `superuser` — a structurally separate operator identity, kept apart from `user` by JWT audience (not a separate secret), with impersonation.
- **CLI/non-interactive auth is a separate concern from browser sessions.** `pat` (personal access tokens) and `device` (RFC 8628 device-authorization-grant) don't mint JWTs — they resolve *who* is asking, and leave it to the host application to decide what credential to hand back.
- **Authorization is the caller's job.** `team` methods that change roles or remove members do not check the caller's own role — a host application resolves the caller's `Member` (via `GetMemberByUserAndTeam`) and checks it before calling. This keeps authit's authorization model unopinionated about your app's specific rules.
- **Roles are per-team, and only per-team.** A `Role` exists on a `Member`, and a `Member` exists in a `Team`, so `team` cannot express a principal whose identity *spans* teams — a platform auditor, a consultant, a support engineer working across many client organizations. That's deliberate, not a gap: such an identity belongs in your own schema, joined to authit by user id. If you find yourself inventing a team that every privileged user joins, or writing one membership row per team to express a single global capability, you're fighting the model — and both workarounds break the moment that principal must reach a team it holds no membership in. authit answers *who is this*; your model answers *what may they do*.

## Packages

| Package | Purpose |
|---|---|
| `crypto` | Password hashing (bcrypt), opaque token generation/hashing, TOTP, AES-256-GCM secret encryption, ID generation |
| `jwt` | JWT signing/verification (`Signer` interface, HMAC-SHA256 implementation), `Claims` |
| `store` | Storage-port interfaces — the contract a host application implements |
| `memstore` | In-memory implementation of every `store` interface, for tests and quick starts |
| `user` | Registration, login/logout/refresh, sessions, password reset, email verification, TOTP/2FA |
| `team` | Teams, membership, roles, invitations |
| `superuser` | Operator accounts, login/refresh, deactivation, impersonation |
| `pat` | Personal access tokens — named, scoped, optionally-expiring bearer credentials for CLIs/scripts |
| `device` | RFC 8628 OAuth 2.0 Device Authorization Grant — "visit this URL, enter this code" CLI login |
| `authithttp` | The only HTTP wiring authit ships: RFC-correct bearer-token extraction, validation, and 401-vs-500 classification |

## Quick start

```go
import (
	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/memstore"
	"github.com/jryannel/authit/user"
)

signer, _ := authitjwt.NewHMACSigner(jwtSecret, authitjwt.Defaults{Issuer: "myapp"})

stores := user.Stores{
	Users:              memstore.NewUserStore(),       // swap for your own store.UserStore
	RefreshTokens:      memstore.NewRefreshTokenStore(),
	PasswordResets:     memstore.NewPasswordResetStore(),
	EmailVerifications: memstore.NewEmailVerificationStore(),
	TOTP:               memstore.NewTOTPStore(),
	PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
	Lockouts:           memstore.NewLockoutStore(),
}

svc, _ := user.NewService(stores, signer, myEmailSender, user.Config{
	TOTPEncryptionKey: totpKey, // 32 bytes, required if you use 2FA
})

u, err := svc.Register(ctx, "alice@example.com", "correct horse battery staple")
result, err := svc.Authenticate(ctx, "alice@example.com", "password", userAgent, ip)
if result.RequiresTwoFactor {
	result, err = svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, code, userAgent, ip)
}
// result.Tokens.AccessToken / result.Tokens.RefreshToken
```

`team` and `superuser` follow the same shape: define `Stores`, construct with `NewService`, call methods.

### CLI auth (`pat` / `device`)

```go
patSvc, _ := pat.NewService(pat.Stores{Tokens: myTokenStore}, pat.Config{Prefix: "mb_"})
raw, token, err := patSvc.CreateToken(ctx, userID, "laptop", []string{"read", "write"}, nil)
// raw is shown to the user once; only its hash is stored.
resolved, err := patSvc.Resolve(ctx, incomingBearerToken) // on every request

deviceSvc, _ := device.NewService(device.Stores{Authorizations: myDeviceStore}, device.Config{})
auth, err := deviceSvc.StartDeviceAuthorization(ctx, "cli", "read write")
// show auth.UserCode + your own verification URL to the CLI user

// from an authenticated web session, once the user enters the code:
deviceSvc.ApproveDeviceAuthorization(ctx, callerUserID, userCode)

// the CLI polls:
userID, scope, err := deviceSvc.PollDeviceToken(ctx, auth.DeviceCode)
// on device.ErrAuthorizationPending / ErrSlowDown, wait auth.Interval (bumping it on
// ErrSlowDown) and poll again; on success, mint whatever credential you want (a pat
// token, a user session, ...) for userID.
```

### Email verification

By default `Authenticate` refuses an account whose address isn't verified, returning `ErrEmailNotVerified`. That's the right default for self-serve signup, but it isn't the right policy everywhere — an emailed, tokenised B2B invite already proves the address, SSO provisioning arrives pre-verified, and seeded demo/test accounts want it off entirely. So it's a knob, not a law:

```go
user.Config{EmailVerification: user.EmailVerificationOptional} // default is ...Required
```

Relaxing the gate doesn't touch the flag — `User.EmailVerified` is still tracked, so your own features can still depend on it; only login stops doing so.

For the paths where the address really is already proven, mark it directly instead of minting and redeeming a token:

```go
svc.MarkEmailVerified(ctx, u.ID) // seeders, accepted invites, SSO provisioning
```

It's idempotent, and it kills any verification link already sitting in an inbox. Never call it from an unauthenticated path — that's the check `VerifyEmail` exists to perform.

### HTTP: extracting and validating a bearer token

authit is a service layer, not a web framework, with one exception. Pulling a bearer token off a request and validating it is identical in every consumer and quietly security-critical: `strings.TrimPrefix(h, "Bearer ")` turns a malformed header into a *token* rather than a rejection, the scheme is case-insensitive per RFC 7235 so a naive prefix check rejects valid requests, and "no token" and "bad token" are both 401 while "the signer can't verify anything" is a 500. So that one piece is tested here instead of approximated everywhere:

```go
import "github.com/jryannel/authit/authithttp"

claims, err := authithttp.Validate(signer, r)
if err != nil {
	w.WriteHeader(authithttp.StatusFor(err)) // 401 or 500 — body is yours
	return
}
// claims.Subject is the user ID.
```

That's the whole package: `BearerToken`, `Validate`, `StatusFor`. No `http.Handler`, no context key, no opinion about your error envelope. Note that `Validate` accepts an impersonation token (`claims.IsImpersonation()`, minted via `superuser.Impersonate`) — it's genuine, so whether acting-as is allowed on a given route is yours to check. If you want revocation to take effect before token expiry, re-resolve the principal from your own storage and treat claims beyond the subject as hints.

## Database schema

authit ships no DDL and no migrations — every package depends only on the `store` interfaces, and your schema is yours. But the required table set shouldn't have to be reverse-engineered from struct definitions one type at a time, so there's a reference:

- **[`schema.sql`](schema.sql)** — a complete, non-binding Postgres table set for all fifteen tables behind every `store` interface, annotated at the places where the columns aren't guessable from the Go types. Rename anything; nothing reads this file.
- **[`sqlbstore/example_test.go`](sqlbstore/example_test.go)** — that same schema wired end to end through `sqlbstore`: a row type and a filled-in `Table[R, T]` for every store in `user.Stores`, ending in a working `user.Service`. It applies `schema.sql` and runs the real flows over it, so the reference schema is checked by the test suite rather than merely asserted.

Three things `store/*.go` will not tell you, and the reason the reference exists:

- `LockoutStore` needs **two** tables. The second — the set of currently-locked accounts — has no authit type at all, so nothing in `store/user.go` hints it exists. Implement only the attempts table and it compiles cleanly, then fails at runtime.
- `store.TOTPSettings` does not use the column names you'd guess: the fields are `Enabled`, `VerifiedAt`, `RecoveryCodeHashes` and `RecoveryCodesUsed` — not `confirmed` and `backup_codes`.
- `RecoveryCodeHashes` is a `[]string` with no obvious storage. `text[]`, a join table and JSON are all fine; the choice is silently yours and it changes your adapter.

## What's deliberately not included

- **HTTP handlers/routing.** authit is a service layer, not a web framework — wire it into your own router (chi, net/http, huma, ...). `authithttp` is the one concession, and it stops at parsing and validating a bearer token.
- **Email delivery.** `user.EmailSender` is an interface; bring your own SMTP/API client.
- **Social/OAuth login, RBAC policy engines, audit logging.** Out of scope for now; `team.Role` and `store.Member.Role` are plain strings you can extend, and `superuser.Impersonate`'s doc comment notes where a host app should hook in its own audit trail.

## Status

Early scaffold. Core flows are implemented and tested (see `go test ./...`), but this has not yet been used in a production app.

## License

Proprietary — see [LICENSE](LICENSE). This is not open source: it's a
reusable asset licensed to clients per-project via
[CLIENT-LICENSE-TEMPLATE.md](CLIENT-LICENSE-TEMPLATE.md), not for
independent public use.
