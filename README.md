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
| `audit` | Opt-in security-event logging (`Logger`, `Event`, `NoopLogger`, `SlogLogger`) — every service's `Config` carries a nil-safe `AuditLogger` |

## Quick start

```go
import (
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
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
import "github.com/mind-vm/authit/authithttp"

claims, err := authithttp.Validate(signer, r)
if err != nil {
	w.WriteHeader(authithttp.StatusFor(err)) // 401 or 500 — body is yours
	return
}
// claims.Subject is the user ID.
```

That's the whole package: `BearerToken`, `Validate`, `StatusFor`. No `http.Handler`, no context key, no opinion about your error envelope. Note that `Validate` accepts an impersonation token (`claims.IsImpersonation()`, minted via `superuser.Impersonate`) — it's genuine, so whether acting-as is allowed on a given route is yours to check. If you want revocation to take effect before token expiry, re-resolve the principal from your own storage and treat claims beyond the subject as hints.

### Ready-made HTTP routes (`authhandlers`)

If you'd rather not hand-write the request/response plumbing, [`authhandlers`](authhandlers) is a separate module (own `go.mod`, like `sqlbstore`) with one mountable route group per plane. It depends on nothing beyond `net/http` and authit itself: no chi, no huma, no OpenAPI generator.

| Constructor | Covers |
|---|---|
| `NewUserHandler` | register, login, refresh, logout, password reset, email verification, 2FA, sessions |
| `NewTeamHandler` | teams, membership, roles, invitations |
| `NewSuperuserHandler` | operator login, operator accounts, impersonation |
| `NewPATHandler` | the caller's own personal access tokens |
| `NewDeviceHandler` | the RFC 8628 device authorization grant |

```go
mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", authhandlers.NewUserHandler(userSvc, signer)))
mux.Handle("/api/", http.StripPrefix("/api", authhandlers.NewTeamHandler(teamSvc, signer,
	authhandlers.RoleAuthorizer{Teams: teamSvc})))
```

They are separate handlers rather than one tree because they don't belong in the same place: the superuser group is an operator surface most deployments should keep off the public internet, and the device group speaks OAuth wire format (form-encoded requests, RFC 6749 error bodies) rather than this package's own JSON conventions.

Protected routes validate the caller's bearer token themselves against the `jwt.Verifier` you pass in — no host middleware or context key required. CORS, rate limiting, and request logging are still yours.

**Two constructors demand an argument authit cannot supply, and panic without it.**

`NewTeamHandler` requires a `TeamAuthorizer`. The `team` package deliberately doesn't check the caller's own role, so a route group that only asked "is this request authenticated" would let any user change any member's role in any team. `RoleAuthorizer` implements the conventional rules (active member may view; active owner or admin may manage), and you can replace it — if your model has a principal that spans teams, `team.Role` has no home for it by design, so write an authorizer that consults your schema first.

`NewDeviceHandler` requires a `DeviceTokenIssuer` and a verification URI. `device.PollDeviceToken` resolves *who* approved a request without minting anything, because what credential a CLI should receive is your decision; and only you know your own verification page's URL. Neither gap has a default that is safe everywhere, so neither gets one.

### Audit logging

Every service's `Config` carries an `AuditLogger audit.Logger` field. Leaving it nil (the zero value) means events are simply not recorded — the same opt-in shape as `user.Config`'s `EmailSender` or `team.Config`'s `Admission`. Logins, lockouts, password/2FA changes, session and token revocation, and impersonation all go through it:

```go
import (
	"log/slog"

	"github.com/mind-vm/authit/audit"
)

userSvc, _ := user.NewService(stores, signer, emailer, user.Config{
	AuditLogger: audit.SlogLogger{Logger: slog.Default()},
})
```

`audit.SlogLogger` covers the common case of wanting these events in application logs (`ResultFailure`/`ResultDenied` log at Warn, everything else at Info). For a compliance trail (SOC2, GDPR, PCI-DSS) or a dedicated event pipeline, implement `audit.Logger` yourself — it's one method, `Log(ctx, audit.Event)`, and takes no error return: delivery guarantees (retry, buffering, an outbox) are the implementation's concern, not authit's, and a logging failure never affects the outcome of the operation being audited.

## Transactions (optional)

Several flows write more than once. `Refresh` revokes the old refresh token and creates the new one; `ResetPassword` sets the password, consumes the token and revokes sessions; `CreateTeam` creates the team and its owner. A crash between two of those writes leaves inconsistent state — a session neither ended nor renewed, a live reset link in an inbox, a team with no owner.

Supply a `store.TxRunner` and those flows become atomic. Leave it nil and they behave exactly as before:

```go
user.Stores{ /* ... */ Tx: myTxRunner }
team.Stores{ /* ... */ Tx: myTxRunner }
superuser.Stores{ /* ... */ Tx: myTxRunner }
```

**The contract is the whole difficulty, so read it before implementing one.** authit calls store methods with the context `RunInTx` hands to your callback — that is its only way to say "this call belongs to that transaction", short of putting a database concept into interfaces whose purpose is not having one. So:

> Every store method called with the context passed to `fn` **must** take part in the transaction. Every store method called with any other context **must not**.

The usual shape is for `RunInTx` to begin a transaction, stash the handle in the context it passes to `fn`, and for each store method to use that handle when present and the pool otherwise. An implementation whose stores ignore the context and always use the pool will compile, pass its own tests, and provide no atomicity at all. If you cannot honour that, leave the field nil — losing atomicity you never had beats believing in atomicity you do not have.

Two deliberate exclusions, both cases where a rollback would undo something that must survive the call returning an error:

- **Refresh-token reuse detection.** It revokes every session and *then* returns an error. Inside the transaction, returning that error would roll back the revocation — the detection would fire, log itself, and undo its own response.
- **Failed-login recording.** The attempt the rate limiter counts must outlive the failure that produced it.

Audit events are emitted after commit, never inside, since a `TxRunner` is permitted to retry.

One thing to know about `team`: `Admission` runs *inside* the transaction, so a seat limit is actually enforceable rather than advisory under concurrency — the count it is given and the member row that follows are consistent. Keep `AdmitMember` fast and free of external I/O; it holds a database transaction open.

`storetest.TxProbe` and `storetest.TxWitness` let you assert which writes your own code puts inside a transaction. They provide no atomicity and are not a substitute for testing a real implementation against a real database.

## Checking your adapter (`storetest`)

authit's whole design rests on you implementing the `store` ports, and nothing in the library can check that you got them right. An adapter that returns a nil pointer instead of `store.ErrNotFound`, or that filters revoked rows out of a lookup, compiles perfectly and fails at runtime — sometimes as a security bug rather than an outage. [`storetest`](storetest) is where those expectations are written down executably:

```go
func TestMyStores(t *testing.T) {
	storetest.RunAll(t, storetest.Stores{
		Users:         func(t *testing.T) store.UserStore { return newUserStore(t) },
		RefreshTokens: func(t *testing.T) store.RefreshTokenStore { return newRefreshTokenStore(t) },
		// ...one factory per port you implement; nil fields are skipped.
	})
}
```

Each factory returns an empty store and may use `t.Cleanup` for teardown. If your schema has foreign keys, supply `Fixtures` so the suite can create the rows they require:

```go
storetest.Stores{
	Fixtures: storetest.Fixtures{EnsureUser: func(t *testing.T, userID string) { /* insert */ }},
	// ...
}
```

Some of what it pins, and why each one is a bug you would otherwise ship:

- **`ErrNotFound` is the only way to say "no such row."** Every service branches on `errors.Is(err, store.ErrNotFound)` and treats anything else as a fault, so a bare `sql.ErrNoRows` turns "this email is free" into a 500.
- **A revoked refresh token is still returned by hash.** Filtering it out looks tidy and silently disables refresh-token reuse detection: a replayed stolen token becomes indistinguishable from an unknown one.
- **`CountRecentFailedLoginAttempts` honours `since`.** The temporary lockout is derived from that count, so ignoring the parameter turns a 15-minute throttle back into a permanent lock.
- **`LockoutStore` really does need its second table**, and `LockAccount` is idempotent — which is why its user-id column must be `UNIQUE`.
- **`RecoveryCodeHashes` round-trips in order, including when empty.** It is a `[]string` with no obvious storage, so it is the field most likely to be dropped — and it fails only once somebody has lost their phone.
- **Scoped operations stay scoped.** Listing one team's members, revoking one user's tokens.

The suite runs against `memstore` on every `go test ./...`, and against `sqlbstore` and the reference `schema.sql` when a Postgres DSN is configured.

## Database schema

authit ships no DDL and no migrations — every package depends only on the `store` interfaces, and your schema is yours. But the required table set shouldn't have to be reverse-engineered from struct definitions one type at a time, so there's a reference:

- **[`schema.sql`](schema.sql)** — a complete, non-binding Postgres table set for all fifteen tables behind every `store` interface, annotated at the places where the columns aren't guessable from the Go types. Rename anything; nothing reads this file.
- **[`sqlbstore/example_test.go`](sqlbstore/example_test.go)** — that same schema wired end to end through `sqlbstore`: a row type and a filled-in `Table[R, T]` for every store in `user.Stores`, ending in a working `user.Service`. It applies `schema.sql` and runs the real flows over it, so the reference schema is checked by the test suite rather than merely asserted.

Three things `store/*.go` will not tell you, and the reason the reference exists:

- `LockoutStore` needs **two** tables, backing two different concepts. The attempts table backs the *temporary* lockout, which authit derives by counting recent failures rather than storing — so it lifts on its own, with nothing to unlock. The second table is the set of *administratively* locked accounts; it has no authit type at all, so nothing in `store/user.go` hints it exists, and nothing inside authit writes to it — `LockAccount`/`UnlockAccount` are there for your own admin surface.
- `store.TOTPSettings` does not use the column names you'd guess: the fields are `Enabled`, `VerifiedAt`, `RecoveryCodeHashes` and `RecoveryCodesUsed` — not `confirmed` and `backup_codes`.
- `RecoveryCodeHashes` is a `[]string` with no obvious storage. `text[]`, a join table and JSON are all fine; the choice is silently yours and it changes your adapter.

## What's deliberately not included

- **HTTP handlers/routing.** authit is a service layer, not a web framework — wire it into your own router (chi, net/http, huma, ...). `authithttp` is the one concession, and it stops at parsing and validating a bearer token.
- **Email delivery.** `user.EmailSender` is an interface; bring your own SMTP/API client.
- **Social/OAuth login, RBAC policy engines.** Out of scope for now; `team.Role` and `store.Member.Role` are plain strings you can extend.

## Passwords

Passwords are hashed with **Argon2id** at OWASP's recommended minimum (19 MiB, 2 iterations, 1 lane) and encoded in the standard PHC string format, so the parameters travel with each hash.

Both the algorithm and the policy are knobs:

```go
user.Config{
	// Defaults to crypto.DefaultHasher() — Argon2id.
	PasswordHasher: authitcrypto.Argon2idHasher{Memory: 64 * 1024, Time: 3},
	// Defaults to crypto.DefaultPasswordPolicy() — length only, 12..1024.
	PasswordValidator: authitcrypto.AllPolicies(
		authitcrypto.LengthPolicy(14, 0),
		authitcrypto.NotEmailPolicy(),
	),
}
```

Two properties are worth relying on:

- **Changing the hasher never invalidates a password.** Every `Hasher` verifies any format authit has written, dispatching on the hash's own prefix, and `Authenticate` re-hashes on the next successful login once the configured hasher reports `NeedsRehash`. An application upgrading from a version that hardcoded bcrypt migrates its whole corpus by doing nothing. `crypto.BcryptHasher` remains available if you need to stay on bcrypt.
- **The policy is never applied at login.** It runs on registration, change and reset only, so tightening it does not lock out the users it was raised to protect. `LengthPolicy` counts runes rather than bytes.

The default policy enforces length and nothing else, deliberately: composition rules ("one uppercase, one digit") measurably reduce entropy by steering people toward predictable substitutions, and a breach-list check needs a corpus this library has no business shipping. A breached-password check is the highest-value thing to add via `AllPolicies`.

Argon2id's memory cost is *per concurrent hash* — at the default, 100 simultaneous logins wants roughly 1.9 GiB. Raise `Memory` only alongside a limit on concurrent authentication.

## Token signing

`jwt.HMACSigner` (HS256) is still there and is the right choice for a single binary. It has one property worth understanding before you deploy a second service: verifying a token needs the same secret that mints one, so **anything that can check an authit token can also forge one** — including an impersonation token, since `Claims.ActorID` is an ordinary field.

For anything beyond one process, sign asymmetrically and hand out the public half:

```go
signer, _ := authitjwt.NewEd25519Signer(privateKey, authitjwt.Defaults{Issuer: "myapp"})
// ...the issuing service uses `signer` exactly as it used an HMACSigner.

// Publish, e.g. at /.well-known/jwks.json:
doc, _ := signer.JWKS()

// A downstream service holds only this. It cannot mint anything.
verifier, _ := authitjwt.NewVerifier(publicKey)
claims, err := authithttp.Validate(verifier, r)
```

`NewRS256Signer` is available where a consumer expects RS256; prefer Ed25519 otherwise — smaller keys and signatures, and no parameters to get wrong. Both refuse RSA keys under 2048 bits.

The interface is split so this is enforced by the type system rather than by convention: `jwt.Verifier` has `Verify`/`Validate` only, `jwt.Signer` embeds it and adds `Sign`/`Generate`. Take a `Verifier` in anything that only checks tokens — `authithttp.Validate` and `authhandlers.NewUserHandler` both do. A `Signer` satisfies `Verifier`, so this narrowing broke no callers.

**Key rotation** works because every asymmetric token carries a `kid` (the RFC 7638 thumbprint of the key, so both sides derive the same id without coordinating). Publish the new key alongside the old, wait for verifiers to pick up the set, switch the signer, then drop the old key once no unexpired token bears it:

```go
verifier, _ := authitjwt.NewVerifier(oldPublicKey, newPublicKey)
```

## Email addresses and sessions

**Addresses are normalised** — trimmed and lower-cased, via `store.NormalizeEmail` — before they reach a store, both when writing and when looking up. So a store can rely on the email column holding exactly that form and compare it with plain equality: no `citext`, no functional index, no case-insensitive collation required. Nothing more aggressive happens; stripping dots or `+tags` is Gmail-specific and would silently merge distinct addresses elsewhere.

If you have rows written before this, normalise the column once before deploying — an address stored with upper-case characters will no longer be found:

```sql
UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));
```

**Refresh tokens rotate, and reuse is treated as a compromise.** `Refresh` revokes the token it consumes, so a legitimate client never sends the same one twice. If a revoked-but-unexpired token is presented, authit revokes *every* refresh token that principal holds and emits `audit.EventUserTokenReuse` — two parties hold a token that should have been spent once, and there is no way to tell which is the attacker, so both are forced back through a password login. The caller still gets `ErrInvalidToken`, identical to what a garbage token returns: a distinct error would confirm to an attacker that a stolen token was genuine.

One accepted false positive: a token revoked by `Logout` and then replayed is indistinguishable from a leak without storing a revocation reason, so it trips the same path. That session was already over, so nothing is lost — but it will appear in your audit trail. Route `EventUserTokenReuse` somewhere a human sees it.

## Brute-force protection

Failed logins are counted per email address over `Config.FailedLoginWindow` (15 minutes by default). Once `Config.MaxFailedLoginAttempts` (5) is reached the address is in *temporary lockout* and `Authenticate` returns `ErrAccountLocked` until the recorded attempts age out. Nothing is stored and nothing has to unlock it.

Two properties are worth knowing, because both were bugs once:

- **The second factor shares the counter.** A correct password does *not* reset it — only a fully completed login does, which means `VerifyTwoFactorLogin` too. An attacker holding a valid password therefore gets `MaxFailedLoginAttempts` guesses at the TOTP code per window, not unlimited guesses, and cannot re-run `Authenticate` to mint a fresh pending session to escape it.
- **Failed logins never lock an account permanently.** `LockoutStore.LockAccount` is not called by authit at all; it is an operator-driven administrative lock, and `Authenticate` honours it, but only your own code sets it.

The lockout is account-scoped by design, so a distributed attack is still caught — but it also means an attacker who knows an address can trigger a *temporary* denial of service against it. Rate limiting (below) is the complementary control.

## Rate limiting

`ratelimit.Limiter` is one method, `Allow(ctx, key) error`. `ratelimit.NewMemory` is an in-process token bucket for a single instance; implement the interface over Redis when you scale horizontally, since N processes otherwise permit N times the rate.

```go
limiter := ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 5, Interval: time.Minute})

user.Config{RateLimiter: limiter}
superuser.Config{RateLimiter: limiter}
device.Config{RateLimiter: limiter} // see below — set this one
```

**This does not replace rate limiting in your HTTP middleware, and cannot.** A service method sees only its arguments: some have an IP, some only an email, none see routes or headers. Per-route, per-IP limiting belongs in middleware. What this port covers is the part middleware cannot reach:

- **Refusing before the password KDF runs.** Argon2id costs 19 MiB and real CPU per attempt, so an unauthenticated flood is a resource-exhaustion vector whether or not any password is ever guessed. `Authenticate` consults the limiter first, before the account lookup and long before the hash comparison.
- **Bounding device user-code guesses.** A user code carries ~34.5 bits so a human can retype it, and RFC 8628 §5.2 rests the security of that on limiting guesses. The lookup happens inside `device`, so only `device` can charge for it. **Set `device.Config.RateLimiter`** — the doc comment on it explains the one trade-off (an attacker who burns the global failure budget also delays legitimate code entry until it refills).
- **Bounding "send this address an email" endpoints**, keyed by address so an unregistered one is treated identically and the limit cannot be used to probe for accounts.

Keys are documented on each `Config`'s `RateLimiter` field. Refusals wrap `ratelimit.ErrRateLimited` (aliased as `user.ErrRateLimited` and friends) and carry a hint via `ratelimit.RetryAfter` for a `Retry-After` header. A limiter's *own* failure — a Redis timeout — is propagated unchanged instead, so "too many attempts" and "the limiter is down" stay distinguishable; they want different status codes.

Leaving the field nil disables the control rather than breaking, the same shape as `AuditLogger`.

## Status

Early scaffold. Core flows are implemented and tested (see `go test ./...`), but this has not yet been used in a production app.

Known gaps to weigh before production use: there are no lifecycle hooks, so extending a flow means wrapping the service method yourself. See [docs/comparison.md](docs/comparison.md) for the full list and the plan.

## License

MIT — see [LICENSE](LICENSE).
