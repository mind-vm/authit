# authit

A reusable Go library for user authentication, superuser (operator) authentication, and team/organization-based auth — with no assumption about which database you use.

authit was designed by studying two existing implementations (a full-featured but Postgres-locked product auth system, and a modular monorepo's shared auth packages) and combining the best parts: the modular package split of the latter, the feature completeness of the former, plus a storage-port layer neither of them had.

```sh
go get github.com/mind-vm/authit@latest
```

`make ci` runs what CI runs (gofmt, vet, `sqlc diff`, and the tests, which need
Postgres at `PGTEST_DSN`). Tool versions are pinned in `mise.toml`.

## Design

- **No database assumption.** Every package that touches persistence depends only on interfaces defined in `store`. A host application implements those interfaces against whatever it uses — Postgres, SQLite, DynamoDB, or nothing at all. `memstore` ships a reference in-memory implementation of every interface, so the library is usable and testable out of the box, and `pgstore` and `sqlitestore` ship every port ready-made on Postgres and SQLite, with their own migrations (see [Choosing a store](#choosing-a-store)).
- **Several ways to sign in, one session model.** Email + password with optional TOTP in `user`; magic links and codes in `emaillogin`; passkeys in `passkey`; external identity providers in `oidc`. The last three resolve *who* someone is; the session is `user`'s.
- **Three independent planes, one shared crypto/JWT layer:**
  - `user` — registration, login, sessions (signed JWTs or server-side, see [Sessions](#sessions-signature-check-or-lookup)), password reset, email verification, TOTP/2FA.
  - `team` — organizations, membership, roles, invitations.
  - `superuser` — a structurally separate operator identity, kept apart from `user` by JWT audience (not a separate secret), with impersonation.
- **CLI/non-interactive auth is a separate concern from browser sessions.** `pat` (personal access tokens) and `device` (RFC 8628 device-authorization-grant) don't mint JWTs — they resolve *who* is asking, and leave it to the host application to decide what credential to hand back.
- **Authorization is the caller's job.** `team` methods that change roles or remove members do not check the caller's own role — a host application resolves the caller's `Member` (via `GetMemberByUserAndTeam`) and checks it before calling. This keeps authit's authorization model unopinionated about your app's specific rules.
- **Roles are per-team, and only per-team.** A `Role` exists on a `Member`, and a `Member` exists in a `Team`, so `team` cannot express a principal whose identity *spans* teams — a platform auditor, a consultant, a support engineer working across many client organizations. That's deliberate, not a gap: such an identity belongs in your own schema, joined to authit by user id. If you find yourself inventing a team that every privileged user joins, or writing one membership row per team to express a single global capability, you're fighting the model — and both workarounds break the moment that principal must reach a team it holds no membership in. authit answers *who is this*; your model answers *what may they do*.

## Packages

One module, `github.com/mind-vm/authit`. `authhandlers` and `sqlbstore`, separate modules up to v0.3.0, were removed in v0.4.0; see [What's deliberately not included](#whats-deliberately-not-included).

| Package | Purpose |
|---|---|
| `crypto` | Password hashing (Argon2id by default, bcrypt verified and available), opaque token generation/hashing, TOTP, AES-256-GCM secret encryption, ID generation |
| `jwt` | JWT signing and verification: `Signer` and the narrower `Verifier`, HMAC-SHA256, Ed25519 and RS256 signers, JWKS, `Claims` |
| `store` | Storage-port interfaces — the contract a host application implements |
| `memstore` | In-memory implementation of every `store` interface, for tests and quick starts |
| `pgstore` | Every store port on Postgres, with their own goose migrations (`Migrate`, `New`) |
| `sqlitestore` | The same ports as `pgstore` on SQLite, pure Go, with their own migrations (`Open`) |
| `storetest` | The conformance suite every adapter, yours included, is held to |
| `user` | Registration, login/logout/refresh, sessions, password reset, email verification, TOTP/2FA |
| `team` | Teams, membership, roles, invitations |
| `superuser` | Operator accounts, login/refresh, deactivation, impersonation |
| `pat` | Personal access tokens — named, scoped, optionally-expiring bearer credentials for CLIs/scripts |
| `device` | RFC 8628 OAuth 2.0 Device Authorization Grant — "visit this URL, enter this code" CLI login |
| `pin` | PIN sign-in on a field device that then stays bound with a long-lived, revocable device token |
| `oidc` | Sign-in with an external identity provider (Google, GitHub, your SSO) |
| `passkey` | WebAuthn — passkeys, Touch ID, security keys — as a second factor or a primary one |
| `emaillogin` | Passwordless sign-in: magic links and short email codes |
| `authz` | Optional owner/admin/member policy — the correct role check, written once |
| `ratelimit` | The `Limiter` port, and an in-process token bucket |
| `authithttp` | The only HTTP wiring authit ships: bearer-token extraction and validation, 401-vs-500 classification, refresh cookies, session cookies, a session middleware and a CSRF check |
| `audit` | Opt-in security-event logging (`Logger`, `Event`, `NoopLogger`, `SlogLogger`) — every service's `Config` carries a nil-safe `AuditLogger` |

## Quick start

The smallest real setup: SQLite for storage, and server-side (opaque) sessions, so signing out takes effect on the next request.

```go
import (
	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/sqlitestore"
	"github.com/mind-vm/authit/user"
)

s, err := sqlitestore.Open(ctx, "auth.db") // creates, configures and migrates the file
if err != nil { /* ... */ }
defer s.Close()

// Opaque sessions sign nothing, but the service is built around a signer.
signer, _ := authitjwt.NewHMACSigner(jwtSecret, authitjwt.Defaults{Issuer: "myapp"})

users, err := user.NewService(user.Stores{
	Users: s, RefreshTokens: s, PasswordResets: s, EmailVerifications: s,
	TOTP: s, PendingTwoFactor: s, Lockouts: s, Tx: s,
}, signer, myEmailSender, user.Config{
	SessionMode:       user.SessionModeOpaque,
	RefreshTokenTTL:   7 * 24 * time.Hour, // the session's lifetime in this mode
	TOTPEncryptionKey: totpKey,            // 32 bytes, required if you use 2FA
})

u, err := users.Register(ctx, "alice@example.com", "correct horse battery staple")
result, err := users.Authenticate(ctx, "alice@example.com", password, r.UserAgent(), ip)
if result.RequiresTwoFactor {
	result, err = users.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, code, r.UserAgent(), ip)
}
// result.Tokens.AccessToken is the session token. There is no refresh token in this mode.

// On every protected request:
claims, err := authithttp.SessionAuth(users).Authenticate(r.Context(), r) // reads the bearer token
if err != nil {
	w.WriteHeader(authithttp.StatusFor(err)) // 401, or 500 when the store is down
	return
}
// claims.Subject is the user id.
_ = users.Logout(ctx, sessionToken) // ends it, on the next request
```

Three things to know about that snippet:

- `StatusFor` answers 401 to a revoked or expired opaque session (every plane's `ErrInvalidToken` matches `authithttp.ErrInvalidToken`); a store failure stays a 500.
- Under the default `EmailVerificationRequired`, `Authenticate` refuses an account until its address is verified; see [Email verification](#email-verification).
- In a browser, keep the session token in a cookie, not in JavaScript. [Cookie sessions in a browser](#cookie-sessions-in-a-browser) covers the helpers and middleware for that, and [`examples/sessions`](examples/sessions) is the whole thing runnable.

For tests and demos, every store above can be swapped for its `memstore` counterpart (`memstore.NewUserStore()`, `memstore.NewRefreshTokenStore()`, ...). Leave `SessionMode` at its zero value for the default JWT model: a short access JWT plus a rotating refresh token.

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

### Field devices (`pin`)

For offline field apps an operator sets a short numeric PIN, the phone signs in once, and from then on it holds a device token rather than asking for a password. This is not `device`, which is the RFC 8628 grant a CLI uses.

```go
pinSvc, _ := pin.NewService(pin.Stores{Users: s, PINs: s, Devices: s, Lockouts: s, Tx: s},
	myResolver, // pin.LoginResolver: personnel number or email -> user id
	pin.Config{})

pinSvc.SetPIN(ctx, operatorID, userID, "482913")            // lifts a lock
res, err := pinSvc.SignIn(ctx, login, pin, "iPhone Safari", ua, ip)
// res.Token goes to the device, once; only its hash is stored
u, dev, err := pinSvc.ValidateDevice(ctx, token)           // on every request
pinSvc.RevokeDevice(ctx, operatorID, dev.ID)               // a lost phone
```

- A wrong login and a wrong PIN give the same answer, `pin.ErrInvalidCredentials`, and cost the same hashing work.
- `MaxFailedAttempts` wrong PINs within `LockDuration` (5 in 15 minutes by default) lock the login with `pin.ErrLocked`. An unknown login locks the same way. The failures are kept in the same `LockoutStore` the user plane uses, and each attempt is counted before its PIN is checked, so concurrent guesses share one budget. `Config.RateLimiter` is checked first, per address and per login.
- Device tokens never expire unless `DeviceTokenTTL` is set.
- Coming from your own implementation: bcrypt PIN hashes verify as they are (`ImportPINHash`) and are re-hashed to Argon2id at the next sign-in. Device tokens stored as hex(SHA-256(token)) are exactly what `crypto.HashToken` writes, so `ImportDevice` keeps those devices signed in.
- Not implemented yet: binding a device once through a magic link or OIDC and using the PIN only on that device afterwards. Nothing in the device rows records how a device was bound, so such a mode can be added without changing them.

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

authit is a service layer, not a web framework, with one exception, `authithttp`. Pulling a bearer token off a request and validating it is identical in every consumer and quietly security-critical: `strings.TrimPrefix(h, "Bearer ")` turns a malformed header into a *token* rather than a rejection, the scheme is case-insensitive per RFC 7235 so a naive prefix check rejects valid requests, and "no token" and "bad token" are both 401 while "the signer can't verify anything" is a 500. So that one piece is tested here instead of approximated everywhere:

```go
import "github.com/mind-vm/authit/authithttp"

claims, err := authithttp.Validate(signer, r)
if err != nil {
	w.WriteHeader(authithttp.StatusFor(err)) // 401 or 500 — body is yours
	return
}
// claims.Subject is the user ID.
```

### Sessions: signature check, or lookup

`user.Config.SessionMode` picks the model, and the default is unchanged.

**`SessionModeJWT` (default)** issues a short access JWT plus a long opaque refresh token. Checking the access token is a signature check — no database, no context, no way for it to fail because a store is unreachable. That is the right trade for APIs, CLIs and multi-service fan-out, where a lookup per service per request is the cost nobody wants. The price, stated plainly: revoking a session stops it being refreshable at once, but the access token it already minted stays valid until it expires.

**`SessionModeOpaque`** issues one random token, validated by looking it up on every request, so revocation takes effect immediately. It is a different shape, not a different encoding:

- **There is no refresh token.** The pair exists so the common path avoids a lookup; once every request performs one, a second credential for avoiding lookups is ceremony. `Refresh` returns `ErrWrongSessionMode`, as does `ValidateSession` in JWT mode.
- **Every protected request costs a lookup.** That is the trade, and it is why this is not the default.
- **Authentication can now fail because a database is down** — a 500, not a 401. Wire it with `authithttp.SessionAuth(svc)`, which keeps that distinction; collapsing it reports an outage as a wall of failed logins.

Sessions expire after `RefreshTokenTTL`, extended on use once `SessionSlidingWindow` has passed (a quarter of the lifetime by default; negative disables extension). A threshold, not every request, because the latter is a write per request.

Both modes use the same rows, so `ListSessions`, `RevokeSession` and `RevokeOtherSessions` behave the same in each. The operations that name *your own* session take, in JWT mode, the refresh token, and in opaque mode the session token itself, because that is the session: `Logout(ctx, sessionToken)` ends an opaque session.

### Acting in a team (`SwitchTeam`)

When teams are tenants, a request needs to know which team the user is acting in, and that belongs on the session rather than in a cookie next to it. `user.Service.SwitchTeam(ctx, sessionToken, teamID, ua, ip)` checks that the user is an active member of `teamID`, rotates the session and returns its replacement. `sessionToken` is the refresh token in JWT mode and the session token in opaque mode. The team then appears as `Claims.TeamID`, in the access token in JWT mode and from `ValidateSession` in opaque mode, and it is carried across `Refresh`. An empty `teamID` switches to no team.

```go
users, _ := user.NewService(user.Stores{ /* ... */ Members: s}, signer, nil, cfg)
teams, _ := team.NewService(team.Stores{ /* ... */ Sessions: s}, nil, team.Config{})

pair, err := users.SwitchTeam(ctx, sessionToken, teamID, r.UserAgent(), ip) // ErrNotTeamMember if not an active member
```

Leaving a team ends the sessions acting in it. With `team.Stores.Sessions` set, `SetMemberActive(..., false)` and `RemoveMember` revoke them in the same transaction. With `user.Stores.Members` set, `Refresh` and `ValidateSession` also check the membership again and refuse a session whose membership has ended. In JWT mode, an access token already issued keeps its `TeamID` until it expires, so a route deciding something that matters still checks the membership.

### Who is this request? (`authithttp.Authenticator`)

Anything that guards a route should take an `Authenticator`, not a `jwt.Verifier`, because "is this authenticated" stopped being a pure function once a session could be validated by lookup:

```go
auth := authithttp.VerifierAuth(signer) // JWT mode: a signature check
auth := authithttp.SessionAuth(users)   // opaque mode: a lookup per request
claims, err := auth.Authenticate(r.Context(), r)
```

Write your own to authenticate from a gateway header, an mTLS certificate, or a session your own framework issued — authit does not need to know. Return `ErrNoToken` or `ErrInvalidToken` for "not authenticated" (401) and anything else for "the check could not be performed" (500); `StatusFor` sorts them.

Note that `Validate` accepts an impersonation token (`claims.IsImpersonation()`, minted via `superuser.Impersonate`) — it's genuine, so whether acting-as is allowed on a given route is yours to check. If you want revocation to take effect before token expiry, use opaque sessions, or re-resolve the principal from your own storage and treat claims beyond the subject as hints.

### Refresh-token cookies

`authithttp` is a service-layer library's one concession to HTTP, and refresh cookies are the second thing in it, for the same reason as bearer parsing: identical in every consumer, and easy to get quietly wrong. Left as "the caller's business", a refresh token ends up in `localStorage`, where any XSS anywhere in the app reads a credential that outlives every access token.

```go
opts := authithttp.CookieOptions{
	Path:   "/auth/refresh",              // required — see below
	MaxAge: 7 * 24 * time.Hour,           // match user.Config.RefreshTokenTTL
}
err := authithttp.SetRefreshCookie(w, tokens.RefreshToken, opts)
token, ok := authithttp.RefreshCookie(r, opts)
err = authithttp.ClearRefreshCookie(w, opts)  // on logout
```

`HttpOnly` is always set and is **not configurable** — no use case justifies a refresh token readable from JavaScript. `Secure` and `SameSite=Strict` are the defaults; the only way to drop `Secure` is a field named `Insecure`, so the unsafe choice is the one you have to type.

`Path` is required rather than defaulting to `/`, because scoping it is the point: attached to your refresh route, the cookie rides one request instead of every request the browser makes to your origin.

These functions return an error rather than writing a cookie the browser will throw away — which is the failure mode worth catching, since a browser discards a bad `Set-Cookie` **silently**:

- A `__Host-` or `__Secure-` name whose prefix rules the other attributes break (`__Host-` requires `Path="/"` and no `Domain`, which is a real trade against path scoping).
- A token containing bytes that aren't RFC 6265 cookie-octets. `net/http` strips those rather than failing, so the cookie would be written, stored, and read back shorter than it went in.

`ClearRefreshCookie` takes the same options as `SetRefreshCookie` on purpose: a browser matches a deletion by name, domain *and* path, so clearing with a different path leaves the credential in place while the user appears to have logged out.

### Cookie sessions in a browser

A browser application on `SessionModeOpaque` keeps the session token in an `HttpOnly` cookie. The helpers mirror the refresh-cookie ones, with defaults that suit a credential every page needs: `Path=/`, and `SameSite=Lax`, since `Strict` would show a signed-in user the sign-in page whenever they follow a link to your app from an email.

```go
cookie := authithttp.SessionCookieOptions{MaxAge: 7 * 24 * time.Hour} // = RefreshTokenTTL

// Sign-in handler:
err := authithttp.SetSessionCookie(w, r, result.Tokens.AccessToken, cookie)
http.Redirect(w, r, authithttp.SafeReturnTo(r.FormValue("next"), "/"), http.StatusSeeOther)

// Guarded routes:
requireUser, err := authithttp.SessionMiddleware(users, authithttp.SessionOptions{
	Cookie: cookie, SignInURL: "/signin",
})
csrf, err := authithttp.CSRFProtect(authithttp.CSRFOptions{})
mux.Handle("GET /account", requireUser(accountPage))
http.ListenAndServe(addr, csrf(mux))

// In a handler:
claims, ok := authithttp.ClaimsFrom(r.Context())
```

What the middleware decides, so that every app stops deciding it differently:

- **No session, or an expired or revoked one:** a browser navigation (`GET`/`HEAD`) is redirected with 303 to `SignInURL?next=<path>`; anything else, including `fetch()` and API clients, gets 401. The stale cookie is cleared. `Optional` lets anonymous requests through without claims instead.
- **The session store is down:** 500, never a redirect. Sending signed-in users to the sign-in page during an outage helps nobody.
- **Sliding expiry:** with `MaxAge` set, the cookie is re-issued on use, capped at the session's expiry, so the browser keeps it as long as the server-side session lives.
- **Return-to:** `SafeReturnTo` accepts only a local path, so the sign-in page cannot be used as an open redirect (`//evil.example`, `/\evil.example`, `javascript:`...).

**`Secure` behind a proxy.** The cookie is `Secure` on every response by default, which is already right behind a TLS-terminating proxy. `AllowHTTP` drops it for plain-HTTP requests only, for `http://localhost`; add `TrustForwardedProto` behind a proxy that sets `X-Forwarded-Proto` itself, so one configuration serves both.

**CSRF beyond SameSite.** `CSRFProtect` refuses a state-changing request whose `Origin` (or, failing that, `Referer`) names neither the request's host nor one of `TrustedOrigins`; it compares hosts, not schemes, like `net/http.CrossOriginProtection`, so it works behind a proxy. `DoubleSubmit` adds a token in an `HttpOnly` cookie that forms echo back in `csrf_token` (or scripts in `X-CSRF-Token`); render it with `authithttp.CSRFToken(r)`.

[`examples/sessions`](examples/sessions) wires all of this over `sqlitestore`: register, sign in, a protected page and sign out, with a test that drives it like a browser.

```sh
go run ./examples/sessions -addr 127.0.0.1:8080 -db /tmp/sessions.db
```

### Team authorization (`authz`)

The `team` package deliberately doesn't check the caller's own role, so a route that only asks "is this request authenticated" before calling it lets any user change any member's role in any team. `authz` is the check written once: `authz.DefaultPolicy()` lets an active member view; an active owner or admin manage members and invitations; and **only an owner grant the owner role or act on a member who holds it**. Adjust it with `With`, e.g. `authz.DefaultPolicy().With("auditor", authz.ActionViewTeam)`.

`Policy.Can` takes a `store.Member` rather than a `store.Role` on purpose: an inactive member is authorized for nothing, and that is the half of the check people leave out. The owner rule is its own action because `owner` is the one role authit itself gives meaning to — the last-owner guards in `team` are the only invariant the library enforces about who controls a team, and an admin who could grant it would grant it to themselves. If you write your own check, an unrecognised action must deny.

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

## Hooks

`user.Config.Hooks` is where a flow stops being authit's business and starts being your application's — refusing an address outside your domain, provisioning a workspace, stamping a last-seen timestamp. Every field is nil-safe, and a hook's error reaches the caller unchanged so you can match your own sentinels with `errors.Is`.

```go
user.Config{Hooks: user.Hooks{
	BeforeRegister: func(ctx context.Context, email string) error {
		if !strings.HasSuffix(email, "@corp.example") {
			return ErrNotInvited
		}
		return nil
	},
	AfterRegister: func(ctx context.Context, u store.User) error {
		return provisionWorkspace(ctx, u.ID)
	},
}}
```

**Before and After mean different things.** A `Before` hook is a gate: it runs before anything is written, and an error refuses the operation cleanly. An `After` hook runs once the operation succeeded, and whether its error can still undo anything depends on `Stores.Tx`:

- **With a `TxRunner`**, `After` hooks run inside the same transaction as the operation's writes, so an error rolls the whole thing back — "create the account only if provisioning succeeds" actually holds.
- **Without one**, the writes have already landed. The error still reaches the caller, but the user exists. Treat the hook as a notification.

If an `After` hook guards something that must not half-happen, configure a `TxRunner`. Note that a flow whose only second participant is a hook you did not configure takes no transaction at all — a login is one write, and wrapping it to guard a nil hook would cost a round trip for nothing.

Three placement decisions worth knowing:

- **`BeforeRegister` sees the normalised address** and fires *before* the already-taken check, so it is reached even for a duplicate registration. It is a cheap gate; making it pay for a database round trip first would defeat the point.
- **`BeforeAuthenticate` runs after rate limiting and the lockout** — so it cannot be used to bypass either — and before the password comparison, so refusing there costs no KDF work.
- **`AfterAuthenticate` fires only on a *fully* completed login.** For an account with 2FA, that means after the second factor. A hook stamping last-seen must not fire for a login that stopped half way.

Hooks run in the request's goroutine, and with a `TxRunner` they run inside an open transaction. Slow work — mail, third-party APIs — belongs in a queue the hook writes to, not in the hook.

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

## Choosing a store

`pgstore` and `sqlitestore` implement the same ports, plus `store.TxRunner`, and both pass the same `storetest` run against a real database. Between them they cover every port in `store`.

| Port | Used by | `memstore` | `pgstore` | `sqlitestore` |
|---|---|:-:|:-:|:-:|
| `UserStore`, `RefreshTokenStore`, `PasswordResetStore`, `EmailVerificationStore`, `TOTPStore`, `PendingTwoFactorStore`, `LockoutStore` | `user` | ✓ | ✓ | ✓ |
| `TxRunner` | `user`, `team`, `superuser`, `emaillogin` | — | ✓ | ✓ |
| `SuperuserStore`, `SuperuserRefreshTokenStore`, `SuperuserTwoFactorStore` | `superuser` | ✓ | ✓ | ✓ |
| `AccountStore` | `oidc` | ✓ | ✓ | ✓ |
| `WebAuthnCredentialStore`, `WebAuthnChallengeStore` | `passkey` | ✓ | ✓ | ✓ |
| `EmailLoginStore` | `emaillogin` | ✓ | ✓ | ✓ |
| `TeamStore`, `MemberStore`, `InvitationStore` | `team` | ✓ | ✓ | ✓ |
| `PersonalAccessTokenStore` | `pat` | ✓ | ✓ | ✓ |
| `DeviceAuthorizationStore` | `device` | ✓ | ✓ | ✓ |
| `PINStore`, `BoundDeviceStore` | `pin` | ✓ | ✓ | ✓ |

One `*pgstore.Store` or `*sqlitestore.Store` value satisfies every port it covers, so the same `s` goes into each `Stores` field.

| | Choose it when |
|---|---|
| `pgstore` | You run Postgres already, or more than one process writes. Tables live in an `auth` schema; call `pgstore.Migrate(ctx, pool)` beside your own migrations, then `pgstore.New(pool)`. |
| `sqlitestore` | A CLI, a desktop tool, a single-host service, or tests that should not need Postgres. `sqlitestore.Open(ctx, "auth.db")` creates, configures and migrates the file. |
| `memstore` | Tests and demos where nothing has to outlive the process. |

```go
s, err := sqlitestore.Open(ctx, "auth.db")
if err != nil { /* ... */ }
defer s.Close()
svc, err := user.NewService(user.Stores{
	Users: s, RefreshTokens: s, PasswordResets: s, EmailVerifications: s,
	TOTP: s, PendingTwoFactor: s, Lockouts: s, Tx: s,
}, signer, emailer, cfg)
```

`sqlitestore` uses `modernc.org/sqlite`, a pure-Go driver, so a binary still cross-compiles with only `GOOS` and `GOARCH`. Its tables carry an `auth_` prefix in place of a schema and keep their own goose version table, so an app can keep its own tables in the same file (`s.DB()`). To share a `*sql.DB` you opened yourself, open it with `sqlitestore.DSN(path)` and pass it to `sqlitestore.Migrate` and `sqlitestore.New`.

What SQLite does not match:

- **One writer at a time.** Transactions begin `IMMEDIATE` and a writer waits up to five seconds for the lock. Concurrent writers queue rather than run in parallel, and sustained write load past that wait fails with a busy error where Postgres would have kept going. Several processes on one host can share the file; several hosts cannot.
- **No in-memory database.** `Open(":memory:")` is refused, since `database/sql` would give each connection its own empty database. Use a file under `t.TempDir()`, or `memstore`.
- **Ids and instants are text.** Ids are stored as canonical lower-case uuids, so an upper-case id still finds its row; instants are stored in UTC and come back in UTC, where pgx returns them in the local zone.

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

The suite runs against `memstore` and `sqlitestore` on every `go test ./...`, and against `pgstore` with Postgres at `PGTEST_DSN`.

## Database schema

`pgstore` and `sqlitestore` ship their DDL as goose migrations, embedded in the package. `pgstore.Migrate(ctx, pool)` creates an `auth` schema; `sqlitestore.Open` (or `Migrate`) creates `auth_`-prefixed tables. Each keeps its own goose version table, so it runs beside your own migrations without either seeing the other's history.

For an adapter of your own, [`schema.sql`](schema.sql) is a non-binding Postgres table set for every `store` interface, teams, PATs and devices included, annotated where the columns are not guessable from the Go types. Nothing reads it and no test applies it; the migrations under [`pgstore/migrations`](pgstore/migrations) are the tested DDL for the ports they cover.

Four things `store/*.go` will not tell you, and the reason the reference exists:

- `LockoutStore` needs **two** tables, backing two different concepts. The attempts table backs the *temporary* lockout, which authit derives by counting recent failures rather than storing — so it lifts on its own, with nothing to unlock. The second table is the set of *administratively* locked accounts; it has no authit type at all, so nothing in `store/user.go` hints it exists, and nothing inside authit writes to it — `LockAccount`/`UnlockAccount` are there for your own admin surface.
- `store.TOTPSettings` does not use the column names you'd guess: the fields are `Enabled`, `VerifiedAt`, `RecoveryCodeHashes` and `RecoveryCodesUsed` — not `confirmed` and `backup_codes`.
- `RecoveryCodeHashes` is a `[]string` with no obvious storage. `text[]`, a join table and JSON are all fine (`pgstore` uses `text[]`, `sqlitestore` JSON); the choice is silently yours and it changes your adapter.
- `team_invitations.invited_by_id` holds a **member** id, not a user id — `team.CreateInvitation`'s parameter is `invitedByMemberID`. The column name reads like a user, and pointing the foreign key there makes every invitation fail.

## What's deliberately not included

- **HTTP routes.** authit is a service layer, not a web framework — wire it into your own router (chi, net/http, huma, ...). `authithttp` is the one concession: bearer tokens, cookies, a session middleware and a CSRF check, but no handlers. The `authhandlers` module, which mounted a route group per plane, was removed in v0.4.0, along with `sqlbstore` and `authitctl`.
- **Email delivery.** `user.EmailSender` and `emaillogin.Sender` are interfaces; bring your own SMTP/API client.
- **SAML, RBAC policy engines.** Out of scope; `team.Role` and `store.Member.Role` are plain strings you can extend, and `authz` is a small optional policy, not an engine.

## Signing in without a password

`emaillogin`, `passkey` and `oidc` answer *who is this* and return a `store.User`. Turning that into a session is `user.Service.IssueSession`, so those sign-ins get the same sessions a password login does: the configured `SessionMode`, rotation, `ListSessions`, revocation.

```go
res, err := users.IssueSession(ctx, signedIn.User.ID, user.LoginMethodPasskey, r.UserAgent(), ip)
if res.RequiresTwoFactor { /* as after Authenticate: VerifyTwoFactorLogin */ }
// res.Tokens, as from Authenticate
```

It refuses an account an operator has locked (`ErrAccountLocked`) and, under `EmailVerificationRequired`, an unverified one, unless the method was a magic link or sign-in code, which proved the address just now and so also marks it verified. `BeforeAuthenticate` gates it and `AfterAuthenticate` runs with the session. An account with TOTP enabled still owes its second factor, except after a passkey: with user verification that is two factors already, so pass `LoginMethodPasskey` only when `Result.UserVerified` is true. The audit event names the method. The password throttle is not consulted, so failed passwords cannot keep the owner out of their passkey. Pass only an id the identity package returned: `IssueSession` verifies nothing itself.

## Passwordless email sign-in (`emaillogin`)

Magic links and short sign-in codes. Both prove one thing — that whoever completes them can read mail sent to that address — and both are request/deliver/redeem:

```go
svc, _ := emaillogin.NewService(emaillogin.Stores{Users: users, Tokens: tokens}, mySender, emaillogin.Config{})

_ = svc.RequestMagicLink(ctx, email)          // emails a link
res, err := svc.RedeemMagicLink(ctx, token)   // res.User is the account; see IssueSession

_ = svc.RequestSignInCode(ctx, email)                 // emails 6 digits
res, err := svc.RedeemSignInCode(ctx, email, code)
```

They differ in exactly one way that matters: **entropy**. A magic link carries 256 bits, so guessing is not a threat. A six-digit code carries about twenty, and is only as safe as the limit on how many times it can be guessed. That limit is the whole flow:

- `MaxCodeAttempts` (5 by default) destroys the code, not merely the attempt. A counter that only gated would leave the code live for the next request.
- **Requesting a new code deletes the old one.** Ten live codes make guessing ten times easier, and an attacker can ask for as many as they like.
- A code is hashed **together with the address**, so it is only ever valid for the inbox it was sent to — six digits are not unique, and two accounts can hold the same code at the same moment.
- A code cannot be redeemed through the link path, which does not count guesses.

**Accounts are created on redemption, never on request.** Creating one when the link is asked for would let anybody fill your user table with addresses they do not control, just by typing them into a form. Delivering to the inbox and getting the token back is what proves control — and it also means the address arrives already verified, so there is no second confirmation email asking the user to prove what they just proved.

Request always reports success whether or not the address is registered; `ErrSignUpDisabled` surfaces at redemption, where only the inbox owner sees it. Every failure mode — wrong, expired, used, exhausted — is one `ErrInvalidToken`, because distinguishing them tells an attacker whether the code they tried was ever real.

## Passkeys (`passkey`)

`passkey` adds WebAuthn, both as a second factor behind a password and as a primary credential that replaces one.

```go
svc, _ := passkey.NewService(passkey.Stores{
	Users: users, Credentials: creds, Challenges: challenges,
}, passkey.Config{
	RPDisplayName: "Example Inc",
	RPID:          "example.com",
	RPOrigins:     []string{"https://example.com"},
})

// Registration, for a user you have already authenticated:
opts, session, _ := svc.BeginRegistration(ctx, userID)   // send opts; store session (a handle)
cred, err := svc.FinishRegistration(ctx, userID, "MacBook Touch ID", session, r)

// Usernameless login — no email typed, no password:
opts, session, _ := svc.BeginDiscoverableLogin(ctx)
res, err := svc.FinishDiscoverableLogin(ctx, session, r)
// res.User is the account; user.Service.IssueSession turns it into a session.
```

**The distinction that decides whether this is one factor or two is user verification.** A passkey proves possession of a device. It carries a *second* factor only when the authenticator asks for a PIN or biometric before signing — so `Config.UserVerification` defaults to `VerificationRequired`, and `Result.UserVerified` reports what actually happened in *this* assertion. Relax it only for a passkey used strictly behind a password, and know that doing so makes a passkey-only login single-factor: anyone holding an unlocked device is the user.

**A signature counter that does not advance is evidence the private key exists in more than one place.** `Config.OnClone` defaults to `CloneReject` — refuse the login and flag the credential. The flag is recorded even when the login is refused, or the next attempt would look like the first. `CloneFlag` allows the login and still records; choose it knowing some authenticators report a counter of zero forever and so never trigger this at all.

`RPID` is your registrable domain, and a credential is bound to it permanently — change it and every passkey your users hold stops working, with no migration. `RPOrigins` must be non-empty; an empty list would allow every origin, removing the check that stops another site from driving the ceremony.

**`Stores.Challenges` is required, and it is what makes an assertion unreplayable.** A ceremony spans two requests, so the challenge has to survive in between — and it is what the signature is checked against. `Session` is a 32-byte handle to a row in `store.WebAuthnChallengeStore`; `Finish` redeems it exactly once, so presenting the same assertion twice fails the second time.

It used to be the state itself, handed to you to store. That is why this is required rather than optional: a challenge that can be redeemed twice is an assertion that can be replayed, and the signature counter is not a backstop, because a credential synced across devices cannot keep a coherent one — iCloud Keychain and Google Password Manager passkeys report zero forever. Consuming the challenge is the only thing standing between a captured request and a repeatable sign-in.

The one obligation on your adapter: **consuming must be atomic.** Delete and return in one statement (`DELETE … RETURNING`), or make the delete's affected-row count decide who won. A read that decides, with the delete after it, lets two concurrent callers both finish the same ceremony — which is the replay this exists to stop. `storetest.RunWebAuthnChallengeStore` has a case for exactly this; run it against your real database, where it means something.

`Remove` refuses to take away the last thing an account can be reached with.

**Not verified:** attestation against the FIDO Metadata Service. That answers "is this authenticator model one I trust", which matters for enterprises enforcing a hardware policy and is irrelevant to almost everyone else. Registration records what the authenticator supplied and does not judge it.

## Social sign-in (`oidc`)

`oidc` adds "sign in with Google/GitHub/your SSO" on top of authit's own accounts. It runs the OAuth 2.0 authorization code flow with PKCE and state, then asks the provider who signed in via its userinfo endpoint over TLS.

```go
svc, _ := oidc.NewService(oidc.Stores{Users: users, Accounts: accounts},
	[]oidc.Provider{oidc.Google(clientID, clientSecret)}, oidc.Config{})

// Redirect the browser; store auth.State and auth.CodeVerifier for the callback.
auth, _ := svc.Begin(ctx, "google", "https://app.example.com/callback")

// On the callback:
res, err := svc.Complete(ctx, "google", "https://app.example.com/callback", oidc.Callback{
	Code: r.FormValue("code"), State: r.FormValue("state"),
	ExpectedState: storedState, CodeVerifier: storedVerifier,
})
// res.User is the authit account; user.Service.IssueSession turns it into a session.
```

**Read `oidc.LinkingPolicy` before configuring this.** Whether a social sign-in may attach to an account that already exists with the same email is *the* security decision in social login, and it has a deliberately inconvenient default:

- `LinkingManual` (the zero value) never links automatically. An unknown provider identity whose email matches an existing account is refused with `ErrAccountNotLinked`; the user signs in by the means they already have and calls `Link` deliberately. Safe regardless of which providers you enable.
- `LinkingVerifiedEmail` links when the provider *claims* it verified the address — and is only as good as that claim. Don't use it with a provider users can register at freely.

The attack: someone who can make a provider assert an address they don't own signs in, gets silently linked to the victim's account, and is now the victim. Every "sign in with X" takeover works this way.

Three more things it does deliberately:

- **No ID token verification.** Verifying one properly means fetching the provider's JWKS, caching it, handling rotation, and getting issuer/audience/expiry/nonce all right. A direct TLS call to userinfo establishes the same fact with the same trust, works for providers that are OAuth 2.0 but not OIDC (GitHub), and has no signature checking to get wrong. The cost is one round trip per sign-in. If you need ID-token verification specifically, this package isn't it.
- **Provider tokens are not stored** unless you set `ProviderTokenKey`, and are AES-256-GCM encrypted when they are. A credential you don't keep can't leak.
- **State and PKCE verifier are handed back to you**, not stored here. They belong to one browser for one minute; a short-lived `HttpOnly` cookie is the natural home, and keeping them would mean another port and a cleanup problem.

Social accounts are created with no password. An empty stored hash verifies nothing — `crypto`'s dispatching `Verify` recognises no algorithm in `""` — so such an account is reachable only through a linked provider until its owner sets a password. `Unlink` refuses to remove the last thing a user can sign in with.

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

The interface is split so this is enforced by the type system rather than by convention: `jwt.Verifier` has `Verify`/`Validate` only, `jwt.Signer` embeds it and adds `Sign`/`Generate`. Take a `Verifier` in anything that only checks tokens — `authithttp.Validate` and `authithttp.VerifierAuth` both do. A `Signer` satisfies `Verifier`, so this narrowing broke no callers.

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

Single use holds under concurrency too. `Refresh` reads the token before it holds anything, so several requests presenting one token all pass that check; the rotation then consumes the token with `ConsumeRefreshToken`, a compare-and-set that exactly one caller wins. The others presented a token somebody else just spent, and get the reuse response above. An adapter must implement `ConsumeRefreshToken` (and `ConsumeSuperuserRefreshToken`) as one atomic statement, `UPDATE … WHERE id = ? AND revoked_at IS NULL` and a look at rows affected, never as a read followed by a write; `storetest` races sixteen callers to check it. The cost is that two tabs refreshing one session at the same instant end that session, as a late replay already did.

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

**Not yet used in production.** Everything below is what can honestly be said instead of that.

### What is verified, and how

`make ci` — gofmt, `go vet`, `sqlc diff` and `go test ./...` with Postgres at `PGTEST_DSN` — is clean. That is table stakes; the part worth stating is which storage implementations have run against a real database.

`storetest` is the conformance suite every store is held to. `memstore` runs all **21** ports on every `go test`, and `pgstore` (against Postgres) and `sqlitestore` (against a SQLite file) run all **21** as well. Both also run the `user`, `team`, `pat` and `device` flows over their `TxRunner`:

> users, refresh tokens, password resets, email verifications, TOTP, pending two-factor sessions, lockouts, teams, members, invitations, personal access tokens, device authorizations, linked accounts (OIDC), WebAuthn credentials, WebAuthn challenges, email-login tokens, PINs, bound devices, superusers, superuser refresh tokens, superuser two-factor.

Teams, PATs, device authorization, the active team per session and `pin` are the newest parts and have the shortest track record; treat them accordingly.

That distinction is not pedantry. The fake and a database have disagreed before, each time in the database's favour: a dropped timestamp that silently restored a permanent lockout; a malformed id that produced 500 instead of 404; a non-atomic read-then-delete that `memstore` let through as a rare race while Postgres failed it every time; and refresh tokens that every concurrent caller could spend (fixed in v0.6.0 with `ConsumeRefreshToken`). **A green in-memory run is weak evidence.**

### What review found

Three independent passes over this work — one security, two code review — found **six** issues, all fixed and written up as S4.1–S4.6 in [docs/comparison.md](docs/comparison.md) (a historical document; it describes the v0.3.0 layout). The largest was a passkey account takeover. Two were found by code review *after* the security pass had signed off, which is the honest argument for the second pair of eyes rather than the first.

### Known gaps

- **Lifecycle hooks are `user`-plane only.** `team`, `superuser`, `pat` and `device` have none.
- **No HTTP routes.** Since v0.4.0 every flow is wired by the host; `authithttp.SessionMiddleware` covers guarding routes, not the sign-in, OIDC or passkey ceremonies themselves.
- **No MySQL.** `pgstore` and `sqlitestore` cover Postgres and SQLite; there is no MySQL adapter, DDL or conformance run.
- **`PendingTwoFactorStore`'s single-use property depends on the optional `TxRunner`.** Leave `Tx` nil and two concurrent requests can spend one pending-2FA token. The WebAuthn challenge store was given an atomic `Consume` for exactly this reason; this port has not been.
- No SAML. No FIDO Metadata Service attestation verification.

[docs/comparison.md](docs/comparison.md) carries the original plan, what was built for each item, and the decisions that changed along the way.

## License

MIT — see [LICENSE](LICENSE).
