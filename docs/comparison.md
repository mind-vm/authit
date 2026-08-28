# authit vs. better-auth vs. goauth

A positioning and gap analysis, and a prioritised plan for what to change in authit.

Comparison points were taken from the [better-auth docs](https://www.better-auth.com/docs) and
[grokify/goauth](https://github.com/grokify/goauth) as of August 2026, and from authit at commit
`8d73c84`.

---

## 1. They are not the same kind of thing

The language difference is the least interesting one. The three projects sit at three different
layers, and only one of them is even arguably a competitor.

| | **goauth** | **better-auth** | **authit** |
|---|---|---|---|
| Category | OAuth **client** toolkit | Full-stack auth **framework** | Auth **service layer** |
| Answers | "How do I call Slack's API as this user?" | "How do I ship login for my app?" | "How do I verify who this is, against my own database?" |
| Owns your DB schema | no (no schema at all) | **yes** — 4 core tables + per-plugin tables, with migrations | no — 15 tables, but *you* write the DDL |
| Owns your HTTP routes | no | **yes** — one catch-all handler | partially — `authhandlers`, user plane only |
| Owns your frontend | no | **yes** — typed client SDK, cookie handling | no |
| Session model | n/a | DB-backed opaque cookie | stateless JWT + opaque refresh row |
| Extension model | add a provider config | plugins (endpoints + schema + hooks) | Go packages + interfaces |

### goauth is not a competitor at all

`goauth` normalises credentials for **outbound** calls: it turns a JSON config into an authenticated
`*http.Client` for 40+ providers. It has no users table, no sessions, no password hashing, no
registration. It is the thing you would use *inside* an app that authit protects, not instead of it.

The only place the two ever meet: if authit ever grows social login, something has to perform the
provider handshake. That job belongs to `golang.org/x/oauth2` plus a small provider-endpoint table —
not to goauth, which carries 40+ service-specific packages and a SCIM normalisation layer you would
not use.

**Do not treat goauth as a reference architecture or a dependency.** Different problem.

### better-auth *is* the real comparison

better-auth is what authit would be if it decided to own the whole stack. Understanding the
differences below is mostly a question of deciding how much of that stack authit *wants*.

---

## 2. The seven differences that actually matter

### 2.1 Who owns the database

**better-auth** ships four core tables (`user`, `session`, `account`, `verification`), adapters for
Kysely / Drizzle / Prisma / MongoDB, and a CLI (`migrate`, `generate`) that diffs your database and
adds missing columns. Plugins declare their own tables and they get created too. You can rename
tables and columns, add typed `additionalFields`, and point sessions at Redis via secondary storage.

**authit** ships no DDL and no migrations. Every package depends only on the `store` interfaces
(`store/user.go`, `store/team.go`, `store/pat.go`, `store/device.go`, `store/superuser.go`), and a
host implements roughly a dozen of them. `memstore` and `sqlbstore` are reference implementations
and `schema.sql` is a non-binding sketch.

This is authit's single strongest design decision and its single highest adoption cost. It is
strictly better when you have an existing schema, an existing query builder, or a database
better-auth has no adapter for. It is strictly worse for a greenfield app, where better-auth is
running in ten minutes and authit asks for a day of adapter work before the first login.

Two concrete consequences worth fixing (see §4):

- **No transaction boundary.** The `store` ports are per-entity CRUD with no `Tx` concept anywhere in
  the codebase. `Refresh` revokes the old token and then creates a new one as two separate writes; a
  crash in between logs the user out. `team.AcceptInvitation` creates a member and then marks the
  invitation accepted. Neither is atomic and there is no way for an implementer to make it so.
- **No conformance suite.** Nothing in the repo lets a host verify its adapter is correct. `memstore`
  and `sqlbstore` each re-implement their own tests. An adapter that gets `GetUserByEmail` case
  sensitivity or `ErrNotFound` semantics wrong compiles fine and fails in production.

### 2.2 Session model — the biggest behavioural difference

**better-auth**: an opaque `session_token` cookie maps to a `session` row. Every request is a lookup,
so **revocation is immediate**. Sessions slide (`expiresIn` refreshed once `updateAge` is reached),
sensitive endpoints require a *fresh* session (`freshAge`, default 1 day), and there is an opt-in
signed-cookie cache that trades immediate revocation for fewer queries — with the staleness window
documented as an explicit choice.

**authit**: a 15-minute HS256 access JWT plus a 7-day opaque refresh row. Nothing is looked up when
an access token is validated. The README is honest about the consequence: revocation does not take
effect until the access token expires unless you re-resolve the principal yourself.

Neither is wrong; they optimise for different shapes. authit's model is the right one for APIs,
CLIs, and multi-service fan-out, where a per-request database round trip per service is unacceptable.
better-auth's is the right one for a classic web app where "sign out everywhere, now" is a product
requirement.

What authit is missing is not the model — it is the **option**. There is no way to get
revoke-immediately semantics without abandoning the library's token issuance entirely.

Related gaps in the same area:

- **Refresh rotation without reuse detection.** `Refresh` does rotate (`user/register_login.go:165`
  revokes the old token). But replaying an already-revoked token just returns `ErrInvalidToken` — it
  does not revoke the whole token family, which is what OAuth 2.0 Security BCP calls for. A stolen
  refresh token used once by an attacker is currently indistinguishable from a race.
- **No cookie helper.** `authithttp` stops at bearer parsing. The refresh token — a 7-day bearer
  credential — is handed to the caller as a string with no guidance, which is exactly the situation
  in which hosts put it in `localStorage`.

### 2.3 Extension model

A better-auth plugin is a single object that can contribute endpoints, database tables, before/after
hooks, middleware, rate-limit rules, and request/response handlers — and its client half infers
types from the server half, so `/my-plugin/hello-world` becomes `client.myPlugin.helloWorld()` with
no hand-written types.

authit has three extension seams total: `user.EmailSender`, `team.Admission`, and `audit.Logger`.
There is **no hook on any flow**. You cannot run code before `Register` to reject a disposable email
domain, or after `Authenticate` to touch a `last_seen_at` column, without wrapping every service
method yourself. Adding a new flow (magic link, say) means a new package, a new store interface, and
a fork of `authhandlers`.

Go cannot and should not reproduce better-auth's typed plugin registry — TypeScript's structural
inference is doing most of that work, and the Go equivalent degrades into `map[string]any` and
reflection. But hooks are cheap and would close most of the practical gap. See §4.

### 2.4 What you actually receive

better-auth hands you a mounted handler, a typed browser client, a migration CLI, and an OpenAPI
plugin. The plumbing is not your problem.

authit hands you services, `authithttp` (bearer extraction, ~3 functions), and `authhandlers` — a
plain `*http.ServeMux` covering the **user plane only**. `team`, `superuser`, `pat`, and `device`
have no routes. Every consumer writes that plumbing again, and the `device` flow in particular has
enough RFC 8628 detail (polling intervals, `slow_down`, error codes) that hand-rolling it per app is
where bugs will live.

This is the highest-leverage gap for adoption, and it does not compromise any of authit's design
principles: `authhandlers` is already a separate module, so shipping more of it costs core users
nothing.

### 2.5 Authorization

better-auth's organization plugin has a real access-control system: statements over resources,
predefined and custom roles, `hasPermission`, per-organization roles stored at runtime
(`dynamicAccessControl`), teams nested inside organizations, and an active organization carried on
the session.

authit's `team` package deliberately does not: `Role` is a string, and the package documentation
argues at length that authorization belongs to the host. That argument is good — the failure mode it
describes (inventing a team every privileged user joins) is real, and better-auth's dynamic AC lets
you build exactly that mess.

But "authz is yours" and "here is a correct owner/admin/member check you can use" are not in
conflict. Right now every consumer re-writes the same three-line role check before every `team`
mutation, and that check — not the storage — is the part people get wrong.

### 2.6 Feature breadth

| | better-auth | authit |
|---|---|---|
| Email + password | ✅ | ✅ |
| TOTP 2FA + recovery codes | ✅ | ✅ |
| Sessions, list/revoke | ✅ | ✅ |
| Password reset, email verification | ✅ | ✅ |
| Teams / organizations / invites | ✅ (plugin) | ✅ |
| API keys | ✅ (plugin) | ✅ (`pat`) |
| Device authorization (RFC 8628) | ✅ (plugin) | ✅ (`device`) |
| Admin / operator plane | ✅ (plugin, role on `user`) | ✅ (`superuser`, structurally separate) |
| Impersonation | ✅ | ✅ |
| Audit logging | partial (hooks) | ✅ (`audit`) |
| **Social / OAuth login** | ✅ | ❌ (explicitly out of scope) |
| **OIDC / SSO / SAML** | ✅ (plugins) | ❌ |
| **Passkeys / WebAuthn** | ✅ (plugin) | ❌ |
| **Magic link / email OTP** | ✅ (plugins) | ❌ |
| **Built-in rate limiting** | ✅ (per-path rules) | ✅ (port + in-memory bucket) *(was lockout only)* |
| **Migrations / schema CLI** | ✅ | ❌ (reference `schema.sql`) |
| **Typed client SDK** | ✅ | ❌ (out of scope, correctly) |
| **Access-control model** | ✅ | ❌ (by design; `authhandlers.TeamAuthorizer` at the HTTP edge) |
| **Pluggable password hashing** | ✅ (scrypt default) | ✅ (argon2id default) |
| **Password policy** | ✅ (length) | ✅ (composable validators) |
| Storage-port architecture | ❌ (adapters, but its schema) | ✅ |

### 2.7 Crypto and hardening posture

This is where the concrete defects are, and where the gap is not a design choice.

| | better-auth | authit |
|---|---|---|
| Password KDF | scrypt by default, `hash`/`verify` fully pluggable | argon2id by default, `crypto.Hasher` pluggable *(was bcrypt, hardcoded)* |
| Password policy | configurable min/max length | composable validators, length by default *(was none)* |
| Email normalisation | handled | **none** — `Alice@x.com` and `alice@x.com` become two accounts, or collide, depending on your store's collation |
| Rate limiting | built in, per-path rules | `ratelimit.Limiter` port *(was none)* |
| Brute-force response | rate limit | account lock (see below) |
| Token signing | HS256, RS256, EdDSA, JWKS endpoint | HS256, RS256, EdDSA, JWKS + verify-only keys *(was HS256 only)* |

Six of these are worth calling out precisely, because they are bugs rather than missing features.
They are listed worst-first.

> **Status:** every defect below is now **fixed** — (a), (b), (c), (f) by T0.1–T0.3, (d) by T0.8, and
> (e)'s documentation half by T0.8; only (e)'s rate limiter remains, and it depends on T1.4. The
> password KDF and policy rows above are closed by T0.4/T0.5. They are described below in the
> present tense as they were found, because the reasoning is what justifies the fix and the shape of
> the defect is what the regression tests pin. (d) and (e) are still open.

**(a) The second factor has no brute-force protection at all.** This is the most serious issue in the
codebase. `Authenticate` clears the failed-attempt counter as soon as the *password* is correct
(`user/register_login.go:86`), which happens **before** the 2FA branch. `VerifyTwoFactorLogin`
(`user/twofactor.go:206`) then never calls `recordFailedLogin` — an invalid code produces an audit
event and nothing else. Verified by grep: `user/twofactor.go` does not reference `Lockouts` at all.

The consequence is that an attacker holding a valid password gets *unlimited* guesses at the second
factor. `crypto.ValidateTOTPCode` delegates to `totp.Validate` with the library default skew of 1, so
roughly 3 of 10^6 codes are valid at any instant; the pending session lives 5 minutes and a fresh one
can be minted on demand by re-running `Authenticate`, which resets the counter again. With no
external rate limiting in front of it, TOTP here is a speed bump, not a second factor.

**(b) Backup codes carry 32 bits of entropy.** `crypto.GenerateBackupCodes` reads 4 bytes and hex-
encodes them (`crypto/totp.go:30`). Combined with (a) — unlimited attempts — a recovery code is
directly brute-forceable, and a recovery code is a *full* bypass of the second factor. 8 bytes
(64 bits) should be the floor for a standalone credential.

**(c) The account lock is permanent and remotely triggerable.** `recordFailedLogin`
(`user/register_login.go:130`) counts failures **by email address** and calls
`LockoutStore.LockAccount` after `MaxFailedLoginAttempts` (default 5) within `FailedLoginWindow`.
`LockAccount` has no expiry parameter and `UnlockAccount` is **never called anywhere in the
library** — verified by grep; only the two `ClearFailedLoginAttempts` call sites exist. So anyone who
knows a user's email address can permanently lock that account with five wrong passwords, and only
manual operator intervention restores it. `store.FailedLoginAttempt` already carries `IPAddress`,
which is unused for anything.

Note that (a) and (c) are the same missing control pointing in opposite directions: the password step
is rate-limited so aggressively that it is a denial-of-service vector, and the 2FA step is not
rate-limited at all.

**(d) HS256-only means every validator can forge.** `jwt.Signer` is an interface, but `HMACSigner` is
the only implementation, and validating an authit token requires the same secret that mints it. In a
single binary that is fine. The moment a second service needs to validate a token, that service can
also issue one for any user — including an impersonation token, since `Claims.ActorID` is just a
field.

**(e) The device flow documents a control it does not ship.** `crypto/usercode.go` states plainly
that for the 8-character user code "the security property comes from rate-limiting guesses at the
verification endpoint, not from the code's entropy alone." authit provides no rate limiter, no
attempt cap on `pendingByUserCode`, and no `authhandlers` route group for `device` — so nothing in
the library or its docs tells a host that it must supply that control, and there is no seam through
which to supply it. Either ship the limiter or make the requirement loud at the API surface.

**(f) The stated timing property is not held.** `checkLockoutAndFetchUser` documents that "lockout can
be checked before a matching user is even confirmed to exist (this avoids leaking account existence
through timing/behavior)" — but the implementation calls `GetUserByEmail` first and returns early on
`ErrNotFound`, skipping `IsAccountLocked` entirely. Unknown emails therefore take a measurably
different path. Either fix the code or fix the comment; right now the comment asserts a security
property the code does not provide.

**Minor:** `consumeBackupCode` (`user/twofactor.go:171`) compares hashes with `==` rather than
`subtle.ConstantTimeCompare`, and `pat.Resolve` issues a full `UpdatePersonalAccessToken` write on
every single request to bump `LastUsedAt` — a per-request write on the hot path of a credential built
for automated traffic. Neither is urgent; both are cheap to fix.

---

## 3. Where authit is genuinely the better design

Worth stating, because the list above is one-sided and the plan in §4 should not erode these.

- **Storage ports beat adapters** when you have an existing database. better-auth's flexibility stops
  at renaming its columns; authit's stops nowhere.
- **The superuser plane is structurally separate.** better-auth's admin plugin is a role on the same
  `user` row, so compromising an admin's password compromises the admin. authit keeps operators in
  their own table with their own tokens, separated by JWT audience. That is a materially stronger
  boundary and it should stay.
- **`pat` and `device` resolve identity rather than minting credentials.** They answer "who is this"
  and hand the decision back. better-auth's device plugin returns session tokens directly. authit's
  seam is cleaner and composes with hosts that have their own credential types.
- **The `team` package documents what it refuses to model, and why.** That documentation is better
  than most libraries' feature lists.
- **One binary, no Node runtime, no ORM chain.** Not nothing.

---

## 4. What to change in authit

Ordered by ratio of value to work. Tier 0 items are defects; everything else is scope.

### 4.0 First: is porting better-auth features the right move?

Mostly no, and not yet. Of everything in the §2.6 matrix, exactly **one** design element is worth
copying outright and **one** feature is worth building — and neither is where the urgency is.

**Worth copying verbatim:** the pluggable `hash`/`verify` password seam (T0.4). better-auth got this
exactly right, and it is the difference between "you use bcrypt" and "you use whatever your threat
model calls for, and you can migrate."

**Worth building, but as a strategic decision on its own:** social/OIDC login (T2.1). It is the single
most common reason a team reaches for better-auth over a smaller library, and "by design, no social
login" will cost more adoption than the simplicity buys back. But it is a week of work, and it should
not jump the queue ahead of §2.7.

**Not worth porting:** the plugin system (Go lacks the type inference that makes it pay), the client
SDK (authit's consumers are Go services), migrations and the schema CLI (authit does not own the
schema — deliberately), the org access-control model, and the product-feature plugins.

The honest framing is that authit's gap versus better-auth is **not a feature gap**. It is a
hardening gap plus a plumbing gap. A team choosing between them today is not choosing between 30
features and 12; they are choosing between "the brute-force controls have been thought about" and
"they have not." Shipping magic links on top of §2.7 would make authit look more competitive and be
less safe.


### Tier 0 — fix before anyone runs this in production

These are defects, not scope. Together they are perhaps two days of work, and they matter far more
than any feature in §2.6.

**T0.1 — Rate-limit the second factor.** ✅ *Done*, though not the way this document originally
proposed. Rather than adding an attempts counter to `PendingTwoFactorSession` — which would have
been a breaking change to `store.PendingTwoFactorStore` and every host adapter — the second factor
now shares the first factor's counter. `Authenticate` no longer clears that counter after a correct
password (only a *fully* completed login does), and `VerifyTwoFactorLogin` records failures and
consults the lockout before checking the code. An attacker holding a valid password gets
`MaxFailedLoginAttempts` guesses per `FailedLoginWindow`, and cannot re-run `Authenticate` to mint a
fresh pending session to escape it, because `Authenticate` reads the same counter.
*Changed:* `user/register_login.go`, `user/twofactor.go`, `user/config.go`.
*Tests:* `user/lockout_test.go` — `TestTwoFactorGuessesAreRateLimited`,
`TestTwoFactorThrottleSurvivesReauthentication`, `TestSuccessfulTwoFactorLoginResetsCounter`. Both
regression tests were confirmed to fail against the previous implementation.

**T0.2 — Widen backup codes to 64 bits.** ✅ *Done.* `crypto.BackupCodeBytes = 8` (was an inline 4),
and `consumeBackupCode` now uses `subtle.ConstantTimeCompare`. Existing codes keep working — they are
stored hashed and verification does not check length — but accounts enrolled before the change should
be prompted to regenerate. `TestGenerateBackupCodes` pins the width so it cannot silently shrink.
*Changed:* `crypto/totp.go`, `user/twofactor.go`, `crypto/crypto_test.go`.

**T0.3 — Make the account lock time-bounded.** ✅ *Done*, and again by a different route than
sketched. Adding an `until` column was not viable: `sqlb` has no upsert to extend an existing lock,
and `LockoutAdapter`'s lock row is host-defined (`NewLockRow func(userID) L`) with no generic way to
read an expiry back out. So instead the temporary lockout is now **derived, not stored** — it is
`CountRecentFailedLoginAttempts(email, now-FailedLoginWindow) >= MaxFailedLoginAttempts`, computed on
each login. It lifts on its own as attempts age out; there is nothing to unlock, no expiry column,
and **no change to the `store` interfaces at all**, so no host adapter breaks.

`LockAccount`/`UnlockAccount` keep their signatures but change meaning: they are now purely the
*administrative* lock, reached only by the host. Nothing in authit calls them. `Authenticate` still
honours a row written there.

This also fixed §2.7(f) for free: because the derived lockout is keyed by email, it is evaluated
*before* the user lookup, which is the property `checkLockoutAndFetchUser`'s doc comment always
claimed and never had.

**Deliberately not done here:** the per-`(email, IP)` counting from the original sketch. Making the
lock trigger IP-scoped would let an attacker rotating IPs avoid it entirely, which is worse than what
it fixes. The account-scoped trigger is the right one; per-IP throttling is a *separate* control and
belongs in T1.4. The residual exposure — an attacker who knows an address can cause a
`FailedLoginWindow`-long DoS against it — is the standard trade, is now bounded and self-healing
rather than permanent, and is documented in the README.
*Changed:* `user/register_login.go`, `superuser/auth.go`, `store/user.go`, `schema.sql`, `README.md`.
*Tests:* `user/lockout_test.go` — `TestFailedLoginsDoNotWriteAdministrativeLock`,
`TestThrottleLiftsWithoutOperatorAction`, `TestAdministrativeLockStillBlocksLogin`,
`TestThrottleAppliesToUnknownAddresses`; `superuser/superuser_test.go`.

**T0.9 — both documentation/behaviour mismatches reconciled.** ✅ *Done.* §2.7(f) fell out of T0.3
(the derived lockout is keyed by email, so it is genuinely evaluated before the user lookup, as the
comment always claimed). §2.7(e) is closed by T1.4 below: `crypto/usercode.go` named rate limiting as
the control its low entropy depends on without saying who supplies it, and `device.Config.RateLimiter`
now supplies the half that only authit can.

**T0.4 — Make password hashing pluggable, and default to argon2id.** ✅ *Done.* `crypto.Hasher`
(`Hash`/`Verify`/`NeedsRehash`) with `crypto.Argon2idHasher` (the new default, OWASP minimum
parameters, PHC string encoding so the parameters travel with each hash) and `crypto.BcryptHasher`.
Both dispatch `Verify` on the hash's own prefix, so either accepts anything authit has ever written —
without that property, changing the hasher would lock out every existing user. `Authenticate` on both
planes re-hashes after a successful password check when `NeedsRehash` reports the stored hash is
weaker than current settings, so an existing bcrypt corpus migrates itself with no migration script.
Best-effort: the stored hash stays valid if the rewrite fails, so it can never fail a login.
*Changed:* `crypto/hasher.go` (new), `user/config.go`, `user/register_login.go`, `user/password.go`,
`superuser/service.go`, `superuser/auth.go`, `user/errors.go`, `superuser/errors.go`.
*Tests:* `crypto/hasher_test.go` (round trip, cross-format verification, `NeedsRehash` thresholds,
malformed input), `user/hashing_test.go` (`TestPasswordHashUpgradesOnLogin`,
`TestUpgradeDoesNotHappenForCurrentHashes`), `superuser/superuser_test.go`.

**T0.5 — Add a password policy seam.** ✅ *Done*, in `crypto` rather than `user` so both planes share
one type: `crypto.PasswordValidator`, with `LengthPolicy`, `NotEmailPolicy` and `AllPolicies` as
composable pieces and `DefaultPasswordPolicy()` (12–1024 runes) as the non-nil default. Enforced on
`Register`, `ChangePassword`, `ResetPassword` and `createSuperuser`.

Two decisions worth recording:

- **The policy is not consulted on login.** Raising it must not lock out the users it was raised to
  protect. Pinned by `TestPasswordPolicyIsNotAppliedOnLogin`.
- **Length only, by default.** Composition rules reduce entropy by steering people toward predictable
  substitutions, and a breach-list check needs a corpus authit should not ship. `AllPolicies` is the
  seam for adding one.

Length is counted in runes, not bytes, so a 12-character minimum does not silently demand 12 bytes of
a script whose characters are three bytes each. The maximum exists because a password is
attacker-controlled input to a deliberately expensive function.

*Changed:* `crypto/policy.go` (new), `user/config.go`, `user/register_login.go`, `user/password.go`,
`superuser/service.go`. *Tests:* `crypto/hasher_test.go`, `user/hashing_test.go`.

> **Note for existing consumers:** T0.5 is the one change in this tier that can break a working
> application at runtime rather than at compile time — any account whose password is under 12
> characters can no longer change or reset it to the same value, and seeded/test fixtures with short
> passwords will start failing at `Register`. Set `PasswordValidator` explicitly to keep the old
> behaviour. The repo's own test fixtures were updated rather than the default weakened.

**T0.6 — Normalise email on the way in.** ✅ *Done.* `store.NormalizeEmail` (trim + lower-case),
applied at the entry point of every method that takes an address: `Register`, `Authenticate`,
`RequestPasswordReset`, `RequestEmailVerificationByEmail`, `createSuperuser`, `superuser.Authenticate`,
`team.CreateInvitation` and `team.AcceptInvitation`.

It lives in `store` because the invariant is a storage-contract statement — *the value authit writes
to and queries the email column with is always this form* — which means an implementation needs no
`citext`, no `lower()` index and no case-insensitive collation. Previously authit's behaviour on
`Alice@` vs `alice@` was decided entirely by the host's collation: one account or two, silently.

The security half is less obvious than the duplicate-account half: the failed-login counter is keyed
by email, so before this an attacker could reset their own throttle just by varying capitalisation.
`TestThrottleCannotBeResetByVaryingCase` pins it.

Lower-casing the whole address is formally lossy — RFC 5321 makes the local part case-sensitive — but
it matches what providers do, and letting case create duplicate accounts is the worse failure.
Dot-stripping and `+tag` removal are deliberately absent: Gmail-specific, and they merge genuinely
distinct addresses elsewhere.

*Note for existing consumers:* rows written before this need a one-time
`UPDATE ... SET email = lower(btrim(email))`, documented on `NormalizeEmail` and in the README.
*Changed:* `store/email.go` (new), `user/register_login.go`, `user/password.go`,
`user/email_verification.go`, `superuser/auth.go`, `superuser/service.go`, `team/invitations.go`.
*Tests:* `user/normalization_test.go`, `superuser/superuser_test.go`.

**T0.7 — Refresh-token reuse detection.** ✅ *Done.* A revoked-but-unexpired refresh token presented
to `Refresh` now revokes every refresh token the principal holds and emits `EventUserTokenReuse` /
`EventSuperuserTokenReuse`. Rotation means the legitimate holder never re-sends a spent token, so a
second use means two parties hold it — and nothing at that point can distinguish them, so both are
forced back through a password login, which only one of them can complete.

Three decisions:

- **The error stays `ErrInvalidToken`**, byte-identical to what a garbage token returns. A distinct
  error would confirm to an attacker that a stolen token was genuine and already spent — exactly the
  fact worth withholding. `TestRefreshReuseIsIndistinguishableFromGarbage` pins it.
- **Expired tokens do not trip it.** An expired token is not evidence of theft and must not take the
  user's other sessions down.
- **A replayed logged-out token does trip it**, an accepted false positive: distinguishing it would
  need a revocation-reason column, and the session was over anyway. Documented rather than hidden,
  since it puts noise in the audit trail.

*Changed:* `user/register_login.go`, `superuser/auth.go`, `audit/audit.go`.
*Tests:* `user/refresh_reuse_test.go`, `superuser/superuser_test.go`. The user-plane test was
confirmed to fail against the previous implementation.

**T0.8 — Add an asymmetric signer.** ✅ *Done.* `jwt.Verifier` (`Verify`/`Validate`) split out of
`jwt.Signer`, which now embeds it — so every existing implementation and call site still compiles, and
narrowing a parameter to `Verifier` breaks no caller. `authithttp.Validate` and
`authhandlers.NewUserHandler` both take the narrow type now.

`jwt.AsymmetricSigner` via `NewRS256Signer` / `NewEd25519Signer`, with `Verifier()`, `PublicKey()`,
`KeyID()` and `JWKS()`. `jwt.NewVerifier(publicKeys...)` builds a value that holds no private key and
therefore cannot mint anything — the property `HMACSigner` structurally cannot offer. `jwt.JWKS` and
`jwt.KeyID` render RFC 7517 key sets and RFC 7638 thumbprints; tokens carry the thumbprint as `kid`,
so a verifier holding several keys can select the right one and a rotation needs no coordination
beyond publishing the set.

*Corrected mid-implementation:* the algorithm-pinning in `methodMatchesKey` was first documented as
"the check that stops algorithm confusion", and a test was written asserting it produced a 401 where
its absence would produce a 500. Measuring rather than assuming showed both claims were wrong:
golang-jwt already refuses an HS256-signed token when the keyfunc returns an `*rsa.PublicKey`, and the
error wraps `ErrTokenSignatureInvalid` either way — so the attack fails and returns 401 with the
pinning removed. What the pinning genuinely changes is that the error no longer *also* wraps
`ErrInvalidKeyType`, the sentinel that everywhere else means "this server is misconfigured"; without
it, an operator watching that signal is paged by an attacker. The comment and tests now say that, and
`TestAlgorithmConfusionKeepsErrorSignalsDistinct` fails when the pinning is removed. The pinning is
defence in depth, and is documented as such.

*Changed:* `jwt/signer.go`, `jwt/asymmetric.go` (new), `jwt/jwks.go` (new), `authithttp/validate.go`,
`authhandlers/authhandlers.go`. *Tests:* `jwt/asymmetric_test.go`, `authithttp/authithttp_test.go`.

**T0.9 — both documentation/behaviour mismatches reconciled.** ✅ *Done.* §2.7(f) fell out of T0.3
(the derived lockout is keyed by email, so it is genuinely evaluated before the user lookup, as the
comment always claimed). §2.7(e) is closed by T1.4 below: `crypto/usercode.go` named rate limiting as
the control its low entropy depends on without saying who supplies it, and `device.Config.RateLimiter`
now supplies the half that only authit can.

**T0.4 — Make password hashing pluggable, and default to argon2id.** ✅ *Done.* `crypto.Hasher`
(`Hash`/`Verify`/`NeedsRehash`) with `crypto.Argon2idHasher` (the new default, OWASP minimum
parameters, PHC string encoding so the parameters travel with each hash) and `crypto.BcryptHasher`.
Both dispatch `Verify` on the hash's own prefix, so either accepts anything authit has ever written —
without that property, changing the hasher would lock out every existing user. `Authenticate` on both
planes re-hashes after a successful password check when `NeedsRehash` reports the stored hash is
weaker than current settings, so an existing bcrypt corpus migrates itself with no migration script.
Best-effort: the stored hash stays valid if the rewrite fails, so it can never fail a login.
*Changed:* `crypto/hasher.go` (new), `user/config.go`, `user/register_login.go`, `user/password.go`,
`superuser/service.go`, `superuser/auth.go`, `user/errors.go`, `superuser/errors.go`.
*Tests:* `crypto/hasher_test.go` (round trip, cross-format verification, `NeedsRehash` thresholds,
malformed input), `user/hashing_test.go` (`TestPasswordHashUpgradesOnLogin`,
`TestUpgradeDoesNotHappenForCurrentHashes`), `superuser/superuser_test.go`.

**T0.5 — Add a password policy seam.** ✅ *Done*, in `crypto` rather than `user` so both planes share
one type: `crypto.PasswordValidator`, with `LengthPolicy`, `NotEmailPolicy` and `AllPolicies` as
composable pieces and `DefaultPasswordPolicy()` (12–1024 runes) as the non-nil default. Enforced on
`Register`, `ChangePassword`, `ResetPassword` and `createSuperuser`.

Two decisions worth recording:

- **The policy is not consulted on login.** Raising it must not lock out the users it was raised to
  protect. Pinned by `TestPasswordPolicyIsNotAppliedOnLogin`.
- **Length only, by default.** Composition rules reduce entropy by steering people toward predictable
  substitutions, and a breach-list check needs a corpus authit should not ship. `AllPolicies` is the
  seam for adding one.

Length is counted in runes, not bytes, so a 12-character minimum does not silently demand 12 bytes of
a script whose characters are three bytes each. The maximum exists because a password is
attacker-controlled input to a deliberately expensive function.

*Changed:* `crypto/policy.go` (new), `user/config.go`, `user/register_login.go`, `user/password.go`,
`superuser/service.go`. *Tests:* `crypto/hasher_test.go`, `user/hashing_test.go`.

> **Note for existing consumers:** T0.5 is the one change in this tier that can break a working
> application at runtime rather than at compile time — any account whose password is under 12
> characters can no longer change or reset it to the same value, and seeded/test fixtures with short
> passwords will start failing at `Register`. Set `PasswordValidator` explicitly to keep the old
> behaviour. The repo's own test fixtures were updated rather than the default weakened.

**T0.6 — Normalise email on the way in.** ✅ *Done.* `store.NormalizeEmail` (trim + lower-case),
applied at the entry point of every method that takes an address: `Register`, `Authenticate`,
`RequestPasswordReset`, `RequestEmailVerificationByEmail`, `createSuperuser`, `superuser.Authenticate`,
`team.CreateInvitation` and `team.AcceptInvitation`.

It lives in `store` because the invariant is a storage-contract statement — *the value authit writes
to and queries the email column with is always this form* — which means an implementation needs no
`citext`, no `lower()` index and no case-insensitive collation. Previously authit's behaviour on
`Alice@` vs `alice@` was decided entirely by the host's collation: one account or two, silently.

The security half is less obvious than the duplicate-account half: the failed-login counter is keyed
by email, so before this an attacker could reset their own throttle just by varying capitalisation.
`TestThrottleCannotBeResetByVaryingCase` pins it.

Lower-casing the whole address is formally lossy — RFC 5321 makes the local part case-sensitive — but
it matches what providers do, and letting case create duplicate accounts is the worse failure.
Dot-stripping and `+tag` removal are deliberately absent: Gmail-specific, and they merge genuinely
distinct addresses elsewhere.

*Note for existing consumers:* rows written before this need a one-time
`UPDATE ... SET email = lower(btrim(email))`, documented on `NormalizeEmail` and in the README.
*Changed:* `store/email.go` (new), `user/register_login.go`, `user/password.go`,
`user/email_verification.go`, `superuser/auth.go`, `superuser/service.go`, `team/invitations.go`.
*Tests:* `user/normalization_test.go`, `superuser/superuser_test.go`.

**T0.7 — Refresh-token reuse detection.** ✅ *Done.* A revoked-but-unexpired refresh token presented
to `Refresh` now revokes every refresh token the principal holds and emits `EventUserTokenReuse` /
`EventSuperuserTokenReuse`. Rotation means the legitimate holder never re-sends a spent token, so a
second use means two parties hold it — and nothing at that point can distinguish them, so both are
forced back through a password login, which only one of them can complete.

Three decisions:

- **The error stays `ErrInvalidToken`**, byte-identical to what a garbage token returns. A distinct
  error would confirm to an attacker that a stolen token was genuine and already spent — exactly the
  fact worth withholding. `TestRefreshReuseIsIndistinguishableFromGarbage` pins it.
- **Expired tokens do not trip it.** An expired token is not evidence of theft and must not take the
  user's other sessions down.
- **A replayed logged-out token does trip it**, an accepted false positive: distinguishing it would
  need a revocation-reason column, and the session was over anyway. Documented rather than hidden,
  since it puts noise in the audit trail.

*Changed:* `user/register_login.go`, `superuser/auth.go`, `audit/audit.go`.
*Tests:* `user/refresh_reuse_test.go`, `superuser/superuser_test.go`. The user-plane test was
confirmed to fail against the previous implementation.

**T0.8 — Add an asymmetric signer.**
`jwt.NewRS256Signer(privateKey)` / `jwt.NewEd25519Signer(...)`, plus a **verify-only** type
(`jwt.Verifier` with just `Verify`/`Validate`) so downstream services get a key that cannot mint. A
small `jwt.JWKS(pub) ([]byte, error)` helper covers the rest. `authithttp.Validate` should take the
narrower `Verifier` interface, not `Signer`.
*Touches:* `jwt/signer.go`, `authithttp/validate.go`.

**T0.9 — Reconcile the two documentation/behaviour mismatches** in §2.7(e) and §2.7(f): either ship
the device-code rate limiting the comment promises (it falls out of T1.4) or restate the requirement
at the API surface, and either check lockout before the user lookup as documented or delete the claim.

### Tier 1 — close the adoption gap without changing what authit is

**T1.1 — Lifecycle hooks.** ✅ *Done.* `user.Config.Hooks` with `BeforeRegister`, `AfterRegister`,
`BeforeAuthenticate`, `AfterAuthenticate` and `AfterPasswordChange`. All nil-safe; a hook's error
reaches the caller unchanged so hosts can use their own sentinels.

The design question worth answering was what an `After` hook's error *means* — the operation already
happened, so returning an error is either meaningless or it undoes something. T1.2 made the good
answer available: **After hooks run inside the same transaction as the operation's writes**, so an
error rolls the operation back and "create the account only if provisioning succeeds" actually holds.
Without a `TxRunner` the writes have already landed independently and the hook is a notification;
that difference is documented rather than glossed, because it is the difference between a guarantee
and a hope.

Placement mattered more than the mechanism, and each choice is pinned by a test:

- **`BeforeAuthenticate` runs after rate limiting and the lockout**, so it cannot be used to reach
  past the brute-force controls, and before the password comparison, so refusing costs no KDF work.
- **`AfterAuthenticate` fires only on a fully completed login.** For an account with 2FA that means
  after the second factor — it is reached from `Authenticate`'s no-2FA path and from
  `VerifyTwoFactorLogin`, and nowhere else. Firing it when the password was accepted would have a
  last-seen hook recording logins that never completed.
- **`BeforeRegister` sees the normalised address** and fires before the taken check: it is a cheap
  gate, and making an allow-list re-implement normalisation would guarantee a subtle mismatch.

One thing fell out of the work rather than being planned. Wrapping `Register` and `Authenticate` to
accommodate their After hooks made my own T1.2 test fail — *"logging in is a single write and should
not open a transaction"* — which was correct: a transaction guarding one write and a nil hook is a
round trip spent on nothing. Those flows now take a transaction only when the relevant hook exists.
The genuinely multi-write flows always do.

Both regressions were confirmed: moving `AfterRegister` outside the transaction fails
`TestAfterRegisterRollsBackWithATxRunner`, and firing `AfterAuthenticate` at the password step fails
`TestAfterAuthenticateOnlyFiresOnACompletedLogin`.

*Scope:* the `user` plane only. `team`, `superuser`, `pat` and `device` have no hooks yet; the shape
transfers directly if they need them.

*Changed:* `user/hooks.go` (new), `user/{config,register_login,password,twofactor}.go`.
*Tests:* `user/hooks_test.go`.

**T1.2 — Optional transactions.** ✅ *Done.* `store.TxRunner` (one method), an optional `Tx` field on
`user.Stores`, `team.Stores` and `superuser.Stores`, and six flows wrapped: `Refresh` (both planes),
`ResetPassword`, `VerifyTwoFactorLogin`, `CreateTeam`, `AcceptInvitation`. Nil changes nothing.

The hard part is not the plumbing, it is the contract. authit calls store methods with the context
`RunInTx` supplies, because that is the only channel it has — widening every port to take a
transaction handle would put a database concept into interfaces whose entire purpose is not having
one. So the obligation is on the implementation: *every store method called with `fn`'s context must
join the transaction, and every method called with any other context must not.* An adapter whose
stores ignore the context compiles, passes its own tests, and provides no atomicity at all. That is
documented at length on the interface, along with the advice to leave the field nil rather than
believe in atomicity you do not have.

Three decisions where the obvious wrapping would have been wrong:

- **Reuse detection stays outside.** `Refresh` revokes every session on detecting a replayed token and
  *then* returns an error. Inside the transaction, that error rolls back the revocation — the
  detection fires, logs itself, and undoes its own response. This is the one that would have quietly
  disabled T0.7.
- **Failed-login recording stays outside**, for the same reason: the attempt the rate limiter counts
  must outlive the failure that produced it.
- **Audit events are emitted after commit.** A `TxRunner` is permitted to retry, so an event logged
  from inside would be logged twice — or, on rollback, logged for something that never happened.

And one that went the other way: `team.Admission` now runs *inside* the transaction, so a seat limit
is enforceable rather than advisory — the member count it is given and the member row that follows are
consistent. The cost is that host code holds a transaction open, which is documented on the field.

*Testing.* `storetest.TxProbe` and `TxWitness` record which operations a service enrolled.
`TxWitness.AssertOutsideTx` is the direction that catches the subtle mistakes above. Both regressions
were confirmed: sweeping the reuse revocation into the transaction fails
`TestReuseRevocationSurvivesTheErrorReturn`, and removing the transaction from `Refresh` fails
`TestRefreshRotatesInsideATransaction`. The probe provides no atomicity and says so — it answers "did
the service put the right writes inside", not "does rollback work".

*Changed:* `store/tx.go` (new), `storetest/tx.go` (new), `user/{service,register_login,password,twofactor}.go`,
`team/{service,teams,invitations}.go`, `superuser/{service,auth}.go`.
*Tests:* `user/tx_test.go`, `team/tx_test.go`.

**T1.3 — Finish `authhandlers`.** ✅ *Done.* `NewTeamHandler`, `NewSuperuserHandler`, `NewPATHandler`
and `NewDeviceHandler` join `NewUserHandler`, each a plain `http.Handler` over its service.

The interesting part was not the plumbing. Three things had no safe default, and pretending otherwise
would have shipped holes:

- **Team authorization.** The `team` package documents at length that checking the caller's role is
  the host's job. A route group that only verified "is this request authenticated" would therefore
  let any user change any member's role in any team — the plumbing would look complete and be a
  privilege-escalation hole. `NewTeamHandler` takes a required `TeamAuthorizer` and panics without
  one, at startup. `RoleAuthorizer` ships the conventional rules and defaults to deny on any action
  it does not recognise, so adding a `TeamAction` cannot silently open a route.
- **Device credentials.** `PollDeviceToken` resolves who approved without minting, by design, so the
  RFC 8628 token endpoint cannot be completed by this package alone. `NewDeviceHandler` takes a
  required `DeviceTokenIssuer`. The verification URI is required for the same reason: `device`
  is explicit that only the host knows its own routing.
- **Operator audience.** The superuser group authenticates through `superuser.Service.Verify`, not
  `authithttp.Validate`. Both planes are signed by the same key, so only the audience check separates
  them; a plain signature check would have accepted an ordinary user's token on every operator route,
  including `Impersonate`. Pinned by a test.

Four smaller decisions worth recording, each one a place where taking the obvious input from the
request body would have broken something:

- `AcceptInvitation` takes the email from the **validated token**, never the body. The invitation's
  email check is the only thing binding it to its recipient; a client-supplied address makes it
  self-attested and the check worthless. The request DTO has no email field to lie with.
- `CreateTeam` and `CreateInvitation` likewise take the caller's identity from claims, not the body.
- Revoking an invitation verifies it belongs to the team named in the path — authorization passes on
  the path's team, so without that check an admin of one team could revoke another team's invitation.
- `pat.ErrNotOwner` maps to **404, not 403**: "exists but is not yours" is an existence oracle.

Two real bugs were found by writing the tests. `interval` truncated a sub-second duration to `0` and
then dropped it via `omitempty` — and RFC 8628 §3.2 says a client seeing no interval assumes 5
seconds, so configuring a *fast* poll would have produced a slower one; it now rounds up and is always
emitted. And `GET /teams/by-slug/{slug}` is ambiguous with `GET /teams/{id}/members` under Go's
ServeMux, which panics at construction; it became a literal `GET /teams/by-slug?slug=...`.

Also fixed here: `writeServiceError` only knew `user`'s sentinels, so `ErrWeakPassword` and
`ErrRateLimited` — both added in this tier of work — were surfacing as opaque 500s. The table now
covers every plane, and a rate-limit refusal carries `Retry-After`.

*Changed:* `authhandlers/{team,superuser,pat,device}.go` (new), `authhandlers/{authhandlers,json}.go`.
*Tests:* `authhandlers/planes_test.go`.

**T1.4 — A rate-limiting port.** ✅ *Done.* New `ratelimit` package: `Limiter` (one method),
`Noop`, `ErrRateLimited`, a `RetryAfter` hint, and `NewMemory` — an in-process token bucket with a
bounded keyspace. Wired into `user` (login, 2FA, password reset, email verification), `superuser`
(login) and `device` (user-code guessing, which closes T0.9).

The framing changed while implementing it. The original sketch said "key by IP and route, not just
email" — but a service method sees only its arguments, and half of them have no IP at all
(`RequestPasswordReset(ctx, email)` never will). Shipping a service-layer limiter that claimed to be
per-IP would have been a lie for those paths. So the package documents itself as explicitly *not* a
replacement for HTTP middleware, and covers only what middleware cannot reach:

- **Refusing before the KDF.** This became the strongest argument for the port existing at all, and it
  is a consequence of T0.4: Argon2id costs 19 MiB and real CPU per attempt, so an unauthenticated
  flood is resource exhaustion regardless of whether a password is ever guessed. Making passwords
  properly expensive to verify created a denial-of-service surface, and this is what closes it.
- **Device user codes** (T0.9) — the lookup is inside `device`, so nothing outside can charge for it.
- **Mail-sending endpoints**, keyed by address so an unregistered one behaves identically and the
  limit cannot be used to probe for accounts.

Three details worth recording:

- **A limiter fault is not a refusal.** A Redis timeout propagates unchanged rather than being folded
  into `ErrRateLimited`; "too many attempts" and "the limiter is down" want different status codes.
- **Keys carry the normalised email**, or varying case would buy a fresh budget — the same bug T0.6
  fixed for the lockout counter, and it would have reappeared here.
- **`Memory` bounds its own keyspace.** A limiter that grows a map per distinct key is itself a
  memory-exhaustion vector, since the attacker picks the key. Eviction drops only fully-refilled
  buckets, which is lossless — a full bucket permits exactly what an absent one does — so flooding
  with junk keys cannot evict and thereby reset a bucket that is actively limiting someone.
  `MaxKeys` is a *hard* bound: once the table is full of actively-limited keys, an unseen key is
  refused rather than admitted untracked, because admitting it would be precisely the bypass the cap
  exists to prevent. (Corrected during T1.3 — the first version let the map overshoot by however many
  keys arrived before something became evictable, which is both unbounded under a sustained flood and
  the reason its test went flaky.)

*Changed:* `ratelimit/` (new), `user/config.go`, `user/errors.go`, `user/register_login.go`,
`user/twofactor.go`, `user/password.go`, `user/email_verification.go`, `superuser/*`, `device/*`,
`crypto/usercode.go`. *Tests:* `ratelimit/ratelimit_test.go` (including `-race`),
`user/ratelimit_test.go`, `device/ratelimit_test.go`, `superuser/superuser_test.go`.

**T1.5 — Cookie helpers in `authithttp`.**
`SetRefreshCookie(w, token, opts)` / `ClearRefreshCookie(w)` with `HttpOnly`, `Secure`, `SameSite`,
and a `Path` scoped to the refresh route. Same justification as the existing bearer-parsing
exception: it is short, identical everywhere, and quietly security-critical.

**T1.6 — A store conformance suite.** ✅ *Done.* New `storetest` package: `RunAll` plus one `Run*`
per port, 53 subtests. `memstore` runs it (it had **no test files at all** before — its correctness was
asserted only indirectly, by the service packages that happen to use it), and `sqlbstore` runs it
against the reference `schema.sql` when a Postgres DSN is configured.

It pins the contract rather than the happy path, which is the point: a flow test only exercises the
paths a service happens to take, while the failures that matter here are the ones a happy path never
notices. Several assertions exist specifically because earlier work in this document made them
load-bearing —

- *A revoked refresh token is still returned by hash.* Filtering it out looks tidy and silently
  disables T0.7's reuse detection. Verified by breaking `memstore` deliberately: the suite fails and
  names the property, where previously the only signal was a service-level test failing three layers
  away.
- *`CountRecentFailedLoginAttempts` honours `since`.* T0.3 made the temporary lockout derived from
  this count, so an adapter ignoring the parameter turns the throttle back into a permanent lock —
  reintroducing the exact defect T0.3 removed.
- *`LockoutStore` needs its second table, and `LockAccount` is idempotent.* The documented footgun,
  now executable.
- *`ErrNotFound` is the only way to say "no such row".*

Two design points, both discovered by trying to point it at a real schema rather than at `memstore`:

- **Identifiers are UUID-shaped.** `"u1"` works fine in memory and is rejected outright by a Postgres
  `uuid` column, so a suite written that way would only ever run against the adapter that needed it
  least.
- **`Fixtures` hooks exist because foreign keys do.** Each suite exercises one port in isolation and
  therefore creates rows referring to users and teams that do not exist. Against `memstore` that is
  fine; against `schema.sql` the database rejects it, and the suite would be reporting a constraint
  the interfaces never promised.

*Scope:* `sqlbstore`'s wiring covers the user plane, reusing the row types `example_test.go` already
defines; the team, PAT, device and superuser adapters would each need example row types first. And
the sqlbstore half is **unverified against a live database** — no Postgres was available where this
was written, so it compiles and skips. `memstore`'s half runs on every `go test ./...`.

*Changed:* `storetest/` (new), `memstore/memstore_test.go` (new), `sqlbstore/conformance_test.go`
(new), `sqlbstore/example_test.go` (its schema helper now returns the pool too).

### Tier 2 — feature scope, in the order that pays

**T2.1 — Social / OIDC login.** This is the number one reason a team picks better-auth, and "no social
login, by design" is a stance that will cost adoption more than it saves complexity. Do it without
compromising the architecture: a new `oidc` package, a new `store.AccountStore` port (provider,
provider account ID, tokens, scopes — the equivalent of better-auth's `account` table), and
`golang.org/x/oauth2` for the handshake. Core `user` stays password-only; linking an OIDC identity to
an existing user becomes an explicit call.

**T2.2 — Passkeys / WebAuthn.** Arguably worth more than TOTP now. `go-webauthn/webauthn` plus a
`store.CredentialStore`. Slots in beside `twofactor.go` as a second-factor *and* as a primary factor.

**T2.3 — Magic link and email OTP.** Cheapest features on this list: `crypto` already generates and
hashes opaque tokens, `EmailSender` already exists, and the token lifecycle is the same shape as
`EmailVerificationToken`.

**T2.4 — Optional server-side sessions.** `store.SessionStore` plus
`user.Config.SessionMode` (`SessionModeJWT` default, `SessionModeOpaque`). Opaque mode issues a
random session token instead of a JWT and validates by lookup, buying immediate revocation for hosts
that want it. This is the one place worth adopting better-auth's model outright — as an option, not a
replacement.

**T2.5 — An optional `authz` package.** Statements, roles, `Can(member store.Member, action, resource string) bool`,
with owner/admin/member predefined. Optional, in its own module, imported by nobody who does not want
it — so the `team` package's documented stance survives intact while the common case stops being
hand-written per consumer.

### Tier 3 — developer experience

**T3.1 — `authitctl`.** `authitctl schema print --dialect postgres|sqlite|mysql` (emit the DDL, which
today is a hand-maintained `schema.sql` for Postgres only) and `authitctl superuser create`. That is
the genuinely useful half of better-auth's CLI. Skip migrations — authit does not own the schema and
should not pretend to.

**T3.2 — OpenAPI document for `authhandlers`.** Hand-written YAML is fine; it is a fixed route set.

**T3.3 — Fill in the README's status.** "Early scaffold… not yet used in a production app" plus the
Tier 0 items above is an accurate combination, but the README should name the specific caveats
(permanent lockout, no password policy, HS256-only) rather than leaving them to be discovered.

### Explicitly do not do

- **Do not build a plugin system.** Without structural type inference it becomes a registry of
  `map[string]any` and reflection. Hooks (T1.1) plus separate modules get the same outcome.
- **Do not ship a client SDK.** authit's consumers are Go services; the browser is the host's problem.
- **Do not chase the long tail of better-auth plugins** (Stripe, usernames, anonymous auth, phone).
  Those are product features, not auth primitives.
- **Do not depend on goauth.** Wrong layer, wrong problem, heavy dependency tree.

---

## 5. Summary

authit is not a worse better-auth; it is a smaller, lower-layer library that made the opposite call
on schema ownership, and the right call for hosts that already have a database. What separates it
from better-auth in kind — storage ports, a structurally separate operator plane, identity-resolving
CLI credentials — is worth keeping, and no item in this plan erodes it.

But the honest headline is not the feature comparison. It is that the second factor is currently
un-rate-limited (§2.7a) while the first factor is rate-limited into a denial-of-service vector
(§2.7c), and that backup codes carry 32 bits (§2.7b). Those three, plus a password policy, are the
difference between a library that is early and a library that is unsafe — and the README's "early
scaffold" note does not currently say so.

Fix Tier 0. Then decide about social login (T2.1) as its own question. Porting anything else from
better-auth is optimising the wrong axis.
