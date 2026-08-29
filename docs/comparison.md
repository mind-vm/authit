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

What authit was missing is not the model — it is the **option**, and T2.4 supplies it.
`user.Config.SessionMode` selects: `SessionModeJWT` is unchanged and remains the default,
`SessionModeOpaque` issues one token validated by lookup, so revocation takes effect on the next
request rather than when an access token happens to expire.

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
| **Social / OAuth login** | ✅ | ✅ (`oidc`) *(was out of scope)* |
| **OIDC / SSO / SAML** | ✅ (plugins) | partial — any OAuth 2.0/OIDC provider; no SAML |
| **Passkeys / WebAuthn** | ✅ (plugin) | ✅ (`passkey`) *(was absent)* |
| **Magic link / email OTP** | ✅ (plugins) | ✅ (`emaillogin`) *(was absent)* |
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
| Email normalisation | handled | `store.NormalizeEmail` at every entry point *(was none — `Alice@x.com` and `alice@x.com` became two accounts, or collided, depending on your store's collation)* |
| Rate limiting | built in, per-path rules | `ratelimit.Limiter` port *(was none)* |
| Brute-force response | rate limit | derived, self-lifting temporary lockout *(was a permanent account lock)* |
| Token signing | HS256, RS256, EdDSA, JWKS endpoint | HS256, RS256, EdDSA, JWKS + verify-only keys *(was HS256 only)* |

Six of these are worth calling out precisely, because they are bugs rather than missing features.
They are listed worst-first.

> **Status: every defect in this section is fixed.** (a), (b), (c) and (f) by T0.1–T0.3, (d) by
> T0.8, (e) by T0.8 for the documentation half and T1.4 for the rate limiter it depended on. The
> password KDF and policy rows in the table above are closed by T0.4/T0.5, and email normalisation
> by T0.6. Each item below links to the Tier 0 entry recording what was actually built.
>
> They are still written in the present tense, as they were found. That is deliberate: the reasoning
> is what justifies the fix, and the shape of the defect is what the regression tests pin — a test
> whose subject has been paraphrased away is a test nobody can check. Read this section as the
> diagnosis, not as the current state.
>
> An earlier version of this note contradicted itself, claiming (d) was fixed and then that "(d) and
> (e) are still open". If you are relying on this document to assess the library's posture, §4's
> Tier 0 entries are the record; this section is why.

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

**T1.5 — Cookie helpers in `authithttp`.** ✅ *Done.* `SetRefreshCookie`, `ClearRefreshCookie`,
`RefreshCookie` and `CookieOptions`. It belongs in this package for the same reason bearer parsing
does: identical in every consumer, and quietly security-critical. Left as "the caller's business", a
refresh token ends up in `localStorage`.

The design is mostly about removing choices rather than offering them:

- **`HttpOnly` is not configurable.** No use case justifies a refresh token readable from JavaScript;
  the access token, which scripts do need, goes in a header.
- **The only way to drop `Secure` is a field named `Insecure`**, so the unsafe option is the one you
  have to type. `SameSite` defaults to `Strict`, which costs a refresh cookie nothing.
- **`Path` is required rather than defaulting to `/`.** Scoping it is the point of the helper — a
  default would have made the unscoped cookie the silent outcome.

The part worth more than the attributes is that these functions *refuse* rather than write a cookie
the browser will discard, because a browser discards a bad `Set-Cookie` **silently** — no error, no
cookie, and a login that looks successful until the first refresh fails. Two cases:

- A `__Host-`/`__Secure-` name whose prefix rules the other attributes break. (`__Host-` requires
  `Path="/"`, so it genuinely trades against path scoping rather than being a free win — stated
  rather than picked.)
- A token containing bytes outside RFC 6265's cookie-octet set. `net/http` strips those instead of
  failing, so the cookie would be written, stored, and read back shorter than it went in.

`ClearRefreshCookie` takes the same options as `SetRefreshCookie` deliberately: a browser matches a
deletion by name, domain *and* path, so clearing with a different path leaves the credential in place
while the user appears to have logged out.

*Changed:* `authithttp/cookie.go` (new), `authithttp/bearer.go` (package doc).
*Tests:* `authithttp/cookie_test.go`.

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
defines; the team, PAT, device and superuser adapters would each need example row types first.
`memstore`'s half runs on every `go test ./...`.

*Verified against a live database.* ✅ This was written unverified — no Postgres was reachable at the
time, so `sqlbstore` compiled and skipped — and was named the most valuable thing to do next. It has
now been run against Postgres 18, under `-race`, and **the first run failed twice**. Both were real,
and neither was reachable from `memstore`:

1. **The example wiring dropped the caller's `CreatedAt` on `failed_login_attempts`**, letting the
   column's `DEFAULT now()` stand in. Every attempt therefore landed at the database's clock instead
   of the one the caller counts with, so an hour-old failure counted as recent — the conformance
   suite's `since` case caught it exactly as it was written to. Harmless in authit's own use, which
   passes `time.Now()` anyway, but the example is what a host copies, and copying it reinstates the
   permanent lockout T0's derived design was introduced to remove. `sqlb` writes `DEFAULT` for a zero
   time, so carrying the field through costs a host nothing.
2. **The flow test's `ListSessions` expectation was stale.** It asserted one live session *after*
   deliberately replaying a rotated refresh token — written before reuse-as-compromise landed, and
   never run since, because this file has never executed. Family revocation is correct; the
   assertion was not. Reordered to check the session list before the replay, and a new assertion now
   covers what reuse actually does. Reverting `revokeFamilyOnReuse` confirms that one fails.

That is the case for integration tests that actually run: neither bug was visible to the in-memory
suite, and one of them was in the code the README points hosts at.

*Changed:* `storetest/` (new), `memstore/memstore_test.go` (new), `sqlbstore/conformance_test.go`
(new), `sqlbstore/example_test.go` (its schema helper now returns the pool too; the two fixes above).

### Tier 2 — feature scope, in the order that pays

**T2.6 — HTTP route groups for the feature packages.** ✅ *Done* (not in the original plan; added
because `oidc`, `passkey` and `emaillogin` all stopped at the service layer, which is the difference
between "authit has passkeys" and "you can ship passkeys with authit"). `NewOIDCHandler`,
`NewPasskeyHandler` and `NewEmailLoginHandler`.

All three resolve an identity without minting a credential, so all three take a required
`SessionIssuer` — the same shape `NewDeviceHandler` already used. It *writes the response* rather
than returning a body, because these flows disagree about what a response is: a passkey assertion is
an XHR wanting JSON, an OAuth callback is a top-level navigation wanting a redirect and a
`Set-Cookie`. One signature covers both only if it owns the `ResponseWriter`.

**The `SameSite` difference between the two ceremony cookies is load-bearing**, and wrong in opposite
directions. The OAuth cookie must be **Lax**: the callback is a top-level navigation *from the
provider's origin*, so a `Strict` cookie is not sent with it and the callback can never find the state
it is supposed to check — the flow simply stops working. The WebAuthn cookies are **Strict**, since
that ceremony is driven by XHR from the site's own page and nothing is lost. Both are pinned by tests
that fail when the setting is flipped.

Two things deliberately absent:

- **No route for linking a provider to an already-authenticated user.** It is a second, differently
  shaped ceremony that has to carry the caller's identity through the redirect, and completing a link
  against whoever the callback happens to arrive as is an account takeover. Approximating it here
  would have been worse than leaving it out.
- **No known-user passkey ceremony.** A passkey as a *second* factor runs against a caller who has
  passed the first factor and is not yet authenticated — the state `user.Authenticate` hands back as a
  pending two-factor token. Only the host holds that, so only the host can wire it.

*A promise this broke, stated rather than quietly dropped:* `authhandlers`'s package doc said it
"depends on nothing beyond net/http and authit itself". Serving `oidc` and `passkey` means importing
`golang.org/x/oauth2` and `go-webauthn/webauthn` with its tree. The doc now says so, and says the cost
is to the module graph rather than to the binary — Go links only reachable code, so a host that never
calls `NewPasskeyHandler` ships none of it.

*Changed:* `authhandlers/{issue,oidc,passkey,emaillogin}.go` (new), `authhandlers/authhandlers.go`.
*Tests:* `authhandlers/featuregroups_test.go`.



**T2.1 — Social / OIDC login.** ✅ *Done.* New `oidc` package, new `store.AccountStore` port,
`golang.org/x/oauth2` for the handshake. Core `user` stays password-only, exactly as this document
proposed; linking is an explicit call.

**The security decision is account linking, and it gets a named type rather than a boolean.** The
attack: someone who can make a provider assert an address they do not own signs in, is silently
linked to the victim's existing account, and is now the victim. Every "sign in with X" takeover works
this way. So `LinkingPolicy` has a deliberately inconvenient zero value — `LinkingManual` refuses to
link automatically and returns `ErrAccountNotLinked`, which is not a failure but the safe outcome, and
the host's move is to have the user sign in by the means they already have and call `Link`.
`LinkingVerifiedEmail` is available and documented as only being worth the provider's claim.

Three scope decisions worth recording:

- **No ID token verification.** Doing it properly means a JWKS client, a cache, rotation handling, and
  issuer/audience/expiry/nonce checks — a meaningful amount of security-critical machinery. A direct
  TLS call to the provider's userinfo endpoint establishes the same fact with the same trust, works
  for providers that are OAuth 2.0 but not OIDC (GitHub), and has no signature checking to get wrong.
  The cost is one round trip per sign-in, and the limitation is stated in the package doc rather than
  left to be discovered.
- **Provider tokens are not stored** unless `ProviderTokenKey` is set, and are AES-256-GCM encrypted
  when they are — reusing the same primitive as TOTP secrets. A credential you do not keep cannot
  leak, so not keeping it is the default.
- **State and the PKCE verifier are returned to the caller**, not stored. They belong to one browser
  for one minute; keeping them would mean another store port and a cleanup problem, to hold state
  that has a natural home in a short-lived cookie.

Smaller things that matter: the link is keyed on the provider's **subject**, never the email, so a
user changing their address at the provider does not move the account. GitHub's mapper reports
`EmailVerified: false` rather than assuming, because its `/user` response does not say — with
`LinkingVerifiedEmail` that means GitHub will not silently take over an account, which is the right
way round for a claim we cannot see. Endpoints must be HTTPS, checked at construction. Social accounts
are created with no password, and an empty hash verifies nothing, so they are reachable only through a
linked provider. `Unlink` refuses to strand an account with no remaining credential.

*Not done:* an `authhandlers` route group for the redirect and callback, and a `sqlbstore` adapter.
Both are mechanical; neither is in this change.

*Changed:* `oidc/` (new), `store/account.go` (new), `memstore/account.go` (new),
`storetest/credentials.go`, `crypto/token.go`, `audit/audit.go`, `schema.sql`, `go.mod`
(`golang.org/x/oauth2`). *Tests:* `oidc/oidc_test.go` against a fake provider that enforces PKCE the
way a real one does; the linking regression was confirmed by removing the policy check.

**T2.2 — Passkeys / WebAuthn.** ✅ *Done.* New `passkey` package over `go-webauthn/webauthn`, new
`store.WebAuthnCredentialStore` port. Registration, known-user login, and usernameless discoverable
login; credential management with rename and revoke.

**The security decision is user verification**, and it is the same shape as `oidc`'s linking policy: a
passkey proves possession of a device, and carries a *second* factor only when the authenticator asks
for a PIN or biometric first. `Config.UserVerification` therefore defaults to `VerificationRequired`,
and `Result.UserVerified` reports what happened in this assertion so a host that relaxed it can still
decide to ask for a password.

**A test caught a real bug in that field.** The first implementation read `Credential.Flags.UserVerified`
off the credential returned by `FinishLogin` — which carries the flags recorded at *registration*, not
this assertion. So `UserVerified` reported user verification that happened once, months ago, for a
login where it did not happen at all. The library's own check still refused the login under
`VerificationRequired`, so only the reported value was wrong — but that value exists precisely for the
hosts who relaxed the requirement and use it to decide whether to also ask for a password. Fixed by
parsing the assertion and reading the flag from it, via `ValidateLogin` rather than `FinishLogin`.

Two other decisions worth recording:

- **Clone detection rejects by default.** A signature counter that fails to advance is the
  specification's one built-in signal that a private key has been copied. The warning is persisted
  *before* the login is refused — losing it because the request failed would make the next attempt
  look like the first.
- **`Data` is an opaque authoritative blob**, and the other columns are denormalised out of it. The
  library's `Credential` struct has grown fields across versions; decomposing it into store columns
  would mean every upgrade risks silently dropping one. The port stays free of the library's types,
  and the conformance suite requires the blob to round-trip byte-exact — it is neither UTF-8 nor free
  of zero bytes, so a text column mangles it and every subsequent login for that authenticator fails.

*Corrected, as in T0.8:* the user-handle ownership check in the discoverable-login handler is defence
in depth, not the load-bearing control — the library performs the same comparison (§7.2 step 6), and
removing the local check does not make the test fail. Said so rather than implying otherwise.

*Not done:* attestation verification against the FIDO Metadata Service — it answers "is this
authenticator model one I trust", needs a metadata blob and its trust chain, and matters to
enterprises enforcing hardware policy rather than to most deployments. Also no `authhandlers` route
group and no `sqlbstore` adapter.

*Changed:* `passkey/` (new), `store/webauthn.go` (new), `memstore/webauthn.go` (new),
`storetest/credentials.go`, `audit/audit.go`, `schema.sql`, `go.mod`.
*Tests:* `passkey/` — against a virtual authenticator that holds an ES256 key and signs for real,
since every property worth checking is downstream of a signature actually verifying.

**T2.3 — Magic link and email OTP.** ✅ *Done.* New `emaillogin` package, new
`store.EmailLoginStore` port, `crypto.GenerateNumericCode`. This document called it the cheapest
feature on the list, and the plumbing was — but the code half is the T0.1 lesson again, and that part
was not cheap to get right.

**A six-digit code is a credential with twenty bits of entropy.** It survives only because of the
limit on guessing it, so that limit is the design:

- `MaxCodeAttempts` **destroys** the code rather than refusing the attempt. A counter that only gated
  would leave it live for the next request, and the budget is the point.
- **Requesting a new code deletes the old.** Ten live codes make guessing ten times easier and an
  attacker can ask for as many as they like — the same shape as the pending-2FA-session escape hatch
  T0.1 had to close.
- The code is hashed **with the address**, because six digits are not unique: two accounts can hold
  the same code simultaneously, and hashing the code alone would make one person's redeemable by
  another.
- A code cannot be redeemed through the link path, which does not count guesses.

**Accounts are created on redemption, never on request.** Creating one when the link is requested
would let anybody fill a user table with addresses they do not control by typing them into a form.
Redemption proves inbox control — which is also why the address arrives verified, with no second
confirmation email asking the user to prove what they just proved.

Every failure is one `ErrInvalidToken`: distinguishing "expired" from "wrong" says whether the code
was ever real, and request always succeeds regardless of whether the address is registered, with
`ErrSignUpDisabled` surfacing at redemption where only the inbox owner sees it.

*A test that could not fail, caught and fixed.* `crypto.GenerateNumericCode` uses rejection sampling,
because `b % 10` over a random byte over-produces digits 0–5 by about 4% — 256 is not a multiple of
10. The first distribution test used 60,000 digits and a 5% tolerance, and **passed against a
deliberately biased implementation**: the bias is roughly 1.6 standard deviations at that sample size.
Resized to a million digits with a 1% threshold, where the bias is about six standard deviations, it
now fails against the biased version as it should. A test that does not catch its own regression is
worse than no test, and this one did not until it was made to.

*Changed:* `emaillogin/` (new), `store/emaillogin.go` (new), `memstore/emaillogin.go` (new),
`crypto/usercode.go`, `storetest/user.go`, `audit/audit.go`, `schema.sql`.
*Tests:* `emaillogin/emaillogin_test.go`, `crypto/numericcode_test.go`.

**T2.4 — Optional server-side sessions.** ✅ *Done*, and smaller than this entry proposed in one
way and much larger in another. Designed in
[server-side-sessions.md](server-side-sessions.md).

*No `store.SessionStore`.* authit already had server-side sessions: a `store.RefreshToken` row is
one, and `ListSessions`/`RevokeSession` already read those rows and already called them sessions. A
new port would have been that row field for field, with `ListSessions` branching on mode to pick
between two identical tables. The gap was never storage — it was that the *access* credential
consulted none of it.

*One credential, not two.* `SessionModeOpaque` issues a single token; `TokenPair.RefreshToken` is
empty, the JSON field is omitted rather than sent blank, `Refresh` returns `ErrNotOpaqueSession` and
`POST /refresh` is not registered at all. The pair exists so the common path avoids a lookup; once
every request performs one, a second credential for avoiding lookups is ceremony. This makes opaque
mode a different API shape rather than a different token encoding, which is why it is a documented
mode and not a default.

*The expensive part: an `Authenticator` seam.* `authithttp.Validate` is a pure function — no
context, no I/O — and six route-group constructors took a `jwt.Verifier`. An opaque token cannot be
checked that way, so `authithttp.Authenticator` now sits where the verifier did, with two real
adapters behind it: `VerifierAuth` (today's behaviour, no I/O) and `SessionAuth` (a lookup). Six
signatures changed, free only because none of this is released. The seam is independently useful: it
is what a host needs to plug in a gateway header, an mTLS identity, or a session its own framework
issued.

*Sliding expiry, with a threshold.* `Config.SessionSlidingWindow` (a quarter of `RefreshTokenTTL` by
default, negative to disable) means using a session extends it only once enough of its life has
passed. Extending on every request is a write on every request, which is the cost that makes people
abandon server-side sessions. `store.RefreshTokenStore.TouchRefreshToken` does it, refusing revoked
rows — without that predicate a session revoked between a request's lookup and its extension comes
back with a fresh lifetime, revocation undone by the request it raced.

*A bug the end-to-end test caught that no unit test would have.* `ValidateSession` returns
`user.ErrInvalidToken`; `authithttp.StatusFor` knows only its own sentinels and answers 500 to
anything else. So revoking a session produced **500 on the next request** — an outage-shaped answer
to an ordinary "you are signed out", and exactly the confusion the `Authenticator` doc had just
finished warning about. `authhandlers.UserSessionAuth` translates, because `authhandlers` is the one
package that can see both. Nothing below the HTTP layer learned about HTTP.

*Not in scope, deliberately:* `superuser` stays JWT-only, `pat` already validates by lookup and
needed nothing, and there is no `freshAge` / re-authentication-for-sensitive-routes.

*Verified against Postgres.* `TouchRefreshToken`'s `revoked_at IS NULL` predicate — the thing
standing between a revocation and the request racing it — is exercised by the reference-schema
conformance run, not only by the in-memory fake.

*Changed:* `authithttp/authenticator.go` (new), `user/config.go`, `user/sessions.go`,
`user/register_login.go`, `user/errors.go`, `store/user.go`, `memstore/refresh_tokens.go`,
`sqlbstore/refreshtoken.go`, `storetest/user.go`, `authhandlers/` (six constructors, `dto.go`),
`schema.sql`. *Tests:* `user/opaque_session_test.go` (new),
`authhandlers/planes_test.go`.

**T2.5 — An optional `authz` package.** ✅ *Done*, with one deviation from this entry.

*Not its own module.* The entry says "in its own module, imported by nobody who does not want it".
The second half is true of any package — Go compiles what is imported — and the module split in this
repo exists for a different reason: `sqlbstore` and `authhandlers` are separate modules because they
drag `sqlb`/`pgx`, `oauth2` and `go-webauthn` into a host's module graph. `authz` depends on `store`
and nothing else, so a separate `go.mod` would buy no isolation and cost a `go.work` entry, a
release to tag, and version skew against the `store` types it is made of. In-tree package.

*What it is.* `authz.Action`, `authz.Policy`, `DefaultPolicy()`, `Can(store.Member, Action)`. No
resources, no wildcards, no runtime-stored roles, no inheritance — the things that let better-auth's
dynamic access control build exactly the mess §2.5 warns about. Unknown roles and unknown actions are
denied, so adding an `Action` here cannot silently widen a policy a host already wrote.

*`Can` takes a Member, not a Role*, because an inactive member is not authorized for anything and
that is the half of the check that gets left out: a deactivated colleague still has a membership row
with a role on it. `CanRole` exists for the case with no Member to consult and says in its name that
it is ignoring something.

*The vocabulary moved rather than being copied.* `authhandlers.TeamAction` and its constants are now
aliases for the `authz` ones, and `RoleAuthorizer` delegates to a `Policy` instead of re-implementing
the switch. That was the point: the escalation S4.3 fixed existed because the only correct check
lived behind an HTTP route group, so a host calling the `team` plane directly had to write its own —
and the one authit shipped was wrong. Two implementations of one rule is how they disagree.

*Does not reverse §2.5's argument.* Roles are still per-team strings, still cannot express a
principal that spans teams, and nothing in authit imports this to work. "Authorization is yours" and
"here is a correct owner/admin/member check" remain compatible claims.

*Changed:* `authz/` (new), `authhandlers/team.go`. *Tests:* `authz/authz_test.go`, each confirmed to
fail against the mutation it describes — including restoring the admin-may-manage-owners grant that
was the original escalation.

### Tier 3 — developer experience

**T3.1 — `authitctl`.** `authitctl schema print --dialect postgres|sqlite|mysql` (emit the DDL, which
today is a hand-maintained `schema.sql` for Postgres only) and `authitctl superuser create`. That is
the genuinely useful half of better-auth's CLI. Skip migrations — authit does not own the schema and
should not pretend to.

**T3.2 — OpenAPI document for `authhandlers`.** Hand-written YAML is fine; it is a fixed route set.

**T3.3 — Fill in the README's status.** "Early scaffold… not yet used in a production app" plus the
Tier 0 items above is an accurate combination, but the README should name the specific caveats
(permanent lockout, no password policy, HS256-only) rather than leaving them to be discovered.

### Tier 4 — findings from the security review of this branch

A `/security-review` pass over the 16 commits found three issues, each confirmed by an independent
adversarial verification before being acted on. All three are fixed; a fourth, non-security crash
turned up while reproducing one of them.

**S4.1 — The WebAuthn ceremony cookie was unauthenticated, which was an account takeover.** ✅
`setCeremonyCookie` wrote `base64(json(SessionData))` with no MAC and kept no server-side copy, so
every field of the ceremony was attacker-chosen. That was not merely untidy: `wan.SessionData`
carries per-ceremony overrides for the origin allowlist and RP id, and go-webauthn prefers them over
`Config` at verification time — `GetOrigins` returns `[]string{Origin}` whenever `Origin` is set, and
`Config.RPOrigins` is only ever enforced at Begin. An attacker with a page on any origin under the
registrable domain could harvest an assertion at `https://evil.example.com` and replay it to
`/passkeys/login/finish` with a hand-made cookie naming its own one-entry allowlist, and be issued a
session for the victim. `HttpOnly`, `Secure` and `SameSite=Strict` were worth nothing — the attacker
mints the `Cookie` header itself and never involves the victim's browser.

Fixed in two independent places, because one of them protects hosts that never touch `authhandlers`:

- `authhandlers` now HMACs the cookie under a required `WithCeremonyKey`, with the cookie's own name
  inside the MAC so a registration ceremony cannot be presented as a login one. The key is required
  and panics at construction: there is no safe default, since a per-process key breaks across
  replicas and anything derivable here is derivable by an attacker.
- `passkey.decodeSession` now strips `Origin` and `RelyingPartyID` outright and refuses a session
  with no `Expires`. The `Session` doc always said it must not be attacker-controlled; a guarantee
  that survives only correct storage is one this package can enforce for itself, in three lines.

*A test that could not fail, caught and fixed — twice, on the same test.* The first version of the
forgery test built its forged cookie by hand, without an `expires`. It passed against the unfixed
code, because `decodeSession` rejects a malformed session with `ErrSession` and `writePasskeyError`
maps that to the same `ceremony_missing` the test was asserting — a pass that had nothing to do with
the MAC. The second version derived the forgery by stripping 32 bytes off a genuine `Set-Cookie`,
which passed too: with the MAC removed there are no 32 bytes to strip, so the leftover was malformed
and took the same path. Only the third version bites — it mints a real session from
`BeginDiscoverableLogin` and encodes it raw, which is what an attacker actually writes and is
independent of the layout of the thing under test. Verified by reverting the MAC.

**S4.2 — The ceremony challenge is not single-use.** ✅ Same root cause as S4.1, separate fix, and
the one that needed a design decision rather than a patch. Nothing recorded that a challenge was
issued, so nothing could record that it was spent; `go-webauthn`'s clone check exempts
`authDataCount == 0 && SignCount == 0`, which is every synced passkey, since a credential shared
across devices cannot keep a coherent counter. Signing the cookie bounded it — a replay then needed
both the cookie and the body, inside the 60-second window — but did not close it.

Closed by `store.WebAuthnChallengeStore`, specified in
[webauthn-challenge-store.md](webauthn-challenge-store.md). `passkey.Session` is now a 32-byte
handle; the ceremony state lives in a row that `Finish` redeems exactly once. The port is two
methods, and the second carries the property: `ConsumeWebAuthnChallenge` deletes and returns, and
exactly one of N concurrent callers may receive the row.

*The stateless mode was dropped rather than kept as an option.* The spec proposed keeping it and
listed the argument against as an open question; the argument won. A documented weaker mode is a
mode somebody runs, and `passkey.Stores.Challenges` being required costs a breaking change that is
free today and never will be again.

*What the port is not.* Not shared with T2.4's session store, though an earlier note here suggested
it: a session is read on every request, listed, refreshed and revoked, while a challenge is written
once and destroyed by its only read. One port covering both would be wider in exchange for nothing.

*A test that could not fail, caught and fixed.* The conformance suite's atomicity case — N
goroutines consume one handle, exactly one wins — **passed against a deliberately non-atomic store**
at eight racers and one round. The window between a read and a delete is nanoseconds and the
scheduler simply did not interleave. At 32 racers it fails on the first round. This is the third
time on this branch that a security test has had to be shown failing before it could be believed,
and the second where the first version was measuring nothing.

*Verified against Postgres, and the number is the argument.* The `sqlbstore` adapter's atomicity does
not come from `DELETE … RETURNING` — sqlb surfaces returned rows only to hooks — but from the
delete's own result deciding who won, which is exactly the kind of reasoning that should not be
believed until it has run. It has now run, under `-race`. Against a deliberately broken version, in
which the read decides and the delete is an afterthought, **32 of 32 concurrent consumers redeem the
same challenge.** The in-memory store lets 2 of 32 through for the same defect. So the fake makes
this look like a rare race and the database shows it is total, which is the whole case for the live
run in one number.

**S4.3 — A team admin could become owner and evict the founder.** ✅ `RoleAuthorizer` granted
`TeamActionManageMembers` to owners and admins alike, and `updateMemberRole` passed `req.Role`
through verbatim. `team.Service.UpdateMemberRole` guards only *demotion* of an existing owner, so an
admin could promote itself, thereby supplying the second owner that `requireNotLastOwner` counts, and
then delete the founder — who has no route back in, since a non-member is refused even
`TeamActionView`.

`owner` gates nothing else in this codebase, so this is a hostile-takeover and permanent-lockout
primitive rather than a confidentiality escalation, and it is rated medium on that basis. It is not
excused by "authz is yours": this is the authorizer the README's quickstart hands people, and §2.5 of
this document presents it as *"a correct owner/admin/member check you can use"*.

Fixed with a new `TeamActionManageOwners`, granted only to owners, required for granting `RoleOwner`
or for mutating a member who already holds it. Both routes are covered — gating only the role change
would have left the same grant available through `createInvitation`, since `AcceptInvitation` copies
the invitation's role onto the new member verbatim. A `TeamAuthorizer` written before this constant
falls to its `default` case and denies, which is the safe direction.

Deliberately *not* done: a whitelist of role strings. Arbitrary roles are a documented decision
(`schema.sql`, `store/team.go`); only `RoleOwner` is special, and only it is special-cased.

**S4.5 — Email-login tokens were spent by reading and writing them back.** ✅ Found by the
code-review pass, not the security one, and it is the same defect S4.2 was — one credential
redeemable twice — in the package next door. `consume` checked `UsedAt == nil` and then wrote
`UsedAt`, so two redemptions of one magic link both saw it unused and both succeeded. The
failed-guess counter had the identical shape and mattered more: read `Attempts`, write `Attempts+1`,
and guesses arriving together are charged as one — which is the whole budget that, per the package's
own doc, is the only reason a six-digit code is safe at all.

`store.EmailLoginStore.UpdateEmailLoginToken` is replaced by two methods that each do one atomic
thing: `MarkEmailLoginTokenUsed` (compare-and-set on `used_at IS NULL`, `ErrNotFound` if lost) and
`IncrementEmailLoginTokenAttempts` (returns the count the store computed). Winning the first is now
what authorises a redemption, so it happens before an account is resolved or created. The port got
narrower, not wider.

*The measurement that mattered.* The concurrency case for this was written as one round of 32
racers, the shape that worked for the challenge store. Against a store that reads, unlocks and then
writes it passed — so it was measured rather than argued about: **that implementation slips through
in roughly four rounds out of five**, because the window here is a mutex release rather than a
network round trip. At 200 rounds it is caught reliably. A single-round version of this test is
worse than none, since it reports a green tick for a magic link that signs two people in.

That is the fourth verification step on this branch to be wrong on the first attempt, and the second
where a mutated implementation failed to *compile* and the harness read the build error as a pass.
The proof loop now builds before it believes a result.

**S4.4 — `memstore.DeleteMember` left its secondary indexes holding freed ids.** ✅ Not a
vulnerability — a crash, found while reproducing S4.3. `DeleteMember` removed the id from `byID`
only, so `GetMemberByUserAndTeam` and `ListMembersByTeam` dereferenced a nil map value and panicked
the process on the next read after any member removal. Reachable over HTTP: remove a member, then
load the team. Both indexes are now pruned, and both readers skip a missing id rather than trusting
the index.

The conformance suite missed it because "update and delete" only checked `GetMember` afterwards. A
new case now deletes a member and then goes back in through *every* lookup, so both stores are held
to it. Verified by reverting the fix: the suite panics with `SIGSEGV`, exactly as the HTTP route did.

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

When this document was written the honest headline was not the feature comparison. It was that the
second factor was un-rate-limited (§2.7a) while the first factor was rate-limited into a
denial-of-service vector (§2.7c), and that backup codes carried 32 bits (§2.7b) — three things that
were the difference between a library that is early and one that is unsafe.

**All of Tier 0 is now fixed, and Tier 1 with it.** Tier 2 stands at T2.1–T2.3 plus T2.6; T2.4 and
T2.5 are unstarted, and Tier 3 is untouched. A later security review of that work found four more
issues, all fixed and recorded in Tier 4 — the largest of them, a passkey account takeover, existed
only because of code added by this plan, which is the argument for reviewing hardening work rather
than trusting it.

What that leaves is a library whose headline risk is no longer a list of defects but the ordinary
one: it is young, and the parts of it verified against a real database are still fewer than the
parts verified only against an in-memory fake. Decide about T2.4 on its merits. Porting anything
else from better-auth is still optimising the wrong axis.
