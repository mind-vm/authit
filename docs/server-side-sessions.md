# Spec — T2.4, optional server-side sessions

Status: **proposed**, not implemented. Three decisions below need settling before code.

---

## 1. What T2.4 actually is

The plan entry reads:

> **T2.4 — Optional server-side sessions.** `store.SessionStore` plus `user.Config.SessionMode`
> (`SessionModeJWT` default, `SessionModeOpaque`). Opaque mode issues a random session token instead
> of a JWT and validates by lookup, buying immediate revocation for hosts that want it.

Written before the code was examined, and it is wrong in one load-bearing way: **authit already has
server-side sessions.** `store.RefreshToken` is a session row — user id, hashed token, expiry,
`RevokedAt`, user agent, IP, created-at — and `user.ListSessions`, `RevokeSession` and
`RevokeOtherSessions` already read it and already call the rows sessions. `authhandlers` already
serves `GET /me/sessions`, `DELETE /me/sessions/{id}` and `POST /me/sessions/revoke-others`.

So the gap is not storage. It is that **the access credential does not consult the storage that
already exists.** A revoked session stops being refreshable immediately; it keeps being *usable*
until the access JWT expires, because `authithttp.Validate` looks nothing up. That is the whole of
what T2.4 has to close, and it makes the item smaller than it looks in one dimension and much bigger
in another.

## 2. The three decisions

### D1 — A new `SessionStore`, or reuse the refresh-token row?

**Recommendation: reuse the row. Do not add `store.SessionStore`.**

A `SessionStore` as specified would carry user id, hashed token, expiry, revoked-at, user agent and
IP — field for field a `RefreshToken`. Two tables would then mean the same thing, `ListSessions`
would have to branch on mode to decide which one it is listing, and a host would implement two ports
to get one concept. That is the shallow-module trade the rest of this codebase keeps refusing.

The objection, and it is real: a refresh token is **single-use** — `Refresh` rotates it, and
replaying a revoked one is treated as compromise and revokes the whole family. A session token is
**multi-use** by definition; validating it on every request must not look like reuse. So the row is
shared but the semantics are not, and the code has to keep them apart rather than pretend they are
the same. Concretely: reuse detection is a property of the *refresh* path, not of the row, and
opaque mode has no refresh path at all — see D2.

### D2 — Does opaque mode still have a refresh token?

**Recommendation: no. One credential.**

In JWT mode the pair exists for a reason: a short access token that needs no lookup, and a long
refresh token that does. Remove the first half's defining property and the pair loses its point —
if every request hits the database anyway, a second credential to avoid hitting the database is
ceremony.

So opaque mode issues one token, validated by lookup on every request, with a sliding expiry
(extended on use, past a threshold, as better-auth does). `TokenPair.RefreshToken` is empty,
`Refresh` returns an error naming the mode, and `POST /refresh` answers 404 rather than pretending.
That is a genuinely different API shape, not a different encoding — the sharpest thing about this
change and the reason it should be a documented mode rather than a quiet default.

### D3 — How does a protected route validate an opaque token?

This is the expensive part, and it is why T2.4 is bigger than it reads.

`authithttp.Validate(v jwt.Verifier, r *http.Request)` is pure: no context, no I/O, no error path
for "the database is down". An opaque token cannot be validated that way — it needs a `ctx` and a
lookup. And `authhandlers.requireUser` takes a `jwt.Verifier`, as do **all seven** route-group
constructors, so every protected route in the library is built on the assumption that authentication
is a pure function.

**Recommendation: introduce an `Authenticator` seam.**

```go
// Authenticator turns a request into a verified principal.
type Authenticator interface {
    Authenticate(ctx context.Context, r *http.Request) (jwt.Claims, error)
}
```

Two adapters, which is what makes it a real seam rather than a hypothetical one:

- `authithttp.VerifierAuth(v jwt.Verifier)` — today's behaviour, no I/O, ignores `ctx`.
- `user.Service` — looks the token up, returns `ErrInvalidToken` for revoked or expired.

Every constructor takes an `Authenticator` instead of a `jwt.Verifier`. That is a breaking change to
seven signatures, and free today because none of this is released.

The cost to be honest about: a host in opaque mode pays a database round trip per request on every
protected route, and `StatusFor` must now distinguish "not authenticated" (401) from "the session
store is down" (500). The second is the part hosts get wrong, so `Authenticate` returns the same
classified errors `Validate` does.

## 3. What is deliberately not in scope

- **The operator plane.** `superuser` keeps JWT-only. An operator session is rare, short and already
  audited; the case for immediate revocation is weakest exactly where the blast radius argument is
  loudest, because operators are few and known. Revisit separately, not as a rider on this.
- **`pat`.** Personal access tokens are already opaque and already validated by lookup. They need
  nothing.
- **Sliding-expiry tuning.** One `SessionSlidingWindow` knob, defaulted; no `freshAge`, no
  re-authentication-for-sensitive-routes. Those are better-auth features worth their own item.

## 4. Work items, once the decisions are settled

| | |
|---|---|
| `user/config.go` | `SessionMode` (`SessionModeJWT` default, `SessionModeOpaque`), `SessionSlidingWindow` |
| `user/register_login.go` | `issueTokenPair` branches: opaque mode mints one token, no JWT |
| `user/sessions.go` | `ValidateSession(ctx, token) (store.User, error)`, sliding-expiry extension |
| `store/user.go` | `RefreshToken` doc: it is the session row in both modes; `TouchRefreshToken` for sliding expiry |
| `authithttp/` | `Authenticator`, `VerifierAuth`, `StatusFor` unchanged in meaning |
| `authhandlers/` | seven constructors take `Authenticator`; `/refresh` 404s in opaque mode |
| `memstore`, `storetest`, `schema.sql` | sliding-expiry write, and its conformance case |
| `README.md`, `docs/comparison.md` | §2.2 currently says authit *cannot* do this; it becomes a mode |

## 5. Open questions

1. **Is opaque mode worth its cost at all?** §2.2 of `comparison.md` argues authit's JWT model is
   right for "APIs, CLIs, and multi-service fan-out", and that what is missing is *the option*. This
   spec grants the option at the price of a seam every route group crosses. If the honest answer is
   that hosts wanting immediate revocation should re-resolve the principal themselves — which
   `authithttp.Validate` already documents — then T2.4 is a documentation item and not a code one.
   I do not think that is right, but it is the question worth asking before seven signatures change.
2. **Should `Authenticator` land regardless?** It is independently useful: it is the seam a host
   needs to plug in *any* credential — an API gateway header, mTLS, a session cookie — and it is the
   only part of this change that survives if D1/D2 are decided differently.
3. **Sliding expiry writes on every request.** Extending an expiry means a write per request, which
   is what better-auth's `updateAge` threshold exists to avoid. Default the threshold high, or skip
   sliding expiry in v1 and let sessions have a fixed lifetime?
