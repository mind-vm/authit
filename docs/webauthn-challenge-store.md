# Spec — `store.WebAuthnChallengeStore`

Status: **proposed**, not implemented. Closes S4.2 in [comparison.md](comparison.md).

---

## 1. The problem

`passkey` hands the WebAuthn ceremony state to the caller and takes it back at Finish:

```go
opts, sess, err := svc.BeginDiscoverableLogin(ctx)   // sess is the state
res, err := svc.FinishDiscoverableLogin(ctx, sess, r)
```

Nothing records that a challenge was issued, so nothing can record that it was spent. The same
`sess` and the same assertion body succeed as often as they are presented.

The signature counter does not save this. `go-webauthn`'s clone check exempts
`authDataCount == 0 && SignCount == 0`, and a credential synced across devices cannot keep a
coherent counter — so iCloud Keychain and Google Password Manager passkeys report zero forever.
For those credentials there is no replay defence at all.

Signing the ceremony cookie (shipped, `0127373`) removed the severe half: the challenge can no
longer be chosen and the expiry can no longer be suppressed. What remains is an attacker holding
**both** the cookie and the assertion body — one request-log line, one APM trace, one debug proxy —
replaying inside the 60-second window. That is bounded, not closed, and only server-side state
closes it.

## 2. Why the package's stated objection no longer holds

`passkey.Session` says:

> authit does not keep it, for the same reason it does not keep OAuth state: it belongs to one
> browser for one minute, and holding it would mean another store port and a cleanup problem.

Both halves of that are already contradicted inside authit. `store.PendingTwoFactorStore` is a
short-lived, single-use, server-side ceremony record — issued after a correct password, exchanged
for a real session, five-minute TTL, its own table (`pending_two_factor_sessions`). It is the same
shape as what this spec proposes, for the same reason, in the same library. The 2FA ceremony keeps
its state; the passkey ceremony is the outlier.

The cleanup problem is likewise not new: `password_reset_tokens`, `email_verification_tokens`,
`email_login_tokens` and `pending_two_factor_sessions` all accumulate expired rows, and authit ships
no sweeper for any of them. Adding a fifth table with that property costs nothing that the first
four did not already cost.

What *was* true is that this is a cost, and it should stay optional. See §5.

## 3. Where the seam goes

**The seam is `passkey.Stores`, not `passkey.Session`.** `Session` is already `[]byte` and already
documented as opaque — "bytes rather than a struct so that the WebAuthn library's types do not leak
into authit's API." Hosts store it and hand it back; nothing reads it.

So the mode change is invisible at the interface. With a challenge store configured, `Session`
carries a random handle instead of the marshalled ceremony state. `BeginLogin` and `FinishLogin`
keep their signatures, `authhandlers` keeps its cookie, and every host keeps its code. The cookie
gets shorter; nothing else moves.

That is the property worth protecting in review: **if this change requires callers to learn
anything new beyond one config field, the design is wrong.**

## 4. The port

```go
// WebAuthnChallenge is one in-flight WebAuthn ceremony.
//
// Data is the ceremony state, opaque to the store: whatever the passkey
// package serialises, round-tripped byte for byte. Store it as bytes, not
// text -- it is not UTF-8.
type WebAuthnChallenge struct {
    ID        string
    // TokenHash is the hash of the handle held by the browser. The handle
    // itself is never stored, for the same reason a refresh token is not.
    TokenHash string
    // UserID is the account a *registration* ceremony belongs to, and nil
    // for a discoverable login, which names no user by design.
    //
    // authit never looks a challenge up by it. It is denormalised out of
    // Data so a host can put a foreign key here and have ceremonies
    // cascade away with the account -- the same reason WebAuthnCredential
    // carries fields it does not strictly need.
    UserID    *string
    Data      []byte
    ExpiresAt time.Time
    CreatedAt time.Time
}

// WebAuthnChallengeStore persists in-flight WebAuthn ceremonies.
type WebAuthnChallengeStore interface {
    CreateWebAuthnChallenge(ctx context.Context, c *WebAuthnChallenge) error

    // ConsumeWebAuthnChallenge atomically deletes the challenge and
    // returns what it held, or ErrNotFound if no live row matched.
    //
    // Atomic is the whole method. Two callers presenting the same handle
    // concurrently must not both receive a row: exactly one deletes it and
    // sees it, the other gets ErrNotFound. A Get followed by a Delete is
    // NOT an implementation of this, however the two calls are ordered --
    // that is the race this port exists to remove, and it is the race that
    // makes a captured assertion replayable.
    //
    // In SQL this is one statement:
    //
    //     DELETE FROM webauthn_challenges WHERE token_hash = $1 RETURNING *
    //
    // Expiry is not judged here. An expired row is returned like any
    // other, and refused by the passkey package; consuming it is still the
    // right outcome, since a spent challenge should not linger either way.
    ConsumeWebAuthnChallenge(ctx context.Context, tokenHash string) (*WebAuthnChallenge, error)
}
```

Two methods. There is deliberately no `Get`, because a caller that can read without consuming can
replay; no `Update`, because a challenge is written once; and no `DeleteExpired`, because no other
port in authit ships a sweeper and this one should not be the exception (§7).

### Why `Consume` and not `Get` + `Delete` in a transaction

`user.VerifyTwoFactorLogin` gets its single-use property by deleting the pending session inside the
same `RunInTx` that issues the token pair. That works, but it makes the security property depend on
`store.TxRunner`, which is **optional** — a host that leaves `Tx` nil gets a 2FA session that two
concurrent requests can both spend.

For a passkey challenge that failure mode *is* the vulnerability, so it must not be optional.
Folding delete-and-return into one method makes single-use an invariant of the port rather than a
property of how the caller happens to sequence two calls, and makes it assertable by the conformance
suite. `TxRunner` stays orthogonal and is not required by this flow.

*(`PendingTwoFactorStore` arguably wants the same treatment. Out of scope here; noted so the
inconsistency is deliberate rather than forgotten.)*

## 5. Wiring and modes

```go
type Stores struct {
    Users       store.UserStore
    Credentials store.WebAuthnCredentialStore
    Tx          store.TxRunner              // optional, unchanged
    Challenges  store.WebAuthnChallengeStore // optional; see below
}
```

**`Challenges` nil — stateless mode.** Exactly today's behaviour. `Session` carries the marshalled
ceremony state. Forgery is prevented (the cookie is MAC'd, `decodeSession` strips the origin and RP
id overrides and requires an expiry), but a captured cookie-plus-body replays within the ceremony
TTL against a counter-0 authenticator.

**`Challenges` set — handle mode.** `Session` carries 32 random bytes; the ceremony state lives in
the store under the hash of those bytes. Finish consumes it. A replay finds nothing and is refused
identically to a stale one. The cookie MAC becomes defence in depth rather than the load-bearing
check — forging a handle now means guessing a live 256-bit value.

Optional rather than required, matching `Tx`: a host that will not add a table should still get a
working passkey flow, and the stateless mode is no longer *unsafe*, only weaker. The package doc
must state the residual in those words rather than implying parity. `NewService` does not warn or
panic — authit does not nag — but `passkey`'s doc comment and the README both name which mode gives
which property.

### Ceremony-type binding

The stored `Data` records which ceremony issued it, and Finish refuses a mismatch: a handle from a
registration ceremony presented to `FinishDiscoverableLogin` is `ErrSession`, and the reverse.

This is not hypothetical. better-auth shipped the same fix in
[#9993](https://github.com/better-auth/better-auth/pull/9993) — *"A passkey registration can no
longer be completed with a challenge that was issued for authentication, or the reverse."* authit
gets this at the HTTP layer today via distinct cookie names bound into the MAC, but the service
layer should not depend on its caller having done that, and hosts calling `passkey` directly get
nothing from the cookie name.

The kind lives inside `Data`, not in the port. The store never looks up by it, so putting it in a
column would widen the interface for the host's benefit only — and unlike `UserID` there is no
foreign key to hang on it.

## 6. Reference schema

```sql
-- store.WebAuthnChallengeStore / store.WebAuthnChallenge.
-- In-flight WebAuthn ceremonies. Short-lived (passkey Config.Timeout, 60s
-- by default) and consumed on first use: FinishLogin deletes the row and
-- reads it in one statement, which is what makes a captured assertion
-- unreplayable.
--
-- The UNIQUE on token_hash is required, not decorative: it is the only
-- thing a ceremony is found by.
--
-- user_id is set for registration and NULL for discoverable login, which
-- names no account by design. authit never queries by it; it is here so
-- ceremonies cascade away with the account.
CREATE TABLE webauthn_challenges (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash text        NOT NULL UNIQUE,
    user_id    uuid        REFERENCES users(id) ON DELETE CASCADE,
    data       bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Expired rows are never returned to a caller that matters, but nothing
-- removes them either -- as with password_reset_tokens and the other
-- short-lived tables, sweeping is yours:
--   DELETE FROM webauthn_challenges WHERE expires_at < now();
CREATE INDEX webauthn_challenges_expires_at_idx ON webauthn_challenges (expires_at);
```

## 7. Conformance suite

`storetest.RunWebAuthnChallengeStore`, run against `memstore` on every `go test ./...` and against
`schema.sql` when `MYBRAIN_DATABASE_URL` is set. Cases:

1. Create then consume returns the row, `Data` byte-identical.
2. A second consume of the same hash returns `store.ErrNotFound`.
3. An unknown hash returns `store.ErrNotFound`, not `nil, nil`.
4. Consuming one challenge leaves another untouched.
5. An expired row is still returned (expiry is the caller's judgement, §4).
6. **Concurrency: N goroutines consume the same hash; exactly one gets a row.** This is the case the
   port exists for, and the only one that can catch a `Get`-then-`Delete` implementation. It is also
   the one that means little against `memstore` (a mutex makes it trivially true) and everything
   against Postgres — so it is the strongest argument yet for the live-database run being part of
   the loop rather than an optional extra.

Per the working agreement, each case gets reverted-behaviour proof before it is trusted. Case 6
specifically must be shown to fail against a deliberate `Get`-then-`Delete` adapter, or it is not
testing what it claims.

## 8. Work items

| | |
|---|---|
| `store/webauthn.go` | the type and port above |
| `passkey/ceremony.go` | handle generation, `Data` wrapper with the ceremony kind, consume-and-check at Finish, kind mismatch → `ErrSession` |
| `passkey/passkey.go` | `Stores.Challenges`, package doc naming both modes and the residual of the weaker one |
| `memstore/webauthn.go` | adapter; consume under the existing mutex |
| `storetest/credentials.go` | the suite in §7 |
| `schema.sql` | §6 |
| `sqlbstore/` | adapter + wiring into the live conformance run — the `DELETE ... RETURNING` is the part worth testing against a real database |
| `README.md`, `docs/comparison.md` | S4.2 closed; both modes stated |

Tests before implementation, and the replay test at the `authhandlers` layer — capture a genuine
cookie and body, replay both, expect refusal — is the one that proves the vulnerability is actually
gone rather than merely narrowed.

## 9. Rejected: sharing a port with T2.4

An earlier suggestion of mine was to design this together with T2.4 (optional server-side sessions),
since both are "opaque handle → server-side record." Having looked at both, **they should not share
a port.** A session is long-lived, read on every request, refreshed, listed per user, and revoked
individually or in bulk; a challenge is written once, read once, and destroyed by that read. A port
covering both is either a session store with a pointless `Consume` or a challenge store carrying
list-and-revoke it never uses — a wider interface in exchange for nothing, which is the definition
of the shallow module this codebase keeps avoiding.

They share a *pattern*, and the pattern is worth applying twice. That is all.

## 10. Open questions

1. **Should stateless mode survive at all?** Keeping it means shipping a documented weaker mode
   forever. Removing it means a required table and a breaking change to `passkey.Stores` — cheap
   now, since neither `passkey` nor `authhandlers` has been released. The spec assumes it survives;
   the argument for deleting it is not weak.
2. **Handle length.** 32 bytes matches `GenerateOpaqueToken` and every other authit credential. No
   reason to differ, but it is the number to object to now rather than after the schema exists.
3. **Should `PendingTwoFactorStore` get the same `Consume` treatment?** Its single-use property
   currently depends on the optional `TxRunner`. Same defect, lower severity, separate change.
