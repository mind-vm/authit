# Spec — T3.1, `authitctl`

Status: **proposed**, not implemented. Two decisions need settling; one of them narrows the item.

---

## 1. What the plan asked for

> **T3.1 — `authitctl`.** `authitctl schema print --dialect postgres|sqlite|mysql` (emit the DDL,
> which today is a hand-maintained `schema.sql` for Postgres only) and `authitctl superuser create`.
> That is the genuinely useful half of better-auth's CLI. Skip migrations — authit does not own the
> schema and should not pretend to.

Reading the code first changes both halves.

## 2. D1 — the dialects

**Recommendation: ship `--dialect postgres` only. Do not ship SQLite or MySQL DDL.**

There is no SQLite or MySQL anywhere in this repository — no store adapter, no conformance wiring, no
DDL, nothing. `grep -i sqlite` finds two prose mentions and a comment about timestamp precision. So
shipping DDL for them means **authoring two schemas by hand that nothing can run**, and keeping three
in sync by eye.

That is the mistake this branch has now documented twice. `sqlbstore` compiled, vetted and read
correctly for its whole life and was wrong on both of its first two live runs — a dropped
`CreatedAt`, then three bad conformance expectations. Unverified DDL for two dialects with no
adapter and no test would be the same bet, taken deliberately, in the file hosts copy to create their
production tables.

Postgres alone is worth shipping. `schema.sql` becomes `go:embed`-ed and printable, which is a real
convenience: a host consuming authit as a module has no copy of it on disk, and telling people to go
find a file in their module cache is how the file gets stale.

The other dialects become worth shipping the moment there is a conformance run that can verify them —
which is its own item, and a bigger one than a CLI.

## 3. D2 — where `superuser create` gets its database binding

This is the part the plan entry could not have known.

`authitctl superuser create` must write a row through `store.SuperuserStore`. authit ships **no
concrete Postgres implementation of any port.** `sqlbstore` is generic over a row type `R` the host
defines, and every concrete row type for the reference schema — `exampleUser`, `exampleSuperuser`,
and the rest — lives in **`sqlbstore/example_test.go`**, which nothing outside the test binary can
import.

So the CLI needs a binding that does not currently exist as real code. Three ways:

**(a) Promote the example row types into a real package. Recommended.** A new
`sqlbstore/refschema` holding the row types and store constructors for `schema.sql` exactly.

This is worth doing on its own merits, independent of the CLI. `example_test.go` is described in its
own comments as the wiring a host copies, and one of the two bugs the first live Postgres run found —
`ToRow` dropping the caller's `CreatedAt` on `failed_login_attempts`, which silently rebuilds the
permanent lockout Tier 0 removed — existed *because* that wiring is copy-paste-only and had never
been exercised as a unit anyone imports. Promoting it means the conformance run tests the thing
hosts actually get, rather than a test-only copy of it.

**(b) Have the CLI define its own row types.** A fourth copy of the same structs, drifting from
`schema.sql` and from `example_test.go` independently. No.

**(c) Drop `superuser create`.** Defensible — authit does not own the schema, so a CLI that writes to
an assumed one is in tension with the library's whole argument. But the tension is smaller than it
looks: the command would be explicitly *for the reference schema*, refuse to guess, and a host with
its own schema simply would not use it. Bootstrapping the first operator with a `psql` heredoc and a
hand-computed Argon2id hash is exactly the sharp edge a CLI should remove.

## 4. Shape

Its own module (`authitctl/`), because `superuser create` needs `pgx` and the root module must not
gain a driver — the same reason `sqlbstore` and `authhandlers` are separate.

```
authitctl schema print [--dialect postgres]
    Writes schema.sql to stdout. Exit 2 on an unsupported dialect, naming
    the ones that exist rather than silently emitting Postgres.

authitctl superuser create --dsn ... --email ... [--display-name ...]
    Reads the password from the terminal, never from a flag or an argument
    — a password in argv is in the process list and the shell history.
    Uses superuser.Service so the password is hashed, validated and audited
    the same way the running application would do it, rather than by an
    INSERT that agrees with it today.
    Refuses to be the second operator created this way? No — CreateSuperuser
    already requires a creator id and Bootstrap already refuses when any
    operator exists, so the command maps onto whichever applies.
```

Read the DSN from `--dsn` or the environment, and nothing else. No config file, no discovery.

## 5. Not in scope

- **Migrations.** The plan says skip them and it is right: authit does not own the schema, and a tool
  that migrates it would have to assume it did.
- **`schema diff`.** Same reason, and worse — it would need to know which deviations from the
  reference are the host's deliberate choices.
- **Anything touching users.** Creating an end-user account is the application's job; the operator
  bootstrap is the only case where there is no application yet to do it.

## 6. Open questions

1. **Is `superuser create` worth a `pgx` dependency and a module?** `schema print` alone needs
   nothing but `go:embed` and could live in the root module as a tiny `cmd/`. If `superuser create`
   goes, so does most of the cost — and the `refschema` package under D2(a) is still worth building
   for the conformance run alone.
2. **Should `refschema` be part of this item at all,** or its own change that lands first? It is the
   larger and more valuable half, and `authitctl` is arguably just its first consumer.
