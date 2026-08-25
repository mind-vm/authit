# authit example — plain HTTP

A runnable server that mounts authit's user plane on a stdlib `http.ServeMux`
and backs it with `memstore`. No database, no config file, no environment
variables:

```sh
go run ./cmd/example
```

It listens on `:8080` (`-addr` to change). `GET /` prints the route list.

The point of this directory is that nothing else in the repo is runnable — the
package tests prove the parts, and this proves they fit together. It is a demo,
not a deployment: signing keys are random per boot (so a restart invalidates
every issued token), all state is in memory, and there is no TLS, CORS, or rate
limiting.

## Why the emailer prints to stdout

`user.EmailSender` is an interface, and this example implements it by printing
to the terminal instead of delivering mail. That's what makes the whole thing
curl-able: password-reset and email-verification tokens are single-use secrets
the service hands to the emailer and never returns over HTTP, so without a
visible emailer those two flows can't be driven from the outside at all.

## Walkthrough

Register. Note that `Register` does *not* send a verification mail on its own —
requesting one is a separate call, so a host can decide whether a given signup
path needs it:

```sh
curl -s -X POST localhost:8080/auth/register \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```
```json
{"id":"c1665731-...","email":"alice@example.com","email_verified":false,"created_at":"..."}
```

Logging in now fails, because `EmailVerificationRequired` is authit's default:

```sh
curl -s -X POST localhost:8080/auth/login \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```
```json
{"error":"email_not_verified","message":"authit/user: email not verified"}
```

Ask for the verification mail, then read the token off the server's stdout:

```sh
curl -s -X POST localhost:8080/auth/email/verification-request \
  -d '{"email":"alice@example.com"}'          # 204

curl -s -X POST localhost:8080/auth/email/verify \
  -d '{"token":"<token from the server log>"}' # 204
```

Now login returns a token pair:

```sh
curl -s -X POST localhost:8080/auth/login \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```
```json
{"requires_two_factor":false,"tokens":{"access_token":"eyJ...","refresh_token":"0l-85...","expires_at":"..."}}
```

The access token is what protected routes want:

```sh
curl -s localhost:8080/auth/me/sessions -H "Authorization: Bearer $ACCESS"   # 200
curl -s localhost:8080/auth/me/sessions                                       # 401
```

Password reset runs through stdout the same way as verification —
`/auth/password/reset-request`, read the token, then `/auth/password/reset` with
`{"token","new_password"}`. Afterwards the old password returns
`401 invalid_credentials`.

Start the server with `-require-verification=false` to skip the verification
step entirely; that sets `user.Config.EmailVerification` to
`EmailVerificationOptional`.

## Watching the audit log

The example passes `audit.SlogLogger`, so security events land in the same
stream as everything else. Driving the flow above produces:

```
level=INFO  msg="authit audit event" event_type=user.registered        result=success
level=WARN  msg="authit audit event" event_type=user.login.failed      result=denied  reason=email_not_verified
level=INFO  msg="authit audit event" event_type=user.email.verified    result=success
level=INFO  msg="authit audit event" event_type=user.login.succeeded   result=success
level=INFO  msg="authit audit event" event_type=user.token.refreshed   result=success
level=INFO  msg="authit audit event" event_type=user.password.reset    result=success
```

Leaving `Config.AuditLogger` nil turns all of it off; that's the default.

## Swapping memstore for a real database

The `user.Stores` literal in [main.go](main.go) is the only place the storage
choice appears. Replacing those seven constructors with `sqlbstore` tables
against a `pgxpool.Pool` changes nothing else in the file — the service, the
handler, the routes, and every response above stay exactly as they are.

That substitution is authit's central design claim, and
[`sqlbstore/example_test.go`](../../../sqlbstore/example_test.go) is the worked
version of it: a row type and a filled-in `Table[R, T]` for every store here,
run against [`schema.sql`](../../../schema.sql) on a real Postgres.
