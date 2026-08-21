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
- **Authorization is the caller's job.** `team` methods that change roles or remove members do not check the caller's own role — a host application resolves the caller's `Member` (via `GetMemberByUserAndTeam`) and checks it before calling. This keeps authit's authorization model unopinionated about your app's specific rules.

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

## What's deliberately not included

- **HTTP handlers/routing.** authit is a service layer, not a web framework — wire it into your own router (chi, net/http, huma, ...).
- **Email delivery.** `user.EmailSender` is an interface; bring your own SMTP/API client.
- **Social/OAuth login, RBAC policy engines, audit logging.** Out of scope for now; `team.Role` and `store.Member.Role` are plain strings you can extend, and `superuser.Impersonate`'s doc comment notes where a host app should hook in its own audit trail.

## Status

Early scaffold. Core flows are implemented and tested (see `go test ./...`), but this has not yet been used in a production app.
