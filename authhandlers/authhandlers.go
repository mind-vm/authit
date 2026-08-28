// Package authhandlers is an opt-in HTTP route group for authit's user
// plane: register, login, refresh, logout, password reset, email
// verification, two-factor auth, and session management, wired over the
// same user.Service a host would otherwise call directly.
//
// It depends on nothing beyond net/http and authit itself — no router, no
// OpenAPI generator, no framework of any kind. NewUserHandler returns a
// plain http.Handler (a *http.ServeMux using Go 1.22's method+pattern
// routing), which a host mounts wherever it likes:
//
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", http.StripPrefix("/auth", authhandlers.NewUserHandler(svc, signer)))
//
// It is a separate module (its own go.mod) so that importing authit's core
// never pulls this in, and importing this never pulls anything beyond
// authit's core in turn — the same shape as sqlbstore.
//
// # Scope
//
// This package covers the user plane only. team, superuser, pat, and
// device are not wired here; a host that wants HTTP routes for those
// follows the same pattern (a thin http.Handler over the service) itself,
// or authhandlers grows a matching NewXHandler later.
//
// # What it does not do
//
// CORS, rate limiting, request logging, TLS, and routing beyond this
// handler's own subtree are the host's job — this package assumes it is
// mounted behind whatever the host already has. Protected routes (session
// management, password change, 2FA management) authenticate the caller by
// validating the request's bearer token with the same key material the
// host's user.Service uses (via authithttp.Validate) and using
// claims.Subject as the user id; there is no cookie or CSRF handling.
package authhandlers

import (
	"net"
	"net/http"

	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/user"
)

// UserHandler serves authit's user-plane routes.
type UserHandler struct {
	svc      *user.Service
	verifier authitjwt.Verifier
	ip       func(*http.Request) string
}

// Option configures NewUserHandler.
type Option func(*options)

type options struct {
	ip func(*http.Request) string
}

// WithIPExtractor overrides how the client IP recorded on login/refresh is
// read from a request — e.g. to trust X-Forwarded-For behind a reverse
// proxy. The default reads the host part of r.RemoteAddr, which is only
// correct for a directly-connected client.
func WithIPExtractor(fn func(*http.Request) string) Option {
	return func(o *options) { o.ip = fn }
}

func defaultIPExtractor(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// NewUserHandler builds the user-plane route group. svc is a *user.Service
// the host has already constructed; verifier must verify the same tokens
// svc issues, since protected routes validate bearer
// tokens against it directly.
//
// Public routes (no Authorization header required):
//
//	POST /register
//	POST /login
//	POST /login/two-factor
//	POST /refresh
//	POST /logout
//	POST /password/reset-request
//	POST /password/reset
//	POST /email/verify
//	POST /email/verification-request
//
// Protected routes (Authorization: Bearer <access token>):
//
//	POST   /password/change
//	POST   /me/email/verification-request
//	GET    /me/sessions
//	DELETE /me/sessions/{id}
//	POST   /me/sessions/revoke-others
//	POST   /me/two-factor/setup
//	POST   /me/two-factor/confirm
//	POST   /me/two-factor/disable
//	POST   /me/two-factor/backup-codes/regenerate
//	GET    /me/two-factor
func NewUserHandler(svc *user.Service, verifier authitjwt.Verifier, opts ...Option) http.Handler {
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	h := &UserHandler{svc: svc, verifier: verifier, ip: o.ip}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", h.register)
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("POST /login/two-factor", h.verifyTwoFactorLogin)
	mux.HandleFunc("POST /refresh", h.refresh)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("POST /password/reset-request", h.requestPasswordReset)
	mux.HandleFunc("POST /password/reset", h.resetPassword)
	mux.HandleFunc("POST /email/verify", h.verifyEmail)
	mux.HandleFunc("POST /email/verification-request", h.requestEmailVerificationByEmail)

	mux.HandleFunc("POST /password/change", h.withAuth(h.changePassword))
	mux.HandleFunc("POST /me/email/verification-request", h.withAuth(h.requestEmailVerification))
	mux.HandleFunc("GET /me/sessions", h.withAuth(h.listSessions))
	mux.HandleFunc("DELETE /me/sessions/{id}", h.withAuth(h.revokeSession))
	mux.HandleFunc("POST /me/sessions/revoke-others", h.withAuth(h.revokeOtherSessions))
	mux.HandleFunc("POST /me/two-factor/setup", h.withAuth(h.beginTwoFactorSetup))
	mux.HandleFunc("POST /me/two-factor/confirm", h.withAuth(h.confirmTwoFactorSetup))
	mux.HandleFunc("POST /me/two-factor/disable", h.withAuth(h.disableTwoFactor))
	mux.HandleFunc("POST /me/two-factor/backup-codes/regenerate", h.withAuth(h.regenerateBackupCodes))
	mux.HandleFunc("GET /me/two-factor", h.withAuth(h.twoFactorStatus))

	return mux
}

// authedHandlerFunc is an http.HandlerFunc that additionally receives the
// caller's claims, resolved from a validated bearer token.
type authedHandlerFunc func(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims)

func (h *UserHandler) withAuth(next authedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := authithttp.Validate(h.verifier, r)
		if err != nil {
			writeError(w, authithttp.StatusFor(err), "unauthorized", err.Error())
			return
		}
		next(w, r, claims)
	}
}
