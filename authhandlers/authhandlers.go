// Package authhandlers is an opt-in set of HTTP route groups for authit,
// wired over the same services a host would otherwise call directly. One
// constructor per plane, each returning a plain http.Handler:
//
//	NewUserHandler        register, login, refresh, logout, password reset,
//	                      email verification, 2FA, session management
//	NewTeamHandler        teams, membership, roles, invitations
//	NewSuperuserHandler   operator login and account management, impersonation
//	NewPATHandler         the caller's own personal access tokens
//	NewDeviceHandler      the RFC 8628 device authorization grant
//	NewOIDCHandler        sign-in with an external identity provider
//	NewPasskeyHandler     WebAuthn registration, login and management
//	NewEmailLoginHandler  magic links and sign-in codes
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
// never pulls this in — the same shape as sqlbstore.
//
// # Dependencies
//
// This package used to depend on nothing beyond net/http and authit's core.
// It no longer can: the oidc and passkey groups exist to serve those
// packages, so importing this module now also brings in golang.org/x/oauth2
// and go-webauthn/webauthn with its own tree.
//
// That is a real cost to the module graph and to `go mod download`, and it
// is worth knowing about. It is not a cost to your binary: Go links only
// reachable code, so a host that never calls NewPasskeyHandler ships none
// of the WebAuthn implementation. If the download size matters to you
// anyway, call the service packages directly and write the eight routes
// yourself — everything here is a thin translation of them.
//
// # Mount them separately
//
// They are separate handlers rather than one tree because they do not
// belong at the same place. NewSuperuserHandler is an operator surface that
// most deployments should keep off the public internet entirely, and
// NewDeviceHandler speaks OAuth wire format (form-encoded requests, RFC
// 6749 error bodies) rather than this package's own JSON conventions.
//
//	mux.Handle("/auth/", http.StripPrefix("/auth", authhandlers.NewUserHandler(users, verifier)))
//	mux.Handle("/api/", http.StripPrefix("/api", authhandlers.NewTeamHandler(teams, auth,
//		authhandlers.RoleAuthorizer{Teams: teams})))
//	mux.Handle("/api/", http.StripPrefix("/api", authhandlers.NewPATHandler(pats, verifier)))
//	adminMux.Handle("/", authhandlers.NewSuperuserHandler(supers))
//
// # Two constructors demand an argument authit cannot supply
//
// NewTeamHandler requires a TeamAuthorizer, and NewDeviceHandler requires a
// DeviceTokenIssuer and a verification URI. Both panic without them, at
// startup rather than at the first request.
//
// This is deliberate. The team package does not check the caller's own role
// -- authorization is the host's model, and it says so -- which means a
// route group that only asked "is this request authenticated" would let any
// user change any member's role in any team. And device.PollDeviceToken
// resolves who approved a request without minting anything, because what
// credential a CLI should receive is the host's decision. Neither gap can
// be filled with a default that is safe everywhere, so neither gets one.
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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/user"
)

// UserHandler serves authit's user-plane routes.
type UserHandler struct {
	svc  *user.Service
	auth authithttp.Authenticator
	ip   func(*http.Request) string
}

// Option configures any handler constructor in this package.
//
// Not every option applies to every group: WithIPExtractor is read by the
// user and superuser groups, WithInsecureCookies and WithCeremonyKey by the
// oidc and passkey groups. An option a constructor does not read is
// ignored, not rejected.
//
// WithCeremonyKey is the exception to "optional": NewOIDCHandler and
// NewPasskeyHandler panic without it. It is spelled as an Option rather
// than a parameter so the other two constructors are not made to carry an
// argument they have no use for.
type Option func(*options)

type options struct {
	ip          func(*http.Request) string
	insecure    bool
	ceremonyKey []byte
}

// WithInsecureCookies drops the Secure attribute from the short-lived
// ceremony cookies the oidc, passkey and emaillogin groups set.
//
// Spelled this way round so the unsafe choice is the one you type. It
// exists for local development against http://localhost and has no other
// legitimate use.
func WithInsecureCookies() Option {
	return func(o *options) { o.insecure = true }
}

// WithCeremonyKey sets the key authenticating the short-lived ceremony
// cookies the oidc and passkey groups use. It is required by
// NewOIDCHandler and NewPasskeyHandler, which panic without it.
//
// It is required rather than defaulted because there is no default that is
// both safe and correct. Generating one per process would break the moment
// a host runs two replicas or restarts mid-ceremony, and any key this
// package could derive on its own would be one an attacker can derive too.
// Only the host knows a secret that is stable across its instances.
//
// Use at least 32 random bytes, keep it out of the source tree, and treat
// it as a secret: whoever holds it can mint a ceremony cookie, which is
// what these routes verify their side of the ceremony against. Rotating it
// invalidates every in-flight ceremony -- a failed sign-in attempt the user
// retries, not a lockout.
//
// It may be the same secret used elsewhere only if that secret is not also
// handed to something that signs attacker-supplied bytes with it. A
// dedicated key costs nothing.
func WithCeremonyKey(key []byte) Option {
	return func(o *options) { o.ceremonyKey = key }
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
func NewUserHandler(svc *user.Service, auth authithttp.Authenticator, opts ...Option) http.Handler {
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	h := &UserHandler{svc: svc, auth: auth, ip: o.ip}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", h.register)
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("POST /login/two-factor", h.verifyTwoFactorLogin)
	if svc.SessionMode() == user.SessionModeJWT {
		// Absent rather than answering an error, in opaque session mode.
		// There is no refresh token to present: the session token is the
		// credential and using it is what extends it. A route that exists
		// only to explain that it does nothing is worse than a 404, which
		// says the same thing in the vocabulary a client already has.
		mux.HandleFunc("POST /refresh", h.refresh)
	}
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
	return requireUser(h.auth, next)
}

// requireUser wraps a handler so it only runs for a request carrying a
// valid user-plane bearer token, passing the resolved claims through.
//
// It is shared by every route group that authenticates an ordinary user.
// The superuser group deliberately does NOT use it: those tokens carry a
// different audience, and checking them with a plain user-plane verifier
// would accept a user token on an operator route. See requireSuperuser.
func requireUser(a authithttp.Authenticator, next authedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := a.Authenticate(r.Context(), r)
		if err != nil {
			writeError(w, authithttp.StatusFor(err), "unauthorized", err.Error())
			return
		}
		next(w, r, claims)
	}
}

// UserSessionAuth wires a user.Service in SessionModeOpaque to the route
// groups, translating its refusals into the ones StatusFor understands.
//
// The translation is the whole function, and it is not cosmetic. The user
// package returns user.ErrInvalidToken for a session that is revoked,
// expired or unknown; authithttp.StatusFor knows only its own sentinels and
// answers 500 to anything else. Without this, revoking a session produces a
// 500 on the next request -- an outage-shaped answer to a perfectly ordinary
// "you are signed out", which is precisely the confusion Authenticator's
// error contract exists to prevent.
//
// A store failure keeps its own error and so keeps its 500, which is the
// half of the distinction worth protecting.
func UserSessionAuth(svc *user.Service) authithttp.Authenticator {
	return authithttp.SessionAuth(sessionValidator{svc})
}

type sessionValidator struct{ svc *user.Service }

func (v sessionValidator) ValidateSession(ctx context.Context, token string) (authitjwt.Claims, error) {
	claims, err := v.svc.ValidateSession(ctx, token)
	if err != nil {
		if errors.Is(err, user.ErrInvalidToken) {
			return authitjwt.Claims{}, fmt.Errorf("%w: %w", authithttp.ErrInvalidToken, err)
		}
		return authitjwt.Claims{}, err
	}
	return claims, nil
}
