package authhandlers

import (
	"github.com/mind-vm/authit/authithttp"
	"net/http"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/oidc"
)

// oidcStateCookie holds the OAuth state and PKCE verifier between the
// redirect out and the callback back.
const oidcStateCookie = "authit_oidc"

// OIDCHandler serves sign-in with an external identity provider.
type OIDCHandler struct {
	ceremonyBase
	svc         *oidc.Service
	auth        authithttp.Authenticator
	redirectURI func(r *http.Request, provider string) string
}

// NewOIDCHandler builds the external-identity route group.
//
//	GET    /oidc/{provider}/start      redirects to the provider
//	GET    /oidc/{provider}/callback   completes the sign-in
//	GET    /me/accounts                lists linked providers   (protected)
//	DELETE /me/accounts/{provider}     unlinks one              (protected)
//
// redirectURI must return the exact callback URL registered with the
// provider, for a given request and provider id. It is a function because
// only the host knows its own scheme, host and mount path, and the value
// must match what the provider has on file byte for byte.
//
// issuer and redirectURI are both required; the constructor panics without
// them.
//
// # Linking is not a route here
//
// oidc.Service.Link attaches a provider to an *already authenticated* user,
// and doing it over HTTP means running the same start/callback pair while
// carrying the caller's identity through it. That is a second, differently
// shaped ceremony, and getting it wrong — completing a link against
// whoever the callback happens to arrive as — is an account takeover. It is
// left to the host deliberately rather than approximated here.
//
// The callback returns 409 `account_not_linked` when a social sign-in
// matches an existing account that it may not join; see oidc.LinkingPolicy.
// That is the safe outcome, not an error: send the user to sign in by the
// means they already have.
func NewOIDCHandler(svc *oidc.Service, auth authithttp.Authenticator, issuer SessionIssuer, redirectURI func(r *http.Request, provider string) string, opts ...Option) http.Handler {
	if issuer == nil {
		panic("authit/authhandlers: NewOIDCHandler requires a SessionIssuer")
	}
	if redirectURI == nil {
		panic("authit/authhandlers: NewOIDCHandler requires a redirectURI function; " +
			"only the host knows the callback URL registered with the provider")
	}
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	if len(o.ceremonyKey) == 0 {
		panic("authit/authhandlers: NewOIDCHandler requires WithCeremonyKey; " +
			"the ceremony cookie carries the state and PKCE verifier the callback is checked against")
	}
	h := &OIDCHandler{
		ceremonyBase: ceremonyBase{issuer: issuer, cookiePath: "/", insecure: o.insecure, key: o.ceremonyKey},
		svc:          svc, auth: auth, redirectURI: redirectURI,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/{provider}/start", h.start)
	mux.HandleFunc("GET /oidc/{provider}/callback", h.callback)
	mux.HandleFunc("GET /me/accounts", requireUser(auth, h.listAccounts))
	mux.HandleFunc("DELETE /me/accounts/{provider}", requireUser(auth, h.unlink))
	return mux
}

func (h *OIDCHandler) start(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	auth, err := h.svc.Begin(r.Context(), provider, h.redirectURI(r, provider))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// SameSite=Lax, not Strict. The callback is a top-level navigation
	// from the provider's origin, so a Strict cookie would not be sent
	// with it and the callback could not find the state it must check.
	h.setCeremonyCookie(w, oidcStateCookie,
		encodeState(ceremonyState{State: auth.State, Verifier: auth.CodeVerifier}), http.SameSiteLaxMode)
	http.Redirect(w, r, auth.URL, http.StatusFound)
}

func (h *OIDCHandler) callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	// Cleared first and unconditionally: whatever happens next, this
	// ceremony is over, and a state left in the browser is one that can be
	// replayed against a second callback.
	defer h.clearCeremonyCookie(w, oidcStateCookie, http.SameSiteLaxMode)

	raw, ok := h.readCeremonyCookie(r, oidcStateCookie)
	if !ok {
		writeError(w, http.StatusBadRequest, "state_missing",
			"no in-flight sign-in for this browser")
		return
	}
	saved, ok := decodeState(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, "state_missing", "sign-in state is unreadable")
		return
	}

	// The provider reports its own failures in the query rather than by
	// status code -- a user who pressed "cancel" arrives here.
	if e := r.URL.Query().Get("error"); e != "" {
		writeError(w, http.StatusBadRequest, "provider_error", e)
		return
	}

	res, err := h.svc.Complete(r.Context(), provider, h.redirectURI(r, provider), oidc.Callback{
		Code:          r.URL.Query().Get("code"),
		State:         r.URL.Query().Get("state"),
		ExpectedState: saved.State,
		CodeVerifier:  saved.Verifier,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.issue(w, r, res.User, res.CreatedUser)
}

func (h *OIDCHandler) listAccounts(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	accounts, err := h.svc.ListAccounts(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]linkedAccountResponse, len(accounts))
	for i, a := range accounts {
		out[i] = linkedAccountResponse{
			Provider: a.Provider, Email: a.Email,
			EmailVerified: a.EmailVerified, LinkedAt: a.CreatedAt.Format(timeFormat),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *OIDCHandler) unlink(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	if err := h.svc.Unlink(r.Context(), claims.Subject, r.PathValue("provider")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const timeFormat = "2006-01-02T15:04:05Z07:00"

type linkedAccountResponse struct {
	Provider      string `json:"provider"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	LinkedAt      string `json:"linked_at"`
}
