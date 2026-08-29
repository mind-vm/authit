package authhandlers

import (
	"github.com/mind-vm/authit/authithttp"
	"net/http"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/passkey"
	"github.com/mind-vm/authit/store"
)

// Cookies holding an in-flight WebAuthn ceremony. Registration and login
// are separate names so a half-finished registration cannot be presented
// to the login endpoint.
const (
	passkeyRegisterCookie = "authit_passkey_register"
	passkeyLoginCookie    = "authit_passkey_login"
)

// PasskeyHandler serves WebAuthn registration, login and management.
type PasskeyHandler struct {
	ceremonyBase
	svc  *passkey.Service
	auth authithttp.Authenticator
}

// NewPasskeyHandler builds the passkey route group.
//
// Public:
//
//	POST /passkeys/login/begin     starts a usernameless sign-in
//	POST /passkeys/login/finish    completes it
//
// Protected (Authorization: Bearer <access token>):
//
//	POST   /me/passkeys/register/begin
//	POST   /me/passkeys/register/finish   {"name": "..."}
//	GET    /me/passkeys
//	PATCH  /me/passkeys/{id}              {"name": "..."}
//	DELETE /me/passkeys/{id}
//
// issuer is required; see SessionIssuer.
//
// # Only the usernameless login is here
//
// The public login route runs the discoverable ceremony: the browser offers
// whatever passkeys it holds, and the assertion says which account. It
// names no user, so it also cannot be used to ask whether an account
// exists.
//
// A known-user ceremony — a passkey as the *second* factor, after a
// password — is deliberately absent. It has to run against a caller who has
// passed the first factor and is not yet authenticated, which is exactly
// the half-authenticated state user.Authenticate hands back as a pending
// two-factor token. Only the host holds that, so only the host can wire it;
// passkey.Service.BeginLogin and FinishLogin are what it calls.
//
// # Registration must be authenticated
//
// The protected routes are protected for a reason worth stating: the
// registration ceremony proves possession of an authenticator and nothing
// about whose account it belongs on. Exposed unauthenticated, it lets
// anybody add their own passkey to somebody else's account.
func NewPasskeyHandler(svc *passkey.Service, auth authithttp.Authenticator, issuer SessionIssuer, opts ...Option) http.Handler {
	if issuer == nil {
		panic("authit/authhandlers: NewPasskeyHandler requires a SessionIssuer")
	}
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	if len(o.ceremonyKey) == 0 {
		panic("authit/authhandlers: NewPasskeyHandler requires WithCeremonyKey; " +
			"the ceremony cookie carries the challenge the assertion is verified against")
	}
	h := &PasskeyHandler{
		// Scoped to "/" because registration lives under /me and login
		// does not; a narrower path would not cover both.
		ceremonyBase: ceremonyBase{issuer: issuer, cookiePath: "/", insecure: o.insecure, key: o.ceremonyKey},
		svc:          svc, auth: auth,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /passkeys/login/begin", h.beginLogin)
	mux.HandleFunc("POST /passkeys/login/finish", h.finishLogin)
	mux.HandleFunc("POST /me/passkeys/register/begin", requireUser(auth, h.beginRegistration))
	mux.HandleFunc("POST /me/passkeys/register/finish", requireUser(auth, h.finishRegistration))
	mux.HandleFunc("GET /me/passkeys", requireUser(auth, h.list))
	mux.HandleFunc("PATCH /me/passkeys/{id}", requireUser(auth, h.rename))
	mux.HandleFunc("DELETE /me/passkeys/{id}", requireUser(auth, h.remove))
	return mux
}

// writeCeremony sends the options to the browser and stashes the session.
//
// SameSite=Strict here, unlike the OAuth cookie: a WebAuthn ceremony is
// driven by XHR from your own page, never by a navigation from someone
// else's, so nothing is lost by refusing to send it cross-site.
func (h *PasskeyHandler) writeCeremony(w http.ResponseWriter, cookie string, opts passkey.Options, sess passkey.Session) {
	h.setCeremonyCookie(w, cookie, sess, http.SameSiteStrictMode)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(opts)
}

func (h *PasskeyHandler) beginRegistration(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	opts, sess, err := h.svc.BeginRegistration(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.writeCeremony(w, passkeyRegisterCookie, opts, sess)
}

func (h *PasskeyHandler) finishRegistration(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	defer h.clearCeremonyCookie(w, passkeyRegisterCookie, http.SameSiteStrictMode)
	sess, ok := h.readCeremonyCookie(r, passkeyRegisterCookie)
	if !ok {
		writeError(w, http.StatusBadRequest, "ceremony_missing", passkey.ErrSession.Error())
		return
	}
	// The credential name is a query parameter because the body is the
	// browser's attestation response verbatim, which this handler must not
	// reshape -- the signature is over exactly those bytes.
	name := r.URL.Query().Get("name")
	cred, err := h.svc.FinishRegistration(r.Context(), claims.Subject, name, sess, r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newPasskeyResponse(cred))
}

func (h *PasskeyHandler) beginLogin(w http.ResponseWriter, r *http.Request) {
	opts, sess, err := h.svc.BeginDiscoverableLogin(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.writeCeremony(w, passkeyLoginCookie, opts, sess)
}

func (h *PasskeyHandler) finishLogin(w http.ResponseWriter, r *http.Request) {
	defer h.clearCeremonyCookie(w, passkeyLoginCookie, http.SameSiteStrictMode)
	sess, ok := h.readCeremonyCookie(r, passkeyLoginCookie)
	if !ok {
		writeError(w, http.StatusBadRequest, "ceremony_missing", passkey.ErrSession.Error())
		return
	}
	res, err := h.svc.FinishDiscoverableLogin(r.Context(), sess, r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.issue(w, r, res.User, false)
}

func (h *PasskeyHandler) list(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	creds, err := h.svc.List(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]passkeyResponse, len(creds))
	for i, c := range creds {
		out[i] = newPasskeyResponse(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *PasskeyHandler) rename(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[renamePasskeyRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.Rename(r.Context(), claims.Subject, r.PathValue("id"), req.Name); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PasskeyHandler) remove(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	if err := h.svc.Remove(r.Context(), claims.Subject, r.PathValue("id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// passkeyResponse never exposes the credential blob or the raw credential
// id. Neither is secret, and neither is any use to a settings page.
type passkeyResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Transports     []string `json:"transports,omitempty"`
	BackupEligible bool     `json:"backup_eligible"`
	BackupState    bool     `json:"backup_state"`
	// CloneWarning is surfaced so a settings page can tell somebody this
	// credential is compromised, which is the only way they will know.
	CloneWarning bool   `json:"clone_warning"`
	LastUsedAt   string `json:"last_used_at,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func newPasskeyResponse(c store.WebAuthnCredential) passkeyResponse {
	out := passkeyResponse{
		ID: c.ID, Name: c.Name, Transports: c.Transports,
		BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		CloneWarning: c.CloneWarning, CreatedAt: c.CreatedAt.Format(timeFormat),
	}
	if c.LastUsedAt != nil {
		out.LastUsedAt = c.LastUsedAt.Format(timeFormat)
	}
	return out
}

type renamePasskeyRequest struct {
	Name string `json:"name"`
}
