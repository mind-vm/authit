package authhandlers

import (
	"net/http"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/pat"
	"github.com/mind-vm/authit/store"
)

// PATHandler serves personal-access-token management for the authenticated
// caller.
type PATHandler struct {
	svc      *pat.Service
	verifier authitjwt.Verifier
}

// NewPATHandler builds the personal-access-token route group. Every route
// is protected and acts on the caller's own tokens, resolved from the
// bearer token's subject — there is no route that names another user, by
// design.
//
//	POST   /me/tokens
//	GET    /me/tokens
//	DELETE /me/tokens/{id}
//
// pat.Service.Resolve is deliberately not a route. It is what a host calls
// on an incoming request to identify the caller, not something a client
// submits a token to; exposing it would be an oracle for testing whether a
// guessed token is live.
func NewPATHandler(svc *pat.Service, verifier authitjwt.Verifier) http.Handler {
	h := &PATHandler{svc: svc, verifier: verifier}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /me/tokens", h.withAuth(h.createToken))
	mux.HandleFunc("GET /me/tokens", h.withAuth(h.listTokens))
	mux.HandleFunc("DELETE /me/tokens/{id}", h.withAuth(h.revokeToken))
	return mux
}

func (h *PATHandler) withAuth(next authedHandlerFunc) http.HandlerFunc {
	return requireUser(h.verifier, next)
}

func (h *PATHandler) createToken(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[createTokenRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt
	}
	raw, token, err := h.svc.CreateToken(r.Context(), claims.Subject, req.Name, req.Scopes, expiresAt)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// The raw token appears in this response and nowhere else, ever --
	// only its hash is stored. Say so in the payload, because a client that
	// does not persist it here cannot recover it.
	writeJSON(w, http.StatusCreated, createTokenResponse{
		Token:               raw,
		PersonalAccessToken: newPATResponse(token),
	})
}

func (h *PATHandler) listTokens(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	tokens, err := h.svc.ListTokens(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]patResponse, len(tokens))
	for i, t := range tokens {
		out[i] = newPATResponse(t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *PATHandler) revokeToken(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	// pat.RevokeToken checks ownership itself and returns ErrNotOwner,
	// which this package maps to 404 rather than 403 -- "exists but is not
	// yours" is an existence oracle over guessable ids.
	if err := h.svc.RevokeToken(r.Context(), claims.Subject, r.PathValue("id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// patResponse never exposes store.PersonalAccessToken.TokenHash.
type patResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func newPATResponse(t store.PersonalAccessToken) patResponse {
	return patResponse{
		ID:         t.ID,
		Name:       t.Name,
		Scopes:     t.Scopes,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
		CreatedAt:  t.CreatedAt,
	}
}

type createTokenRequest struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type createTokenResponse struct {
	// Token is the raw credential, returned exactly once.
	Token               string      `json:"token"`
	PersonalAccessToken patResponse `json:"personal_access_token"`
}
