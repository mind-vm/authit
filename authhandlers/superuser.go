package authhandlers

import (
	"net/http"
	"time"

	"github.com/mind-vm/authit/authithttp"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/superuser"
)

// SuperuserHandler serves authit's operator plane.
type SuperuserHandler struct {
	svc *superuser.Service
	ip  func(*http.Request) string
}

// NewSuperuserHandler builds the operator-plane route group.
//
// Public routes:
//
//	POST /login
//	POST /refresh
//	POST /logout
//
// Protected routes (Authorization: Bearer <operator access token>):
//
//	GET  /superusers
//	POST /superusers
//	POST /superusers/{id}/deactivate
//	POST /impersonate
//
// # Mount this somewhere else
//
// Everything here is an operator surface. It should not sit under the same
// public prefix as the user routes, and most deployments should not expose
// it on the public internet at all — put it behind whatever network or VPN
// boundary your admin tooling already uses. authit keeps operators in their
// own table with their own tokens precisely so that boundary is possible;
// mounting this at /auth/admin on the same origin gives that away.
//
// Note that Bootstrap is deliberately absent. Creating the first operator
// from an unauthenticated HTTP request would be a race worth losing — it is
// a deployment step, not an endpoint.
func NewSuperuserHandler(svc *superuser.Service, opts ...Option) http.Handler {
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	h := &SuperuserHandler{svc: svc, ip: o.ip}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("POST /refresh", h.refresh)
	mux.HandleFunc("POST /logout", h.logout)

	mux.HandleFunc("GET /superusers", h.withAuth(h.listSuperusers))
	mux.HandleFunc("POST /superusers", h.withAuth(h.createSuperuser))
	mux.HandleFunc("POST /superusers/{id}/deactivate", h.withAuth(h.deactivate))
	mux.HandleFunc("POST /impersonate", h.withAuth(h.impersonate))
	return mux
}

// superuserHandlerFunc receives the caller's operator claims.
type superuserHandlerFunc func(w http.ResponseWriter, r *http.Request, claims superuser.Claims)

// withAuth authenticates an operator.
//
// It routes through superuser.Service.Verify rather than
// authithttp.Validate, and that difference is the security boundary of this
// whole plane: Verify checks the token's audience, so an ordinary user's
// access token — which is signed by the same key — is rejected here. A
// plain signature check would accept it and hand a user every operator
// route, including Impersonate.
func (h *SuperuserHandler) withAuth(next superuserHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := authithttp.BearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", authithttp.ErrNoToken.Error())
			return
		}
		claims, err := h.svc.Verify(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", superuser.ErrInvalidToken.Error())
			return
		}
		next(w, r, claims)
	}
}

func (h *SuperuserHandler) login(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[loginRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tokens, err := h.svc.Authenticate(r.Context(), req.Email, req.Password, r.UserAgent(), h.ip(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newSuperuserTokenResponse(tokens))
}

func (h *SuperuserHandler) refresh(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[refreshRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tokens, err := h.svc.Refresh(r.Context(), req.RefreshToken, r.UserAgent(), h.ip(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newSuperuserTokenResponse(tokens))
}

func (h *SuperuserHandler) logout(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[logoutRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SuperuserHandler) listSuperusers(w http.ResponseWriter, r *http.Request, _ superuser.Claims) {
	list, err := h.svc.ListSuperusers(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]superuserResponse, len(list))
	for i, su := range list {
		out[i] = newSuperuserResponse(su)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *SuperuserHandler) createSuperuser(w http.ResponseWriter, r *http.Request, claims superuser.Claims) {
	req, err := decodeJSON[createSuperuserRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	su, err := h.svc.CreateSuperuser(r.Context(), req.Email, req.Password, req.DisplayName, claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newSuperuserResponse(su))
}

func (h *SuperuserHandler) deactivate(w http.ResponseWriter, r *http.Request, claims superuser.Claims) {
	if err := h.svc.Deactivate(r.Context(), claims.Subject, r.PathValue("id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SuperuserHandler) impersonate(w http.ResponseWriter, r *http.Request, claims superuser.Claims) {
	req, err := decodeJSON[impersonateRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	token, err := h.svc.Impersonate(r.Context(), claims.Subject, req.UserID, req.UserEmail)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// A user-plane access token, carrying ActorID so downstream audit code
	// can record who was really acting. There is no refresh token: an
	// impersonation session is meant to expire, not to be renewed.
	writeJSON(w, http.StatusOK, impersonateResponse{AccessToken: token})
}

// superuserResponse never exposes store.Superuser.PasswordHash.
type superuserResponse struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	IsActive    bool       `json:"is_active"`
	CreatedBy   *string    `json:"created_by,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func newSuperuserResponse(su store.Superuser) superuserResponse {
	return superuserResponse{
		ID:          su.ID,
		Email:       su.Email,
		DisplayName: su.DisplayName,
		IsActive:    su.IsActive,
		CreatedBy:   su.CreatedBy,
		LastLoginAt: su.LastLoginAt,
		CreatedAt:   su.CreatedAt,
	}
}

func newSuperuserTokenResponse(t superuser.TokenPair) tokenResponse {
	return tokenResponse{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, ExpiresAt: t.ExpiresAt}
}

type createSuperuserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type impersonateRequest struct {
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
}

type impersonateResponse struct {
	AccessToken string `json:"access_token"`
}
