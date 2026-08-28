package authhandlers

import (
	"errors"
	"net/http"

	"github.com/mind-vm/authit/emaillogin"
)

// EmailLoginHandler serves passwordless sign-in by magic link or code.
type EmailLoginHandler struct {
	ceremonyBase
	svc *emaillogin.Service
}

// NewEmailLoginHandler builds the passwordless email route group.
//
// Every route is public — that is the point of the flow — and every one of
// them is a place an unauthenticated caller can name any address they like,
// so read what each returns before wiring a UI to it.
//
//	POST /email/link/request   {"email": "..."}
//	POST /email/link/redeem    {"token": "..."}
//	POST /email/code/request   {"email": "..."}
//	POST /email/code/redeem    {"email": "...", "code": "..."}
//
// issuer is required; see SessionIssuer.
//
// # The request routes always return 204
//
// Whether or not the address is registered. A response that differed would
// turn this into a membership oracle for the whole user table, which is a
// bad trade for a form anybody can type into. Reflect that in your UI: say
// "if that address has an account, we have sent a link", not "sent" or "no
// such user".
//
// Rate limiting on these routes matters more than on most. They cause mail
// to be sent to an address the caller chose. Configure
// emaillogin.Config.RateLimiter, and put per-IP limiting in your middleware
// as well — the service can only key on the address, which is the thing an
// attacker varies.
func NewEmailLoginHandler(svc *emaillogin.Service, issuer SessionIssuer, opts ...Option) http.Handler {
	if issuer == nil {
		panic("authit/authhandlers: NewEmailLoginHandler requires a SessionIssuer; " +
			"authit resolves the user but does not mint a session")
	}
	o := options{ip: defaultIPExtractor}
	for _, opt := range opts {
		opt(&o)
	}
	h := &EmailLoginHandler{ceremonyBase: ceremonyBase{issuer: issuer, insecure: o.insecure}, svc: svc}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /email/link/request", h.requestLink)
	mux.HandleFunc("POST /email/link/redeem", h.redeemLink)
	mux.HandleFunc("POST /email/code/request", h.requestCode)
	mux.HandleFunc("POST /email/code/redeem", h.redeemCode)
	return mux
}

func (h *EmailLoginHandler) requestLink(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[emailOnlyRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.RequestMagicLink(r.Context(), req.Email); err != nil {
		writeEmailLoginError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *EmailLoginHandler) requestCode(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[emailOnlyRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.RequestSignInCode(r.Context(), req.Email); err != nil {
		writeEmailLoginError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *EmailLoginHandler) redeemLink(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[magicLinkRedeemRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.svc.RedeemMagicLink(r.Context(), req.Token)
	if err != nil {
		writeEmailLoginError(w, err)
		return
	}
	h.issue(w, r, res.User, res.CreatedUser)
}

func (h *EmailLoginHandler) redeemCode(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[codeRedeemRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.svc.RedeemSignInCode(r.Context(), req.Email, req.Code)
	if err != nil {
		writeEmailLoginError(w, err)
		return
	}
	h.issue(w, r, res.User, res.CreatedUser)
}

// writeEmailLoginError maps this plane's sentinels.
//
// Note that ErrInvalidToken is 401 with one code covering wrong, expired,
// used and exhausted. The service deliberately does not distinguish them,
// and re-introducing the distinction here would undo that: an attacker who
// can tell "expired" from "wrong" learns whether the code they guessed was
// ever real.
func writeEmailLoginError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, emaillogin.ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, "invalid_token", emaillogin.ErrInvalidToken.Error())
	case errors.Is(err, emaillogin.ErrSignUpDisabled):
		writeError(w, http.StatusForbidden, "signup_disabled", emaillogin.ErrSignUpDisabled.Error())
	default:
		writeServiceError(w, err)
	}
}

type emailOnlyRequest struct {
	Email string `json:"email"`
}

type magicLinkRedeemRequest struct {
	Token string `json:"token"`
}

type codeRedeemRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
