package authhandlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mind-vm/authit/authithttp"
	"math"
	"net/http"
	"time"

	"github.com/mind-vm/authit/device"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/ratelimit"
)

// DeviceGrantType is the grant_type a device token request must carry
// (RFC 8628 §3.4).
const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceTokenIssuer mints whatever credential the CLI should receive once
// the user has approved, and returns the body to serialise as the token
// response.
//
// authit does not do this itself, and the split is deliberate:
// device.PollDeviceToken answers "who approved this, and for what scope",
// leaving the host to decide what that is worth -- a user session, a
// personal access token, something of its own. That decision cannot be made
// by this package, so the endpoint cannot be complete without you.
//
// The returned value is marshalled as-is, so it must carry at least
// access_token and token_type to satisfy RFC 6749 §5.1. Returning an error
// produces a 500 with error=server_error; return it only for genuine
// failures, since by this point the user has already approved.
type DeviceTokenIssuer func(ctx context.Context, userID, scope string) (any, error)

// DeviceHandler serves the RFC 8628 device authorization grant.
type DeviceHandler struct {
	svc             *device.Service
	auth            authithttp.Authenticator
	issuer          DeviceTokenIssuer
	verificationURI string
}

// NewDeviceHandler builds the device-flow route group.
//
// Protocol routes, form-encoded per RFC 6749/8628 and unauthenticated:
//
//	POST /device/code   the device authorization endpoint (§3.1, §3.2)
//	POST /device/token  the token endpoint (§3.4, §3.5)
//
// Verification routes, JSON and protected by a user bearer token — this is
// the "enter the code you see on your TV" screen, not part of the OAuth
// wire protocol:
//
//	POST /device/approve
//	POST /device/deny
//
// verificationURI is the absolute URL of your own verification page, which
// is returned to the device and read aloud to the user. authit cannot
// derive it: device.Service is explicit that building it belongs to the
// host, which is the only party that knows its own domain and routing.
// issuer and verificationURI are both required; NewDeviceHandler panics
// without them, at startup rather than at first use.
func NewDeviceHandler(svc *device.Service, auth authithttp.Authenticator, issuer DeviceTokenIssuer, verificationURI string) http.Handler {
	if issuer == nil {
		panic("authit/authhandlers: NewDeviceHandler requires a DeviceTokenIssuer; " +
			"authit resolves who approved the request but does not mint the credential")
	}
	if verificationURI == "" {
		panic("authit/authhandlers: NewDeviceHandler requires a verificationURI; " +
			"RFC 8628 §3.2 makes verification_uri a required response field")
	}
	h := &DeviceHandler{svc: svc, auth: auth, issuer: issuer, verificationURI: verificationURI}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /device/code", h.deviceCode)
	mux.HandleFunc("POST /device/token", h.deviceToken)
	mux.HandleFunc("POST /device/approve", requireUser(auth, h.approve))
	mux.HandleFunc("POST /device/deny", requireUser(auth, h.deny))
	return mux
}

// oauthError is RFC 6749 §5.2's error body, which is NOT this package's
// usual {error, message} shape. Device-flow clients parse this one, and
// getting the field name wrong turns "keep polling" into "give up".
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	// Per RFC 6749 §5.1: token endpoint responses must not be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Error: code, ErrorDescription: description})
}

func (h *DeviceHandler) deviceCode(w http.ResponseWriter, r *http.Request) {
	// Form-encoded, per RFC 6749 §3.2 -- not JSON. Real device clients send
	// this, and accepting only JSON would make the endpoint unusable by
	// anything that already speaks the protocol.
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	auth, err := h.svc.StartDeviceAuthorization(r.Context(), clientID, r.PostFormValue("scope"))
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimited) {
			writeOAuthError(w, http.StatusTooManyRequests, "slow_down", err.Error())
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, deviceCodeResponse{
		DeviceCode:      auth.DeviceCode,
		UserCode:        auth.UserCode,
		VerificationURI: h.verificationURI,
		// verification_uri_complete is optional (§3.3.1) and is what makes
		// a QR code possible. The user code is in a query parameter
		// because the page needs to prefill it, and the device code -- the
		// actual secret -- is never in a URL.
		VerificationURIComplete: h.verificationURI + "?user_code=" + auth.UserCode,
		ExpiresIn:               seconds(auth.ExpiresIn),
		Interval:                seconds(auth.Interval),
	})
}

func (h *DeviceHandler) deviceToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if gt := r.PostFormValue("grant_type"); gt != DeviceGrantType {
		// A distinct code from invalid_request, per RFC 6749 §5.2: the
		// request was well formed, the grant was simply not one we serve.
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be "+DeviceGrantType)
		return
	}
	deviceCode := r.PostFormValue("device_code")
	if deviceCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}

	userID, scope, err := h.svc.PollDeviceToken(r.Context(), deviceCode)
	if err != nil {
		status, code := deviceTokenError(err)
		writeOAuthError(w, status, code, err.Error())
		return
	}

	body, err := h.issuer(r.Context(), userID, scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, body)
}

// deviceTokenError maps device's sentinels onto RFC 8628 §3.5's token
// endpoint error codes.
//
// authorization_pending and slow_down are the ordinary path, not failures:
// a polling CLI sees them repeatedly and must keep going. They are 400
// because RFC 6749 §5.2 puts every token-endpoint error there, which reads
// oddly in a log and is nonetheless what clients expect.
func deviceTokenError(err error) (status int, code string) {
	switch {
	case errors.Is(err, device.ErrAuthorizationPending):
		return http.StatusBadRequest, "authorization_pending"
	case errors.Is(err, device.ErrSlowDown):
		return http.StatusBadRequest, "slow_down"
	case errors.Is(err, device.ErrAccessDenied):
		return http.StatusBadRequest, "access_denied"
	case errors.Is(err, device.ErrExpiredToken):
		return http.StatusBadRequest, "expired_token"
	case errors.Is(err, ratelimit.ErrRateLimited):
		return http.StatusTooManyRequests, "slow_down"
	default:
		return http.StatusInternalServerError, "server_error"
	}
}

func (h *DeviceHandler) approve(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[deviceUserCodeRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.ApproveDeviceAuthorization(r.Context(), claims.Subject, req.UserCode); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DeviceHandler) deny(w http.ResponseWriter, r *http.Request, _ authitjwt.Claims) {
	req, err := decodeJSON[deviceUserCodeRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.DenyDeviceAuthorization(r.Context(), req.UserCode); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// seconds converts a duration to the whole seconds the protocol speaks in,
// rounding up and never returning zero.
//
// Truncating instead would be a quiet trap: a sub-second interval becomes
// 0, `omitempty` then drops the field, and RFC 8628 §3.2 says a client that
// sees no interval must assume 5 seconds -- so configuring a fast poll
// would produce a slower one. Rounding up keeps the advertised value a
// value the server will actually honour.
func seconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}

// deviceCodeResponse is RFC 8628 §3.2. Durations are seconds, per the spec.
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	// Always emitted: an absent interval means 5 seconds to a client, so
	// omitting a configured one silently overrides it.
	Interval int `json:"interval"`
}

type deviceUserCodeRequest struct {
	UserCode string `json:"user_code"`
}
