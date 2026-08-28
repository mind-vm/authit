package authhandlers

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"

	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/device"
	"github.com/mind-vm/authit/pat"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/superuser"
	"github.com/mind-vm/authit/team"
	"github.com/mind-vm/authit/user"
)

// errorBody is the JSON shape of every error response this package writes.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

// serviceErrors maps authit's sentinel errors to the status and stable
// error code this package responds with. Checked in order with errors.Is,
// so more specific sentinels must precede more general ones.
//
// Every plane's sentinels live in one table because several are literally
// the same variable: user.ErrRateLimited, superuser.ErrRateLimited and
// device.ErrRateLimited are all ratelimit.ErrRateLimited, and
// user.ErrWeakPassword is crypto.ErrWeakPassword. Listing them per package
// would be listing them twice.
var serviceErrors = []struct {
	err    error
	status int
	code   string
}{
	// Cross-plane.
	{ratelimit.ErrRateLimited, http.StatusTooManyRequests, "rate_limited"},
	{authitcrypto.ErrWeakPassword, http.StatusUnprocessableEntity, "weak_password"},

	// user
	{user.ErrEmailTaken, http.StatusConflict, "email_taken"},
	{user.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
	{user.ErrEmailNotVerified, http.StatusForbidden, "email_not_verified"},
	{user.ErrAccountLocked, http.StatusLocked, "account_locked"},
	{user.ErrInvalidToken, http.StatusUnauthorized, "invalid_token"},
	{user.ErrInvalidTwoFactor, http.StatusUnauthorized, "invalid_two_factor"},
	{user.ErrTwoFactorEnabled, http.StatusConflict, "two_factor_already_enabled"},
	{user.ErrTwoFactorNotEnabled, http.StatusConflict, "two_factor_not_enabled"},
	{user.ErrSessionNotFound, http.StatusNotFound, "session_not_found"},

	// superuser
	{superuser.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
	{superuser.ErrAccountLocked, http.StatusLocked, "account_locked"},
	{superuser.ErrInactive, http.StatusForbidden, "account_inactive"},
	{superuser.ErrInvalidToken, http.StatusUnauthorized, "invalid_token"},
	{superuser.ErrCannotDeactivateSelf, http.StatusConflict, "cannot_deactivate_self"},
	{superuser.ErrAlreadyBootstrapped, http.StatusConflict, "already_bootstrapped"},

	// team
	{team.ErrInvitationInvalid, http.StatusNotFound, "invitation_invalid"},
	{team.ErrEmailMismatch, http.StatusForbidden, "email_mismatch"},
	{team.ErrLastOwner, http.StatusConflict, "last_owner"},
	{team.ErrNotOwner, http.StatusForbidden, "not_owner"},
	{team.ErrMemberNotFound, http.StatusNotFound, "member_not_found"},
	{team.ErrSlugTaken, http.StatusConflict, "slug_taken"},
	{team.ErrMembershipRejected, http.StatusForbidden, "membership_rejected"},

	// pat
	{pat.ErrInvalidToken, http.StatusUnauthorized, "invalid_token"},
	{pat.ErrExpiryTooFar, http.StatusUnprocessableEntity, "expiry_too_far"},
	{pat.ErrExpiryRequired, http.StatusUnprocessableEntity, "expiry_required"},
	{pat.ErrNotOwner, http.StatusNotFound, "token_not_found"},

	// device
	{device.ErrInvalidUserCode, http.StatusNotFound, "invalid_user_code"},
}

// writeServiceError maps an error returned from any authit service to a
// response. Known sentinels get their mapped status and a message safe to
// expose (authit's own error text, never an internal one); anything else is
// reported as an opaque 500 so a storage or programming error never leaks
// detail to the client.
//
// A rate-limit refusal additionally carries Retry-After when the limiter
// supplied a hint, which is the difference between a client that backs off
// correctly and one that hammers until it is banned.
func writeServiceError(w http.ResponseWriter, err error) {
	for _, m := range serviceErrors {
		if errors.Is(err, m.err) {
			if d, ok := ratelimit.RetryAfter(err); ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
			}
			writeError(w, m.status, m.code, m.err.Error())
			return
		}
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

// decodeJSON decodes r's body as JSON into a T, rejecting unknown fields so
// a client typo fails loudly instead of being silently ignored.
func decodeJSON[T any](r *http.Request) (T, error) {
	var v T
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, err
	}
	return v, nil
}
