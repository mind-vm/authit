package authhandlers

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"

	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/device"
	"github.com/mind-vm/authit/emaillogin"
	"github.com/mind-vm/authit/oidc"
	"github.com/mind-vm/authit/passkey"
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
//
// The feature planes are here too, for the weaker reason: one way of
// mapping an error, not two. They used to have a switch each, which is the
// same table written three more times and a place for a plane to drift into
// answering differently for no reason anybody decided.
//
// message overrides the response text, which is otherwise err.Error(). It
// exists for one case -- see oidc.ErrIdentity -- and should stay rare: a
// message that is not the sentinel's own text is one more thing to keep
// true.
var serviceErrors = []struct {
	err     error
	status  int
	code    string
	message string
}{
	// Cross-plane.
	{err: ratelimit.ErrRateLimited, status: http.StatusTooManyRequests, code: "rate_limited"},
	{err: authitcrypto.ErrWeakPassword, status: http.StatusUnprocessableEntity, code: "weak_password"},

	// user
	{err: user.ErrEmailTaken, status: http.StatusConflict, code: "email_taken"},
	{err: user.ErrInvalidCredentials, status: http.StatusUnauthorized, code: "invalid_credentials"},
	{err: user.ErrEmailNotVerified, status: http.StatusForbidden, code: "email_not_verified"},
	{err: user.ErrAccountLocked, status: http.StatusLocked, code: "account_locked"},
	{err: user.ErrInvalidToken, status: http.StatusUnauthorized, code: "invalid_token"},
	{err: user.ErrInvalidTwoFactor, status: http.StatusUnauthorized, code: "invalid_two_factor"},
	{err: user.ErrTwoFactorEnabled, status: http.StatusConflict, code: "two_factor_already_enabled"},
	{err: user.ErrTwoFactorNotEnabled, status: http.StatusConflict, code: "two_factor_not_enabled"},
	{err: user.ErrSessionNotFound, status: http.StatusNotFound, code: "session_not_found"},
	// Both are the caller getting the shape of the request wrong, not this
	// server failing. Without an entry they fall to the default and answer
	// 500, which reports a misuse as an outage.
	{err: user.ErrCurrentSessionRequired, status: http.StatusBadRequest, code: "current_session_required"},
	{err: user.ErrWrongSessionMode, status: http.StatusBadRequest, code: "wrong_session_mode"},

	// superuser
	{err: superuser.ErrInvalidCredentials, status: http.StatusUnauthorized, code: "invalid_credentials"},
	{err: superuser.ErrAccountLocked, status: http.StatusLocked, code: "account_locked"},
	{err: superuser.ErrInactive, status: http.StatusForbidden, code: "account_inactive"},
	{err: superuser.ErrInvalidToken, status: http.StatusUnauthorized, code: "invalid_token"},
	{err: superuser.ErrCannotDeactivateSelf, status: http.StatusConflict, code: "cannot_deactivate_self"},
	{err: superuser.ErrAlreadyBootstrapped, status: http.StatusConflict, code: "already_bootstrapped"},

	// team
	{err: team.ErrInvitationInvalid, status: http.StatusNotFound, code: "invitation_invalid"},
	{err: team.ErrEmailMismatch, status: http.StatusForbidden, code: "email_mismatch"},
	{err: team.ErrLastOwner, status: http.StatusConflict, code: "last_owner"},
	{err: team.ErrNotOwner, status: http.StatusForbidden, code: "not_owner"},
	{err: team.ErrMemberNotFound, status: http.StatusNotFound, code: "member_not_found"},
	{err: team.ErrSlugTaken, status: http.StatusConflict, code: "slug_taken"},
	{err: team.ErrMembershipRejected, status: http.StatusForbidden, code: "membership_rejected"},

	// pat
	{err: pat.ErrInvalidToken, status: http.StatusUnauthorized, code: "invalid_token"},
	{err: pat.ErrExpiryTooFar, status: http.StatusUnprocessableEntity, code: "expiry_too_far"},
	{err: pat.ErrExpiryRequired, status: http.StatusUnprocessableEntity, code: "expiry_required"},
	{err: pat.ErrNotOwner, status: http.StatusNotFound, code: "token_not_found"},

	// device
	{err: device.ErrInvalidUserCode, status: http.StatusNotFound, code: "invalid_user_code"},

	// oidc
	{err: oidc.ErrUnknownProvider, status: http.StatusNotFound, code: "unknown_provider"},
	// 400, not 401: nothing failed to authenticate. The callback is not the
	// continuation of a flow this server started -- forged, or badly resumed.
	{err: oidc.ErrStateMismatch, status: http.StatusBadRequest, code: "state_mismatch"},
	// Not a failure. The host's move is to tell the user this address
	// already has an account and have them sign in and link it.
	{err: oidc.ErrAccountNotLinked, status: http.StatusConflict, code: "account_not_linked"},
	{err: oidc.ErrProviderEmailUnverified, status: http.StatusConflict, code: "provider_email_unverified"},
	{err: oidc.ErrSignUpDisabled, status: http.StatusForbidden, code: "signup_disabled"},
	{err: oidc.ErrAlreadyLinked, status: http.StatusConflict, code: "already_linked"},
	{err: oidc.ErrLastCredential, status: http.StatusConflict, code: "last_credential"},
	{err: oidc.ErrNoEmail, status: http.StatusBadRequest, code: "no_email"},
	// The provider's fault or the network's, not the caller's.
	{err: oidc.ErrProviderUnreachable, status: http.StatusBadGateway, code: "provider_unreachable"},
	{err: oidc.ErrExchange, status: http.StatusBadRequest, code: "exchange_failed"},
	// Deliberately answers as ErrExchange does, code and text alike. Which
	// of the two provider-side steps failed is useful in a log and is not
	// the caller's business.
	{err: oidc.ErrIdentity, status: http.StatusBadRequest, code: "exchange_failed",
		message: oidc.ErrExchange.Error()},

	// passkey
	// One code for every verification failure -- bad signature, wrong
	// origin, stale challenge. Which check failed belongs in a log, not in
	// a response body.
	{err: passkey.ErrCeremony, status: http.StatusUnauthorized, code: "ceremony_failed"},
	{err: passkey.ErrSession, status: http.StatusBadRequest, code: "ceremony_missing"},
	// 409, not 401. The assertion verified; the authenticator is the
	// problem, and the user needs to be told something specific -- that
	// this credential is compromised and must be replaced.
	{err: passkey.ErrCloneWarning, status: http.StatusConflict, code: "clone_warning"},
	{err: passkey.ErrUserVerificationRequired, status: http.StatusUnauthorized, code: "user_verification_required"},
	{err: passkey.ErrAlreadyRegistered, status: http.StatusConflict, code: "already_registered"},
	{err: passkey.ErrCredentialNotFound, status: http.StatusNotFound, code: "credential_not_found"},
	{err: passkey.ErrNoCredentials, status: http.StatusConflict, code: "no_credentials"},
	{err: passkey.ErrLastCredential, status: http.StatusConflict, code: "last_credential"},

	// emaillogin
	// Wrong, expired, already used and exhausted are one answer. The
	// service refuses to distinguish them and re-introducing the
	// distinction here would undo that: an attacker who can tell "expired"
	// from "wrong" learns whether the code they guessed was ever real.
	{err: emaillogin.ErrInvalidToken, status: http.StatusUnauthorized, code: "invalid_token"},
	{err: emaillogin.ErrSignUpDisabled, status: http.StatusForbidden, code: "signup_disabled"},
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
			message := m.message
			if message == "" {
				message = m.err.Error()
			}
			writeError(w, m.status, m.code, message)
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
