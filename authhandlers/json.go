package authhandlers

import (
	"encoding/json"
	"errors"
	"net/http"

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

// userErrors maps user package sentinel errors to the status and stable
// error code this package responds with. Checked in order with errors.Is,
// so more specific sentinels should precede more general ones — none
// currently wrap another, but this keeps the mapping robust if that
// changes.
var userErrors = []struct {
	err    error
	status int
	code   string
}{
	{user.ErrEmailTaken, http.StatusConflict, "email_taken"},
	{user.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
	{user.ErrEmailNotVerified, http.StatusForbidden, "email_not_verified"},
	{user.ErrAccountLocked, http.StatusLocked, "account_locked"},
	{user.ErrInvalidToken, http.StatusUnauthorized, "invalid_token"},
	{user.ErrInvalidTwoFactor, http.StatusUnauthorized, "invalid_two_factor"},
	{user.ErrTwoFactorEnabled, http.StatusConflict, "two_factor_already_enabled"},
	{user.ErrTwoFactorNotEnabled, http.StatusConflict, "two_factor_not_enabled"},
	{user.ErrSessionNotFound, http.StatusNotFound, "session_not_found"},
}

// writeServiceError maps an error returned from user.Service to a response.
// Known sentinels get their mapped status and a message safe to expose
// (authit's own error text, never an internal one); anything else is
// reported as an opaque 500 so a storage or programming error never leaks
// detail to the client.
func writeServiceError(w http.ResponseWriter, err error) {
	for _, m := range userErrors {
		if errors.Is(err, m.err) {
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
