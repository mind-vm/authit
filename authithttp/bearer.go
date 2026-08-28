// Package authithttp is the only HTTP wiring authit's core ships:
// RFC-correct bearer-token extraction, token validation, the
// classification of what went wrong, and refresh-token cookies. It imports
// net/http and nothing else beyond authit's own jwt package — no router, no
// http.Handler, no context key, no opinion about what a 401 body looks
// like. Those are the host application's business.
//
// Everything here earns its place the same way: the step is identical in
// every consumer, and quietly security-critical when got slightly wrong.
//
// # Bearer tokens
//
// The obvious hand-rolled version has several quiet failure modes:
//
//   - strings.TrimPrefix(h, "Bearer ") returns the header unchanged when the
//     prefix is absent, so a malformed header silently becomes a token
//     string rather than a rejection.
//   - The auth scheme is case-insensitive per RFC 7235, so a naive prefix
//     check rejects a legitimate "bearer ..." header.
//   - A missing header and an invalid token are both 401, but a signer that
//     can't verify anything at all (a misconfigured key) is a 500 — and
//     collapsing the two hides an outage behind a wall of 401s.
//
// Typical use, inside whatever middleware the host already has:
//
//	claims, err := authithttp.Validate(signer, r)
//	if err != nil {
//		w.WriteHeader(authithttp.StatusFor(err)) // 401 or 500
//		return
//	}
//	// claims.Subject is the user ID; put it wherever your app keeps it.
//
// # Refresh cookies
//
// The access token belongs in an Authorization header, which is what
// BearerToken reads. The refresh token does not: it is long-lived, so
// putting it anywhere JavaScript can reach means any XSS anywhere in the
// application yields a credential that outlives every access token. See
// SetRefreshCookie, ClearRefreshCookie and RefreshCookie, which take the
// decisions that are not really decisions — HttpOnly, Secure, SameSite —
// out of the caller's hands, and refuse to write a cookie the browser will
// silently discard.
package authithttp

import (
	"net/http"
	"strings"
)

// BearerToken extracts the credential from the request's Authorization
// header per RFC 7235: the scheme is matched case-insensitively, and only a
// well-formed "Bearer <token>" yields ok.
//
// It reports ok == false — never a garbage token — for a missing header, a
// different scheme, a scheme with no credential after it, or a credential
// containing whitespace. It also rejects a request carrying more than one
// Authorization header rather than picking one, since which of them the
// caller meant is not knowable here.
//
// The returned token is not validated in any way; it is only syntactically a
// credential. Pass it to a Signer, or use Validate, which does both.
func BearerToken(r *http.Request) (string, bool) {
	if r == nil || r.Header == nil {
		return "", false
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return "", false
	}
	return parseBearer(headers[0])
}

// parseBearer splits one Authorization header value into its credential,
// reporting whether it was a well-formed bearer credential.
func parseBearer(header string) (string, bool) {
	const scheme = "bearer"
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	// The scheme must be followed by whitespace, not by more of a longer
	// word: "BearerToken foo" is not the Bearer scheme.
	rest := header[len(scheme):]
	if rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	// RFC 7235 allows optional whitespace around the credential but the
	// credential itself is a single token, so anything with whitespace
	// still in it after trimming is malformed rather than a token that
	// happens to contain a space.
	token := strings.Trim(rest, " \t")
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
