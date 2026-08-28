package authithttp

import (
	"errors"
	"fmt"
	"net/http"

	jwtlib "github.com/golang-jwt/jwt/v5"
	authitjwt "github.com/mind-vm/authit/jwt"
)

var (
	// ErrNoToken means the request carried no usable bearer credential —
	// no Authorization header, a different scheme, or a malformed one.
	// The caller is unauthenticated: 401.
	ErrNoToken = errors.New("authit/http: no bearer token")
	// ErrInvalidToken means a credential was present but did not verify:
	// bad signature, expired, malformed, wrong issuer or audience. Errors
	// returned with this sentinel also wrap the signer's own error, so a
	// caller that wants to distinguish (say) expiry from forgery can still
	// check errors.Is(err, jwt.ErrTokenExpired). The caller is
	// unauthenticated: 401.
	ErrInvalidToken = errors.New("authit/http: invalid bearer token")
)

// Validate extracts the request's bearer token and verifies it with v.
//
// The error it returns is classified, which is the point of the function.
// ErrNoToken and ErrInvalidToken both mean "this request is not
// authenticated" (401). Anything else means the verifier could not do its
// job at all — a key that isn't valid for its algorithm, or, for a Verifier
// that fetches keys, a fetch that failed — which is a server fault (500),
// not the caller's. Pass the error to StatusFor rather than assuming every failure
// here is a 401; collapsing the two hides a misconfigured deployment behind
// a wall of plausible-looking auth failures.
//
// Validate deliberately does not decide anything beyond "is this token
// genuine and unexpired". Two things in particular are left to the caller:
//
//   - Authorization. Claims.Subject is a user ID, not a permission. Whether
//     that user may do this is the host's call, and a host that wants
//     revocation to take effect before the token expires should re-resolve
//     the principal from its own storage rather than trusting claims beyond
//     the subject.
//   - Impersonation. If an operator minted this token by impersonating the
//     subject (see the superuser package), Claims.IsImpersonation reports
//     true and Claims.ActorID names the operator. The token is genuine, so
//     Validate accepts it; a route where acting-as-someone-else should not
//     be allowed must check IsImpersonation itself.
//
// It takes a Verifier rather than a Signer deliberately. Checking a token
// needs no ability to mint one, and with an asymmetric key the verifying
// half is safe to distribute where the signing half is not — see
// jwt.NewVerifier. A Signer satisfies Verifier, so passing one still works.
func Validate(v authitjwt.Verifier, r *http.Request) (authitjwt.Claims, error) {
	if v == nil {
		return authitjwt.Claims{}, errors.New("authit/http: nil verifier")
	}
	token, ok := BearerToken(r)
	if !ok {
		return authitjwt.Claims{}, ErrNoToken
	}
	claims, err := v.Validate(token)
	if err != nil {
		if isTokenFault(err) {
			return authitjwt.Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
		return authitjwt.Claims{}, fmt.Errorf("authit/http: validating bearer token: %w", err)
	}
	return claims, nil
}

// StatusFor maps an error from Validate to the status a bearer-authenticated
// endpoint should return: 401 when the request failed to authenticate itself,
// 500 when this server could not perform the check. It says nothing about the
// response body, and returns 200 for a nil error so it can be used
// unconditionally.
func StatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrNoToken), errors.Is(err, ErrInvalidToken):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// tokenFaults are the golang-jwt sentinels that mean the *token* was at
// fault. Everything else it can return (ErrInvalidKey, ErrInvalidKeyType,
// ErrHashUnavailable) means the verifying side was, as does any error from a
// custom Verifier that isn't one of these at all.
var tokenFaults = []error{
	jwtlib.ErrTokenMalformed,
	jwtlib.ErrTokenUnverifiable,
	jwtlib.ErrTokenSignatureInvalid,
	jwtlib.ErrTokenRequiredClaimMissing,
	jwtlib.ErrTokenInvalidAudience,
	jwtlib.ErrTokenExpired,
	jwtlib.ErrTokenUsedBeforeIssued,
	jwtlib.ErrTokenInvalidIssuer,
	jwtlib.ErrTokenInvalidSubject,
	jwtlib.ErrTokenNotValidYet,
	jwtlib.ErrTokenInvalidId,
	jwtlib.ErrTokenInvalidClaims,
	jwtlib.ErrInvalidType,
}

// isTokenFault reports whether err blames the presented token rather than
// the verifying side.
//
// ErrTokenUnverifiable is the one ambiguous member: golang-jwt returns it
// both when a key function rejects a token (HMACSigner refuses a token whose
// alg isn't HMAC that way, which is an attack, not an outage) and when a key
// function fails for its own reasons. It is counted as the token's fault, so
// an alg-confusion attempt gets a 401 rather than a 500 and a page. A Signer
// that fetches keys over the network should therefore surface a transient
// failure as its own error type and have the host check for it before
// reaching for StatusFor — the error from Validate wraps the signer's,
// so errors.Is still finds it.
func isTokenFault(err error) bool {
	for _, fault := range tokenFaults {
		if errors.Is(err, fault) {
			return true
		}
	}
	return false
}
