package authithttp

import (
	"context"
	"net/http"

	authitjwt "github.com/mind-vm/authit/jwt"
)

// Authenticator turns a request into a verified principal.
//
// It exists because "is this request authenticated" stopped being a pure
// function. Validate answers it by checking a signature and nothing else,
// which is what makes authit's default session model cheap: no lookup, no
// context, no way for the check to fail because a database is unreachable.
// A session validated by lookup — see user.Config.SessionMode — cannot be
// checked that way, and neither can a credential that lives somewhere authit
// has never heard of.
//
// So this is the seam. Everything that guards a route takes one of these
// rather than a jwt.Verifier, and what is behind it is the host's choice:
//
//   - VerifierAuth(v) is the default and does exactly what it always did.
//   - SessionAuth(svc) looks an opaque session up on every request.
//   - Your own implementation reads a gateway header, an mTLS certificate,
//     or a cookie your own framework issued. authit does not need to know.
//
// # The error contract, which is the part worth getting right
//
// Return ErrNoToken when the request carried no credential and
// ErrInvalidToken when it carried one that did not verify. Both mean 401.
// Anything else means the check could not be performed — the store is down,
// a key could not be fetched — and means 500, because answering 401 to that
// tells a caller their credential is bad when it may be fine, and hides an
// outage behind a wall of plausible auth failures.
//
// StatusFor does that classification. An implementation that collapses its
// own failures into ErrInvalidToken has thrown the distinction away before
// StatusFor can see it.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (authitjwt.Claims, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(ctx context.Context, r *http.Request) (authitjwt.Claims, error)

func (f AuthenticatorFunc) Authenticate(ctx context.Context, r *http.Request) (authitjwt.Claims, error) {
	return f(ctx, r)
}

// VerifierAuth is the default: verify the bearer token's signature, look
// nothing up.
//
// The context is ignored, deliberately and permanently. Nothing here can
// block, so nothing here can be cancelled, and a host that wants revocation
// to take effect before a token expires wants SessionAuth or its own
// implementation instead.
func VerifierAuth(v authitjwt.Verifier) Authenticator {
	return AuthenticatorFunc(func(_ context.Context, r *http.Request) (authitjwt.Claims, error) {
		return Validate(v, r)
	})
}

// SessionValidator resolves an opaque session token to its principal. It is
// what *user.Service satisfies, expressed as an interface so this package
// does not import the service packages it is meant to sit underneath.
//
// Return an error wrapping ErrInvalidToken for a session that is revoked,
// expired or unknown, and the store's own error for a lookup that failed.
type SessionValidator interface {
	ValidateSession(ctx context.Context, token string) (authitjwt.Claims, error)
}

// SessionAuth validates an opaque session token by looking it up, which is
// what buys immediate revocation: a session revoked a moment ago is refused
// by the next request rather than by the one after the access token
// expires.
//
// The cost is a round trip to the session store on every protected request.
// That is the trade, it is not hidden, and it is why this is not the
// default.
func SessionAuth(v SessionValidator) Authenticator {
	return AuthenticatorFunc(func(ctx context.Context, r *http.Request) (authitjwt.Claims, error) {
		token, ok := BearerToken(r)
		if !ok {
			return authitjwt.Claims{}, ErrNoToken
		}
		return v.ValidateSession(ctx, token)
	})
}
