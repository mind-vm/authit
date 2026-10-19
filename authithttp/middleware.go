package authithttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
)

type claimsKey struct{}

// ContextWithClaims returns a copy of ctx carrying claims, as
// SessionMiddleware stores them. It is exported for a host's own tests, and
// for a host that authenticates some other way and wants ClaimsFrom to keep
// working downstream.
func ContextWithClaims(ctx context.Context, claims authitjwt.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFrom returns the claims SessionMiddleware put in the request's
// context. ok is false when there are none: the request did not pass
// through the middleware, or passed through it with Optional set and no
// valid session.
func ClaimsFrom(ctx context.Context) (authitjwt.Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(authitjwt.Claims)
	return claims, ok
}

// DefaultReturnToParam is the query parameter SessionMiddleware uses to
// tell the sign-in page where the user was going.
const DefaultReturnToParam = "next"

// SessionOptions configures SessionMiddleware. The zero value is usable: a
// cookie named DefaultSessionCookieName, and 401 for every unauthenticated
// request.
type SessionOptions struct {
	// Cookie is where the session token is read from. Use the same options
	// for SetSessionCookie at sign-in, or the middleware looks for a
	// cookie that is not there.
	Cookie SessionCookieOptions

	// SignInURL is where a browser is sent when it asks for a page without
	// a valid session. Empty means never redirect: every unauthenticated
	// request is a 401. Do not wrap the sign-in page itself in the
	// middleware, or the redirect loops.
	//
	// Only a GET or HEAD that IsAPIRequest does not claim is redirected.
	// Anything else gets a 401: redirecting a POST loses its body, and an
	// API client wants a status it can act on, not a sign-in form.
	SignInURL string

	// ReturnToParam is the query parameter added to SignInURL carrying the
	// path and query the user asked for. Defaults to DefaultReturnToParam.
	// Pass the value through SafeReturnTo before redirecting to it after
	// sign-in; it arrives from the browser, so anyone can put anything in
	// it.
	ReturnToParam string

	// IsAPIRequest reports whether a request is from a program rather than
	// a person navigating, and so wants a 401 rather than a redirect. The
	// default treats a request as a browser navigation when Sec-Fetch-Mode
	// is "navigate", or, when that header is absent, when Accept mentions
	// text/html; everything else is an API request.
	IsAPIRequest func(*http.Request) bool

	// Optional lets a request with no valid session through to the next
	// handler, without claims, instead of refusing it. It is for pages
	// that render differently when signed in -- a home page that shows
	// either "sign in" or the user's name. A failing session store is
	// still a 500: "could not check" is not "not signed in".
	Optional bool

	// ErrorHandler writes the response for a refused request: 401, or 500
	// when the session could not be checked. The default writes the status
	// text. err is what the validator returned, or ErrNoToken.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)
}

// SessionMiddleware authenticates each request by the session cookie,
// validating it with v -- a *user.Service in SessionModeOpaque -- and puts
// the claims in the request's context, where ClaimsFrom finds them.
//
// What it does with a request that has no valid session is the part every
// host used to write for itself:
//
//   - The session could not be checked (the store is down, or v is a
//     service in the wrong SessionMode): 500, never a redirect. A redirect
//     would send a signed-in user to the sign-in page whenever the database
//     hiccups, and they would sign in again, into the same outage.
//   - No session, or an expired, revoked or unknown one: a browser
//     navigation (GET or HEAD) is redirected with 303 to SignInURL, with the
//     page it asked for in ReturnToParam. Every other request gets a 401.
//     An invalid cookie is also cleared, so the browser stops sending it.
//   - A valid session with Cookie.MaxAge set re-issues the cookie, so the
//     browser keeps it for as long as the server-side session, which
//     user.Service extends on use, keeps living. Its lifetime is capped at
//     the session's own expiry.
//
// It returns an error for options that cannot work: a cookie the browser
// would discard, or a SignInURL that does not parse.
func SessionMiddleware(v SessionValidator, opts SessionOptions) (func(http.Handler) http.Handler, error) {
	if v == nil {
		return nil, errors.New("authit/http: nil session validator")
	}
	if err := opts.Cookie.validate(); err != nil {
		return nil, err
	}
	var signIn *url.URL
	if opts.SignInURL != "" {
		u, err := url.Parse(opts.SignInURL)
		if err != nil {
			return nil, fmt.Errorf("authit/http: SignInURL: %w", err)
		}
		signIn = u
	}
	param := opts.ReturnToParam
	if param == "" {
		param = DefaultReturnToParam
	}
	isAPI := opts.IsAPIRequest
	if isAPI == nil {
		isAPI = isAPIRequest
	}
	fail := opts.ErrorHandler
	if fail == nil {
		fail = func(w http.ResponseWriter, _ *http.Request, status int, _ error) {
			http.Error(w, http.StatusText(status), status)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := SessionCookie(r, opts.Cookie)
			var claims authitjwt.Claims
			err := ErrNoToken
			if ok {
				claims, err = v.ValidateSession(r.Context(), token)
			}
			if err == nil {
				slideCookie(w, r, token, claims, opts.Cookie)
				next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
				return
			}

			status := StatusFor(err)
			if status != http.StatusUnauthorized {
				fail(w, r, status, err)
				return
			}
			if ok {
				// The options were validated above, so this cannot fail.
				_ = ClearSessionCookie(w, r, opts.Cookie)
			}
			if opts.Optional {
				next.ServeHTTP(w, r)
				return
			}
			if signIn != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) && !isAPI(r) {
				http.Redirect(w, r, signInLocation(signIn, param, r), http.StatusSeeOther)
				return
			}
			fail(w, r, status, err)
		})
	}, nil
}

// slideCookie re-issues a persistent session cookie, so that the browser's
// copy outlives the request by as much as the server-side session does.
func slideCookie(w http.ResponseWriter, r *http.Request, token string, claims authitjwt.Claims, opts SessionCookieOptions) {
	if opts.MaxAge <= 0 {
		return
	}
	maxAge := opts.MaxAge
	if claims.ExpiresAt != nil {
		maxAge = min(maxAge, time.Until(claims.ExpiresAt.Time))
	}
	if maxAge < time.Second {
		return
	}
	http.SetCookie(w, opts.cookie(r, token, maxAge))
}

func signInLocation(signIn *url.URL, param string, r *http.Request) string {
	u := *signIn
	q := u.Query()
	q.Set(param, r.URL.RequestURI())
	u.RawQuery = q.Encode()
	return u.String()
}

// isAPIRequest is the default SessionOptions.IsAPIRequest.
func isAPIRequest(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode != "navigate"
	}
	return !strings.Contains(r.Header.Get("Accept"), "text/html")
}

// SafeReturnTo returns target if it is a path on this site, and fallback
// otherwise. Use it on the return-to value a sign-in page receives before
// redirecting to it, or the sign-in page becomes an open redirect: a link
// to your own domain that signs the user in and then delivers them,
// credentials fresh in mind, to a lookalike.
//
// Only a path that starts with a single "/" passes. Rejected, among
// others: an absolute URL, a scheme-relative "//evil.example", the
// "/\evil.example" that browsers read as scheme-relative, anything with a
// control character in it (browsers strip tabs and newlines, turning
// "/\t/evil.example" into "//evil.example"), and "javascript:" in any
// spelling.
func SafeReturnTo(target, fallback string) string {
	if target == "" || target[0] != '/' {
		return fallback
	}
	if len(target) > 1 && (target[1] == '/' || target[1] == '\\') {
		return fallback
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return fallback
		}
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fallback
	}
	return target
}
