package authithttp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// DefaultCSRFCookieName, DefaultCSRFHeader and DefaultCSRFField are the
// defaults for the double-submit token in CSRFOptions.
const (
	DefaultCSRFCookieName = "authit_csrf"
	DefaultCSRFHeader     = "X-CSRF-Token"
	DefaultCSRFField      = "csrf_token"
)

var (
	// ErrCrossOrigin means a state-changing request came from another
	// origin, or did not say where it came from.
	ErrCrossOrigin = errors.New("authit/http: cross-origin request refused")
	// ErrCSRFToken means the double-submit token was missing or did not
	// match.
	ErrCSRFToken = errors.New("authit/http: missing or mismatched CSRF token")
)

// CSRFOptions configures CSRFProtect.
type CSRFOptions struct {
	// TrustedOrigins are other origins allowed to send state-changing
	// requests, written as the browser sends them in Origin:
	// "https://admin.example.com", scheme and host, no path. The request's
	// own host is always allowed.
	TrustedOrigins []string

	// AllowMissingOrigin lets through a state-changing request that carries
	// neither Origin nor Referer. Browsers send Origin on every cross-origin
	// request and on same-origin POSTs, so such a request is almost always
	// a program -- curl, a test, a server-side client -- which is not what
	// CSRF is about. It is refused by default because "almost always" is
	// not "always": an old browser or a privacy extension can strip both.
	AllowMissingOrigin bool

	// DoubleSubmit additionally requires a token: a random value set in a
	// cookie, which the page must echo back in the TokenHeader header or
	// the TokenField form field. Read it for rendering with CSRFToken.
	// The cookie is HttpOnly, so a script takes it from the page (a <meta>
	// tag, say), not from document.cookie.
	DoubleSubmit bool

	// TokenCookie is the double-submit cookie. Its Name defaults to
	// DefaultCSRFCookieName and its SameSite to Strict; everything else,
	// including AllowHTTP, works as for the session cookie. A __Host-
	// name is worth its constraints here: without it, a sibling subdomain
	// can plant a cookie of its own and so choose the token.
	TokenCookie SessionCookieOptions

	// TokenHeader and TokenField default to DefaultCSRFHeader and
	// DefaultCSRFField. The header is checked first; the form field is
	// read only when the header is absent, and reading it parses the body.
	TokenHeader string
	TokenField  string

	// ErrorHandler writes the response for a refused request. err is
	// ErrCrossOrigin or ErrCSRFToken. The default is a 403 with the status
	// text.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

type csrfTokenKey struct{}

// CSRFToken returns the double-submit token for r, for rendering into a
// form or a <meta> tag. It is empty unless r passed through CSRFProtect
// with DoubleSubmit set.
func CSRFToken(r *http.Request) string {
	token, _ := r.Context().Value(csrfTokenKey{}).(string)
	return token
}

// CSRFProtect refuses state-changing requests that another site could have
// made the browser send.
//
// SameSite=Lax on the session cookie already keeps it off a cross-site
// POST. What it does not cover: a browser that ignores SameSite, a request
// from a sibling subdomain (same site, different origin), and a
// state-changing GET, which no middleware can save and no application
// should have.
//
// Requests with a safe method (GET, HEAD, OPTIONS, TRACE) always pass.
// Every other request must come from the request's own host or one of
// TrustedOrigins, judged by Origin and, when the browser left that out, by
// Referer. The host is compared and not the scheme, as
// net/http.CrossOriginProtection does, so the check works unchanged behind
// a TLS-terminating proxy. With DoubleSubmit it must also echo the token.
//
// It returns an error for options that cannot work: a token cookie the
// browser would discard, or a TrustedOrigins entry that is not an origin.
func CSRFProtect(opts CSRFOptions) (func(http.Handler) http.Handler, error) {
	trusted := make(map[string]bool, len(opts.TrustedOrigins))
	for _, o := range opts.TrustedOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return nil, errors.New("authit/http: TrustedOrigins entry is not an origin: " + o)
		}
		trusted[strings.ToLower(u.Scheme+"://"+u.Host)] = true
	}
	cookie := opts.TokenCookie
	if cookie.Name == "" {
		cookie.Name = DefaultCSRFCookieName
	}
	if cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteStrictMode
	}
	if opts.DoubleSubmit {
		if err := cookie.validate(); err != nil {
			return nil, err
		}
	}
	header := opts.TokenHeader
	if header == "" {
		header = DefaultCSRFHeader
	}
	field := opts.TokenField
	if field == "" {
		field = DefaultCSRFField
	}
	fail := opts.ErrorHandler
	if fail == nil {
		fail = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			safe := false
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				safe = true
			}
			if !safe && !sameOrigin(r, trusted, opts.AllowMissingOrigin) {
				fail(w, r, ErrCrossOrigin)
				return
			}
			if !opts.DoubleSubmit {
				next.ServeHTTP(w, r)
				return
			}

			token, ok := SessionCookie(r, cookie)
			if !safe {
				sent := r.Header.Get(header)
				if sent == "" {
					sent = r.PostFormValue(field)
				}
				if !ok || sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
					fail(w, r, ErrCSRFToken)
					return
				}
			}
			if !ok {
				// rand.Text is 26 characters of base32: 130 bits, and
				// always a legal cookie value.
				token = rand.Text()
				http.SetCookie(w, cookie.cookie(r, token, cookie.MaxAge))
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfTokenKey{}, token)))
		})
	}, nil
}

// sameOrigin reports whether r says it came from its own host or a trusted
// origin.
func sameOrigin(r *http.Request, trusted map[string]bool, allowMissing bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			u, err := url.Parse(ref)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return false
			}
			origin = u.Scheme + "://" + u.Host
		}
	}
	if origin == "" {
		// Sec-Fetch-Site is sent by every current browser and cannot be
		// set by a page, so when it is present it settles the question.
		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin", "none":
			return true
		case "":
			return allowMissing
		default:
			return false
		}
	}
	if origin == "null" {
		// A sandboxed frame, a file: page, a redirect across origins: the
		// browser knows where the request came from and will not say.
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return trusted[strings.ToLower(u.Scheme+"://"+u.Host)]
}
