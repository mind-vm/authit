package authithttp

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultSessionCookieName is the cookie name used when
// SessionCookieOptions.Name is empty. Like DefaultRefreshCookieName it
// carries no prefix, for the same reason: renaming a cookie signs everybody
// out, which is not something a default should do on upgrade.
const DefaultSessionCookieName = "authit_session"

// SessionCookieOptions describes how a session token -- the single
// credential user.SessionModeOpaque issues -- is stored in the browser.
//
// It mirrors CookieOptions, and differs from it where a session cookie is a
// different thing from a refresh cookie:
//
//   - Path defaults to "/". A refresh cookie is scoped to the one route
//     that spends it; a session cookie is the credential every page needs.
//   - SameSite defaults to Lax, not Strict. Under Strict, a signed-in user
//     who follows a link to the application from an email or a chat
//     arrives without the cookie and is shown the sign-in page. Lax still
//     withholds it from cross-site POSTs, which is the request CSRF is
//     made of; CSRFProtect covers what Lax leaves.
//   - Secure is decided per request when AllowHTTP is set, so one
//     configuration can serve http://localhost in development and HTTPS
//     behind a TLS-terminating proxy in production.
//
// HttpOnly is always set, for the reason given on SetRefreshCookie.
type SessionCookieOptions struct {
	// Name defaults to DefaultSessionCookieName. A __Host- or __Secure-
	// prefix is validated as it is for CookieOptions.Name, and cannot be
	// combined with AllowHTTP: both prefixes require Secure on every
	// response, which AllowHTTP exists to drop.
	Name string

	// Path defaults to "/".
	Path string

	// Domain is empty by default, which makes the cookie host-only.
	Domain string

	// MaxAge is how long the browser keeps the cookie. Zero makes it a
	// browser-session cookie, discarded when the browser closes. To keep
	// people signed in, set it to user.Config.RefreshTokenTTL, which is
	// the session's lifetime in opaque mode; SessionMiddleware then slides
	// the cookie along with the session.
	MaxAge time.Duration

	// SameSite defaults to http.SameSiteLaxMode.
	SameSite http.SameSite

	// AllowHTTP sets Secure only on a response to a request that arrived
	// over HTTPS, instead of on every response. Without it -- the default
	// -- the cookie is always Secure, which is correct behind a
	// TLS-terminating proxy as it stands: the browser is talking HTTPS
	// even though this server is not. It exists for development against
	// http://localhost.
	AllowHTTP bool

	// TrustForwardedProto makes AllowHTTP treat a request whose
	// X-Forwarded-Proto is "https" as HTTPS. Set it only behind a proxy
	// that sets that header itself and overwrites whatever the client
	// sent; otherwise a client chooses the answer. It has no effect
	// without AllowHTTP, since the cookie is then Secure regardless.
	TrustForwardedProto bool
}

func (o SessionCookieOptions) name() string {
	if o.Name == "" {
		return DefaultSessionCookieName
	}
	return o.Name
}

func (o SessionCookieOptions) path() string {
	if o.Path == "" {
		return "/"
	}
	return o.Path
}

func (o SessionCookieOptions) sameSite() http.SameSite {
	if o.SameSite == 0 {
		return http.SameSiteLaxMode
	}
	return o.SameSite
}

// secure reports whether the cookie written in response to r carries the
// Secure attribute.
func (o SessionCookieOptions) secure(r *http.Request) bool {
	return !o.AllowHTTP || isHTTPS(r, o.TrustForwardedProto)
}

// validate checks the options against the cookie-prefix rules, which
// browsers enforce by silently discarding the cookie.
func (o SessionCookieOptions) validate() error {
	name := o.name()
	switch {
	case strings.HasPrefix(name, "__Host-"):
		if o.AllowHTTP {
			return fmt.Errorf("%w: %q requires Secure, but AllowHTTP is set", ErrCookiePrefix, name)
		}
		if o.path() != "/" {
			return fmt.Errorf(`%w: %q requires Path="/", got %q`, ErrCookiePrefix, name, o.Path)
		}
		if o.Domain != "" {
			return fmt.Errorf("%w: %q requires no Domain, got %q", ErrCookiePrefix, name, o.Domain)
		}
	case strings.HasPrefix(name, "__Secure-"):
		if o.AllowHTTP {
			return fmt.Errorf("%w: %q requires Secure, but AllowHTTP is set", ErrCookiePrefix, name)
		}
	}
	return nil
}

func (o SessionCookieOptions) cookie(r *http.Request, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     o.name(),
		Value:    value,
		Path:     o.path(),
		Domain:   o.Domain,
		MaxAge:   int(maxAge.Seconds()),
		Secure:   o.secure(r),
		HttpOnly: true,
		SameSite: o.sameSite(),
	}
}

// SetSessionCookie writes the session token to the response as a cookie.
//
// It takes the request because, with AllowHTTP, whether the cookie is
// Secure depends on how the request arrived. Like SetRefreshCookie it
// returns an error rather than write a cookie the browser would discard.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, opts SessionCookieOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if !validCookieValue(token) {
		return ErrCookieValue
	}
	http.SetCookie(w, opts.cookie(r, token, opts.MaxAge))
	return nil
}

// ClearSessionCookie expires the cookie SetSessionCookie wrote. Pass the
// same options: a deletion that does not match the cookie's name, domain
// and path leaves it in place, still working.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request, opts SessionCookieOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	c := opts.cookie(r, "", 0)
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0)
	http.SetCookie(w, c)
	return nil
}

// SessionCookie reads the session token back off a request. It reports
// ok == false for a missing or empty cookie. The token is not validated: it
// means something only to user.Service.ValidateSession.
func SessionCookie(r *http.Request, opts SessionCookieOptions) (string, bool) {
	if r == nil {
		return "", false
	}
	c, err := r.Cookie(opts.name())
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// isHTTPS reports whether r arrived over HTTPS: on a TLS connection to this
// server or, when trustForwardedProto is set, through a proxy that says so
// in X-Forwarded-Proto. Only the first value counts, which is the one the
// proxy nearest the client wrote when it overwrites the header -- and a
// proxy that does not overwrite it should not be trusted at all.
func isHTTPS(r *http.Request, trustForwardedProto bool) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !trustForwardedProto {
		return false
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}
