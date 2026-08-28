package authithttp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultRefreshCookieName is the cookie name used when CookieOptions.Name
// is empty.
//
// It carries no __Host- or __Secure- prefix, deliberately. Those prefixes
// are worth using and are supported here (see CookieOptions.Name), but
// switching a cookie's name invalidates every session already issued under
// the old one, so it is not something a default should do to an application
// that upgrades.
const DefaultRefreshCookieName = "authit_refresh"

var (
	// ErrCookiePathRequired means CookieOptions.Path was empty.
	ErrCookiePathRequired = errors.New("authit/http: cookie Path is required")
	// ErrCookiePrefix means the cookie name carries a __Host- or __Secure-
	// prefix whose rules the other attributes break.
	ErrCookiePrefix = errors.New("authit/http: cookie name prefix conflicts with its attributes")
	// ErrCookieValue means the token cannot be stored in a cookie as-is.
	ErrCookieValue = errors.New("authit/http: token is not a valid cookie value")
)

// CookieOptions describes how a refresh token is stored in the browser.
//
// # Why this is here at all
//
// authit is a service layer and ships no cookie handling as a rule. The
// refresh token is the exception for the same reason bearer parsing is: it
// is a long-lived credential, the correct handling is identical in every
// consumer, and the incorrect handling is both easy and common. Left to
// "the caller's business", a refresh token ends up in localStorage, where
// any XSS on any page of the application reads it and gets a credential
// that outlives every access token.
type CookieOptions struct {
	// Name defaults to DefaultRefreshCookieName.
	//
	// Two prefixes are worth knowing about, and both are validated here
	// rather than left to fail silently in the browser:
	//
	//   __Secure-  requires Secure. Compatible with a scoped Path, so it
	//              is the one to reach for.
	//   __Host-    requires Secure, Path="/" and no Domain. Strongest --
	//              it cannot be set or overwritten by a subdomain -- but
	//              incompatible with scoping the cookie to a refresh
	//              route, so it is a real trade rather than a free win.
	//
	// A browser silently ignores a Set-Cookie whose prefix rules are
	// broken: no error, no cookie, and a login that appears to succeed and
	// then cannot refresh. Set/Clear return an error instead.
	Name string

	// Path is required. It is the point of the exercise: scoped to your
	// refresh route ("/auth/refresh"), the cookie is attached to that one
	// request instead of every request the browser makes to your origin,
	// so a long-lived credential stops being sprayed across your entire
	// API surface.
	//
	// Use "/" only if you have decided you want that.
	Path string

	// Domain is empty by default, which makes the cookie host-only: sent
	// to exactly the host that set it, and never to a sibling subdomain.
	// Setting it widens that to a domain and everything under it, which is
	// worth doing only if you actually need to.
	Domain string

	// MaxAge is how long the browser keeps the cookie. Zero makes it a
	// session cookie, discarded when the browser closes -- the safer
	// default, and the wrong one if you want people to stay signed in.
	// Set it to the same value as user.Config.RefreshTokenTTL when you do.
	MaxAge time.Duration

	// SameSite defaults to http.SameSiteStrictMode. A refresh cookie is
	// only ever sent by your own application's own request to its own
	// refresh route, so Strict costs nothing and removes the cookie from
	// cross-site requests entirely.
	SameSite http.SameSite

	// Insecure drops the Secure attribute, allowing the cookie over plain
	// HTTP. The field is spelled this way round so the unsafe choice is
	// the one you have to type: it exists for local development against
	// http://localhost and has no other legitimate use.
	Insecure bool
}

func (o CookieOptions) name() string {
	if o.Name == "" {
		return DefaultRefreshCookieName
	}
	return o.Name
}

func (o CookieOptions) sameSite() http.SameSite {
	if o.SameSite == 0 {
		return http.SameSiteStrictMode
	}
	return o.SameSite
}

// validate checks the options against the cookie-prefix rules, which
// browsers enforce by silently discarding the cookie.
func (o CookieOptions) validate() error {
	if o.Path == "" {
		return ErrCookiePathRequired
	}
	name := o.name()
	switch {
	case strings.HasPrefix(name, "__Host-"):
		if o.Insecure {
			return fmt.Errorf("%w: %q requires Secure, but Insecure is set", ErrCookiePrefix, name)
		}
		if o.Path != "/" {
			return fmt.Errorf(`%w: %q requires Path="/", got %q`, ErrCookiePrefix, name, o.Path)
		}
		if o.Domain != "" {
			return fmt.Errorf("%w: %q requires no Domain, got %q", ErrCookiePrefix, name, o.Domain)
		}
	case strings.HasPrefix(name, "__Secure-"):
		if o.Insecure {
			return fmt.Errorf("%w: %q requires Secure, but Insecure is set", ErrCookiePrefix, name)
		}
	}
	return nil
}

// SetRefreshCookie writes the refresh token to the response as a cookie.
//
// HttpOnly is always set and is not configurable. A refresh token readable
// from JavaScript is a refresh token stealable by any XSS anywhere in the
// application, and no use case justifies it -- the access token, which
// scripts do need, belongs in an Authorization header, which is what
// BearerToken reads.
//
// It returns an error rather than writing a cookie the browser will
// discard: an empty Path, a token that is not a legal cookie value, or a
// name prefix whose rules the other attributes break.
func SetRefreshCookie(w http.ResponseWriter, token string, opts CookieOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if !validCookieValue(token) {
		return ErrCookieValue
	}
	http.SetCookie(w, &http.Cookie{
		Name:     opts.name(),
		Value:    token,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   int(opts.MaxAge.Seconds()),
		Secure:   !opts.Insecure,
		HttpOnly: true,
		SameSite: opts.sameSite(),
	})
	return nil
}

// validCookieValue reports whether s is entirely RFC 6265 cookie-octets:
// printable ASCII excluding space, double quote, comma, semicolon and
// backslash.
//
// The check is here because net/http does not fail on a bad value -- it
// silently strips the offending bytes, so the cookie is written, stored,
// read back shorter than it went in, and the token no longer resolves.
// authit's own tokens are base64url and always pass; a host storing
// something of its own gets an error instead of a mystery.
func validCookieValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b == 0x21,
			b >= 0x23 && b <= 0x2B,
			b >= 0x2D && b <= 0x3A,
			b >= 0x3C && b <= 0x5B,
			b >= 0x5D && b <= 0x7E:
		default:
			return false
		}
	}
	return true
}

// ClearRefreshCookie expires the cookie SetRefreshCookie wrote.
//
// Pass the same CookieOptions used to set it. A browser matches a deletion
// against a cookie by name, domain and path, so clearing with a different
// Path leaves the original cookie in place -- the user appears to log out,
// the credential is still in the browser, and it still works. That is the
// mistake this function exists to make hard to write.
func ClearRefreshCookie(w http.ResponseWriter, opts CookieOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:   opts.name(),
		Value:  "",
		Path:   opts.Path,
		Domain: opts.Domain,
		// Both, because MaxAge governs modern browsers and Expires is the
		// fallback; a deletion that sets only one is honoured unevenly.
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   !opts.Insecure,
		HttpOnly: true,
		SameSite: opts.sameSite(),
	})
	return nil
}

// RefreshCookie reads the refresh token back off a request. It reports
// ok == false for a missing or empty cookie, and never a partial value.
//
// The token is not validated here in any sense: it is an opaque string that
// only user.Service.Refresh can resolve.
func RefreshCookie(r *http.Request, opts CookieOptions) (string, bool) {
	if r == nil {
		return "", false
	}
	c, err := r.Cookie(opts.name())
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
