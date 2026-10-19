package authithttp_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/authithttp"
)

func setSessionCookieHeader(t *testing.T, r *http.Request, opts authithttp.SessionCookieOptions) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := authithttp.SetSessionCookie(w, r, "tok", opts); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	got := w.Result().Header.Values("Set-Cookie")
	if len(got) != 1 {
		t.Fatalf("expected one Set-Cookie header, got %d", len(got))
	}
	return got[0]
}

func plainHTTP() *http.Request { return httptest.NewRequest(http.MethodGet, "http://app.test/", nil) }

func overTLS() *http.Request {
	r := plainHTTP()
	r.TLS = &tls.ConnectionState{}
	return r
}

func forwarded(proto string) *http.Request {
	r := plainHTTP()
	r.Header.Set("X-Forwarded-Proto", proto)
	return r
}

func TestSessionCookieDefaults(t *testing.T) {
	h := setSessionCookieHeader(t, plainHTTP(), authithttp.SessionCookieOptions{})
	for _, want := range []string{"authit_session=tok", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(h, want) {
			t.Fatalf("Set-Cookie %q is missing %q", h, want)
		}
	}
	if strings.Contains(h, "Max-Age") {
		t.Fatalf("a zero MaxAge should be a browser-session cookie: %s", h)
	}
}

// Without AllowHTTP the cookie is Secure on every response, including one
// to a plain-HTTP request -- which is what a request looks like to a server
// behind a TLS-terminating proxy, where Secure is exactly right.
func TestSessionCookieSecureDecision(t *testing.T) {
	cases := []struct {
		name   string
		r      *http.Request
		opts   authithttp.SessionCookieOptions
		secure bool
	}{
		{"default over http", plainHTTP(), authithttp.SessionCookieOptions{}, true},
		{"AllowHTTP over http", plainHTTP(), authithttp.SessionCookieOptions{AllowHTTP: true}, false},
		{"AllowHTTP over TLS", overTLS(), authithttp.SessionCookieOptions{AllowHTTP: true}, true},
		{"AllowHTTP, forwarded https, untrusted", forwarded("https"), authithttp.SessionCookieOptions{AllowHTTP: true}, false},
		{"AllowHTTP, forwarded https, trusted", forwarded("https"), authithttp.SessionCookieOptions{AllowHTTP: true, TrustForwardedProto: true}, true},
		{"AllowHTTP, forwarded HTTPS list, trusted", forwarded("HTTPS, http"), authithttp.SessionCookieOptions{AllowHTTP: true, TrustForwardedProto: true}, true},
		{"AllowHTTP, forwarded http, trusted", forwarded("http"), authithttp.SessionCookieOptions{AllowHTTP: true, TrustForwardedProto: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := setSessionCookieHeader(t, tc.r, tc.opts)
			if got := strings.Contains(h, "Secure"); got != tc.secure {
				t.Fatalf("Secure = %v, want %v: %s", got, tc.secure, h)
			}
		})
	}
}

func TestSessionCookiePrefixRules(t *testing.T) {
	for name, opts := range map[string]authithttp.SessionCookieOptions{
		"__Host- with a scoped path": {Name: "__Host-session", Path: "/app"},
		"__Host- with a domain":      {Name: "__Host-session", Domain: "example.com"},
		"__Host- with AllowHTTP":     {Name: "__Host-session", AllowHTTP: true},
		"__Secure- with AllowHTTP":   {Name: "__Secure-session", AllowHTTP: true},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := authithttp.SetSessionCookie(w, plainHTTP(), "tok", opts); !errors.Is(err, authithttp.ErrCookiePrefix) {
				t.Fatalf("expected ErrCookiePrefix, got %v", err)
			}
			if len(w.Result().Header.Values("Set-Cookie")) != 0 {
				t.Fatal("a cookie the browser would discard must not be written")
			}
		})
	}
	// __Host- works with the defaults, since Path defaults to "/".
	if h := setSessionCookieHeader(t, plainHTTP(), authithttp.SessionCookieOptions{Name: "__Host-session"}); !strings.Contains(h, "__Host-session=tok") {
		t.Fatalf("a valid __Host- cookie should be written: %q", h)
	}
}

func TestSessionCookieRejectsUnstorableValues(t *testing.T) {
	w := httptest.NewRecorder()
	if err := authithttp.SetSessionCookie(w, plainHTTP(), "has space", authithttp.SessionCookieOptions{}); !errors.Is(err, authithttp.ErrCookieValue) {
		t.Fatalf("expected ErrCookieValue, got %v", err)
	}
}

func TestSessionCookieClearMatchesSet(t *testing.T) {
	opts := authithttp.SessionCookieOptions{Name: "__Secure-session", Path: "/app", Domain: "app.example.com", MaxAge: time.Hour}
	set := setSessionCookieHeader(t, plainHTTP(), opts)
	w := httptest.NewRecorder()
	if err := authithttp.ClearSessionCookie(w, plainHTTP(), opts); err != nil {
		t.Fatalf("ClearSessionCookie: %v", err)
	}
	clear := w.Result().Header.Get("Set-Cookie")
	for _, attr := range []string{"__Secure-session=", "Path=/app", "Domain=app.example.com"} {
		if !strings.Contains(set, attr) || !strings.Contains(clear, attr) {
			t.Fatalf("set and clear must agree on %q\n set:   %s\n clear: %s", attr, set, clear)
		}
	}
	if !strings.Contains(clear, "Max-Age=0") || !strings.Contains(clear, "Expires=") {
		t.Fatalf("clear should expire the cookie both ways: %s", clear)
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	opts := authithttp.SessionCookieOptions{MaxAge: time.Hour}
	h := setSessionCookieHeader(t, plainHTTP(), opts)
	if !strings.Contains(h, "Max-Age=3600") {
		t.Fatalf("Max-Age must be whole seconds: %s", h)
	}
	r := plainHTTP()
	r.Header.Set("Cookie", strings.SplitN(h, ";", 2)[0])
	if got, ok := authithttp.SessionCookie(r, opts); !ok || got != "tok" {
		t.Fatalf("SessionCookie = %q, %v", got, ok)
	}
	if _, ok := authithttp.SessionCookie(plainHTTP(), opts); ok {
		t.Fatal("a missing cookie must report ok == false")
	}
	if _, ok := authithttp.SessionCookie(nil, opts); ok {
		t.Fatal("a nil request must report ok == false")
	}
}
