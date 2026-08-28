package authithttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/authithttp"
)

func setCookieHeader(t *testing.T, opts authithttp.CookieOptions, token string) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := authithttp.SetRefreshCookie(w, token, opts); err != nil {
		t.Fatalf("SetRefreshCookie: %v", err)
	}
	got := w.Result().Header.Values("Set-Cookie")
	if len(got) != 1 {
		t.Fatalf("expected one Set-Cookie header, got %d", len(got))
	}
	return got[0]
}

// TestRefreshCookieIsAlwaysHttpOnlyAndSecure pins the two attributes that
// are not configurable, and the one that is only configurable the unsafe
// way round.
func TestRefreshCookieIsAlwaysHttpOnlyAndSecure(t *testing.T) {
	header := setCookieHeader(t, authithttp.CookieOptions{Path: "/auth/refresh"}, "tok")
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/auth/refresh"} {
		if !strings.Contains(header, want) {
			t.Fatalf("Set-Cookie %q is missing %q", header, want)
		}
	}
	// There is no option to turn HttpOnly off: a refresh token readable by
	// JavaScript is stealable by any XSS in the application.
	insecure := setCookieHeader(t, authithttp.CookieOptions{Path: "/auth/refresh", Insecure: true}, "tok")
	if !strings.Contains(insecure, "HttpOnly") {
		t.Fatal("HttpOnly must not be droppable")
	}
	if strings.Contains(insecure, "Secure") {
		t.Fatal("Insecure should drop the Secure attribute")
	}
}

// TestPathIsRequired: an unscoped refresh cookie is attached to every
// request to the origin, which is the thing this helper exists to avoid.
// Defaulting to "/" would have made that the silent outcome.
func TestPathIsRequired(t *testing.T) {
	w := httptest.NewRecorder()
	err := authithttp.SetRefreshCookie(w, "tok", authithttp.CookieOptions{})
	if !errors.Is(err, authithttp.ErrCookiePathRequired) {
		t.Fatalf("expected ErrCookiePathRequired, got %v", err)
	}
	if len(w.Result().Header.Values("Set-Cookie")) != 0 {
		t.Fatal("nothing should have been written")
	}
}

// TestCookiePrefixRulesAreEnforced is the subtle one. A browser given a
// Set-Cookie whose __Host-/__Secure- prefix rules are broken discards it
// without a word: no error, no cookie, and a login that looks successful
// until the first refresh fails.
func TestCookiePrefixRulesAreEnforced(t *testing.T) {
	for name, opts := range map[string]authithttp.CookieOptions{
		"__Host- with a scoped path": {Name: "__Host-refresh", Path: "/auth/refresh"},
		"__Host- with a domain":      {Name: "__Host-refresh", Path: "/", Domain: "example.com"},
		"__Host- without Secure":     {Name: "__Host-refresh", Path: "/", Insecure: true},
		"__Secure- without Secure":   {Name: "__Secure-refresh", Path: "/auth/refresh", Insecure: true},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := authithttp.SetRefreshCookie(w, "tok", opts); !errors.Is(err, authithttp.ErrCookiePrefix) {
				t.Fatalf("expected ErrCookiePrefix, got %v", err)
			}
			if len(w.Result().Header.Values("Set-Cookie")) != 0 {
				t.Fatal("a cookie the browser would discard must not be written")
			}
		})
	}

	// The combinations that are legal must still work.
	if h := setCookieHeader(t, authithttp.CookieOptions{Name: "__Host-refresh", Path: "/"}, "tok"); !strings.Contains(h, "__Host-refresh") {
		t.Fatalf("a valid __Host- cookie should be written: %q", h)
	}
	if h := setCookieHeader(t, authithttp.CookieOptions{Name: "__Secure-refresh", Path: "/auth/refresh"}, "tok"); !strings.Contains(h, "__Secure-refresh") {
		t.Fatalf("a valid __Secure- cookie should be written: %q", h)
	}
}

func TestRejectsUnstorableValues(t *testing.T) {
	for _, token := range []string{
		"", "has space", "has;semicolon", `has"quote`, "has,comma", `has\\backslash`,
		// net/http strips these silently rather than failing, so the
		// cookie would be written and read back shorter than it went in.
		"has\nnewline", "has\ttab", "nön-ascii",
	} {
		w := httptest.NewRecorder()
		if err := authithttp.SetRefreshCookie(w, token, authithttp.CookieOptions{Path: "/auth/refresh"}); !errors.Is(err, authithttp.ErrCookieValue) {
			t.Fatalf("token %q: expected ErrCookieValue, got %v", token, err)
		}
	}
}

// TestClearMatchesSet: a browser matches a deletion by name, domain and
// path. Clearing with a different path leaves the original cookie in place,
// so the user appears to log out while the credential stays in the browser
// and keeps working.
func TestClearMatchesSet(t *testing.T) {
	opts := authithttp.CookieOptions{Name: "__Secure-refresh", Path: "/auth/refresh", Domain: "app.example.com"}

	setHeader := setCookieHeader(t, opts, "tok")
	w := httptest.NewRecorder()
	if err := authithttp.ClearRefreshCookie(w, opts); err != nil {
		t.Fatalf("ClearRefreshCookie: %v", err)
	}
	clearHeader := w.Result().Header.Get("Set-Cookie")

	for _, attr := range []string{"__Secure-refresh=", "Path=/auth/refresh", "Domain=app.example.com"} {
		if !strings.Contains(setHeader, attr) || !strings.Contains(clearHeader, attr) {
			t.Fatalf("set and clear must agree on %q\n set:   %s\n clear: %s", attr, setHeader, clearHeader)
		}
	}
	if !strings.Contains(clearHeader, "Max-Age=0") {
		t.Fatalf("clear should expire the cookie: %s", clearHeader)
	}
	// Expires as well as Max-Age: a deletion that sets only one is
	// honoured unevenly across browsers.
	if !strings.Contains(clearHeader, "Expires=") {
		t.Fatalf("clear should set Expires too: %s", clearHeader)
	}
}

func TestMaxAgeIsSeconds(t *testing.T) {
	header := setCookieHeader(t, authithttp.CookieOptions{
		Path: "/auth/refresh", MaxAge: 7 * 24 * time.Hour,
	}, "tok")
	if !strings.Contains(header, "Max-Age=604800") {
		t.Fatalf("Max-Age must be whole seconds: %s", header)
	}
	// Zero means a session cookie, so no Max-Age attribute at all.
	sessionCookie := setCookieHeader(t, authithttp.CookieOptions{Path: "/auth/refresh"}, "tok")
	if strings.Contains(sessionCookie, "Max-Age") {
		t.Fatalf("a zero MaxAge should produce a session cookie: %s", sessionCookie)
	}
}

// TestRoundTrip: what Set writes, RefreshCookie reads.
func TestRoundTrip(t *testing.T) {
	opts := authithttp.CookieOptions{Path: "/auth/refresh"}
	header := setCookieHeader(t, opts, "the-refresh-token")

	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Cookie", strings.SplitN(header, ";", 2)[0])

	got, ok := authithttp.RefreshCookie(r, opts)
	if !ok || got != "the-refresh-token" {
		t.Fatalf("RefreshCookie = %q, %v; want the token back", got, ok)
	}

	// A request with no cookie reports absence rather than an empty token.
	if _, ok := authithttp.RefreshCookie(httptest.NewRequest(http.MethodPost, "/auth/refresh", nil), opts); ok {
		t.Fatal("a missing cookie must report ok == false")
	}
	if _, ok := authithttp.RefreshCookie(nil, opts); ok {
		t.Fatal("a nil request must report ok == false")
	}
}
