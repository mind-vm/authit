package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheExampleWorks drives the example the way a browser would: a
// protected page bounces to sign-in, registering signs in and returns to
// it, signing out ends the session, and a form posted from another origin
// is refused.
func TestTheExampleWorks(t *testing.T) {
	a, err := newApp(context.Background(), filepath.Join(t.TempDir(), "example.db"))
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	get := func(path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Accept", "text/html")
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res, string(body)
	}
	post := func(path, origin string, form url.Values) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Origin", origin)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res, string(body)
	}
	field := regexp.MustCompile(`name="(csrf_token|next)" value="([^"]*)"`)
	formOf := func(body string) url.Values {
		v := url.Values{}
		for _, m := range field.FindAllStringSubmatch(body, -1) {
			v.Set(m[1], m[2])
		}
		return v
	}

	// Not signed in: the account page lands on the sign-in form, which
	// remembers where the user was going.
	res, body := get("/account")
	if res.Request.URL.Path != "/signin" || !strings.Contains(body, `value="/account"`) {
		t.Fatalf("expected the sign-in form for /account, got %s: %s", res.Request.URL, body)
	}
	form := formOf(body)
	if form.Get("csrf_token") == "" {
		t.Fatalf("the form has no CSRF token: %s", body)
	}
	form.Set("email", "alice@example.com")
	form.Set("password", "correct-horse-battery-staple")

	// The same form from another origin is refused.
	if res, _ := post("/register", "https://evil.example", form); res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin register: %d, want 403", res.StatusCode)
	}

	// Registering signs in and goes back to /account.
	res, body = post("/register", srv.URL, form)
	if res.StatusCode != http.StatusOK || res.Request.URL.Path != "/account" || !strings.Contains(body, "Signed in as alice@example.com") {
		t.Fatalf("register: %d at %s: %s", res.StatusCode, res.Request.URL, body)
	}

	// Signing out ends the session for real: the account page bounces again.
	if res, _ := post("/signout", srv.URL, formOf(body)); res.Request.URL.Path != "/" {
		t.Fatalf("signout landed on %s", res.Request.URL)
	}
	if res, _ := get("/account"); res.Request.URL.Path != "/signin" {
		t.Fatalf("after sign-out /account landed on %s", res.Request.URL)
	}

	// A wrong password is a 401, and the right one signs in again.
	res, body = get("/signin?next=/account")
	form = formOf(body)
	form.Set("email", "alice@example.com")
	form.Set("password", "wrong")
	if res, _ := post("/signin", srv.URL, form); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d, want 401", res.StatusCode)
	}
	form.Set("password", "correct-horse-battery-staple")
	if res, body := post("/signin", srv.URL, form); res.Request.URL.Path != "/account" || !strings.Contains(body, "alice@example.com") {
		t.Fatalf("sign-in: at %s: %s", res.Request.URL, body)
	}
}
