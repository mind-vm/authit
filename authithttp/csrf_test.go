package authithttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mind-vm/authit/authithttp"
)

func csrfHandler(t *testing.T, opts authithttp.CSRFOptions) (http.Handler, *error) {
	t.Helper()
	var refused error
	opts.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		refused = err
		w.WriteHeader(http.StatusForbidden)
	}
	mw, err := authithttp.CSRFProtect(opts)
	if err != nil {
		t.Fatalf("CSRFProtect: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(authithttp.CSRFToken(r)))
	})), &refused
}

func postFrom(headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://app.example.com/transfer", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestCSRFOriginCheck(t *testing.T) {
	h, refused := csrfHandler(t, authithttp.CSRFOptions{TrustedOrigins: []string{"https://admin.example.com"}})
	cases := []struct {
		name    string
		headers map[string]string
		ok      bool
	}{
		{"same origin", map[string]string{"Origin": "https://app.example.com"}, true},
		// Host, not scheme: behind a TLS proxy this server sees http.
		{"same host, other scheme", map[string]string{"Origin": "http://app.example.com"}, true},
		{"trusted origin", map[string]string{"Origin": "https://admin.example.com"}, true},
		{"trusted host, wrong scheme", map[string]string{"Origin": "http://admin.example.com"}, false},
		{"cross origin", map[string]string{"Origin": "https://evil.example"}, false},
		{"sibling subdomain", map[string]string{"Origin": "https://blog.example.com"}, false},
		{"null origin", map[string]string{"Origin": "null"}, false},
		{"referer only, same", map[string]string{"Referer": "https://app.example.com/form"}, true},
		{"referer only, cross", map[string]string{"Referer": "https://evil.example/page"}, false},
		{"referer garbage", map[string]string{"Referer": "not a url"}, false},
		{"neither, Sec-Fetch-Site same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		{"neither, Sec-Fetch-Site cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"neither, nothing at all", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*refused = nil
			w := httptest.NewRecorder()
			h.ServeHTTP(w, postFrom(tc.headers))
			if ok := w.Code == http.StatusOK; ok != tc.ok {
				t.Fatalf("passed = %v, want %v (status %d)", ok, tc.ok, w.Code)
			}
			if !tc.ok && !errors.Is(*refused, authithttp.ErrCrossOrigin) {
				t.Fatalf("refused with %v, want ErrCrossOrigin", *refused)
			}
		})
	}
}

func TestCSRFSafeMethodsPass(t *testing.T) {
	h, _ := csrfHandler(t, authithttp.CSRFOptions{})
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		r := httptest.NewRequest(m, "http://app.example.com/", nil)
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: got %d", m, w.Code)
		}
	}
}

func TestCSRFAllowMissingOrigin(t *testing.T) {
	h, _ := csrfHandler(t, authithttp.CSRFOptions{AllowMissingOrigin: true})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postFrom(nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	// It does not relax anything else.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, postFrom(map[string]string{"Origin": "https://evil.example"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross origin: got %d, want 403", w.Code)
	}
}

func TestCSRFDoubleSubmit(t *testing.T) {
	h, refused := csrfHandler(t, authithttp.CSRFOptions{DoubleSubmit: true})

	// A first GET issues the token: in a cookie, and to the page.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://app.example.com/form", nil))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authithttp.DefaultCSRFCookieName {
		t.Fatalf("expected the token cookie, got %+v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || !c.Secure {
		t.Fatalf("token cookie attributes: %+v", c)
	}
	token := w.Body.String()
	if token == "" || token != c.Value {
		t.Fatalf("CSRFToken %q does not match the cookie %q", token, c.Value)
	}

	// A later GET carrying it keeps it rather than minting another.
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/form", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.String() != token || len(w.Result().Cookies()) != 0 {
		t.Fatalf("token should be stable: got %q and %d cookies", w.Body.String(), len(w.Result().Cookies()))
	}

	post := func(cookie *http.Cookie, header, field string) int {
		form := url.Values{}
		if field != "" {
			form.Set(authithttp.DefaultCSRFField, field)
		}
		r := httptest.NewRequest(http.MethodPost, "http://app.example.com/transfer", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://app.example.com")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if header != "" {
			r.Header.Set(authithttp.DefaultCSRFHeader, header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := post(c, token, ""); got != http.StatusOK {
		t.Fatalf("token in header: %d", got)
	}
	if got := post(c, "", token); got != http.StatusOK {
		t.Fatalf("token in form: %d", got)
	}
	for name, code := range map[string]int{
		"no token sent":   post(c, "", ""),
		"wrong token":     post(c, "AAAAAAAAAAAAAAAAAAAAAAAAAA", ""),
		"no cookie":       post(nil, token, ""),
		"cookie mismatch": post(&http.Cookie{Name: authithttp.DefaultCSRFCookieName, Value: "other"}, token, ""),
	} {
		if code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403", name, code)
		}
	}
	if !errors.Is(*refused, authithttp.ErrCSRFToken) {
		t.Fatalf("refused with %v, want ErrCSRFToken", *refused)
	}
}

func TestCSRFRejectsUnworkableOptions(t *testing.T) {
	for _, o := range []string{"admin.example.com", "https://admin.example.com/path", "https://"} {
		if _, err := authithttp.CSRFProtect(authithttp.CSRFOptions{TrustedOrigins: []string{o}}); err == nil {
			t.Fatalf("TrustedOrigins %q: expected an error", o)
		}
	}
	if _, err := authithttp.CSRFProtect(authithttp.CSRFOptions{
		DoubleSubmit: true,
		TokenCookie:  authithttp.SessionCookieOptions{Name: "__Host-csrf", AllowHTTP: true},
	}); !errors.Is(err, authithttp.ErrCookiePrefix) {
		t.Fatalf("expected ErrCookiePrefix, got %v", err)
	}
}
