package authithttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
)

// fakeSessions validates the one token "good", refuses every other with
// user.ErrInvalidToken, and fails outright when down is set.
type fakeSessions struct {
	down    bool
	expires time.Time
}

var errStoreDown = errors.New("session store: connection refused")

func (f fakeSessions) ValidateSession(_ context.Context, token string) (authitjwt.Claims, error) {
	if f.down {
		return authitjwt.Claims{}, errStoreDown
	}
	if token != "good" {
		return authitjwt.Claims{}, user.ErrInvalidToken
	}
	exp := f.expires
	if exp.IsZero() {
		exp = time.Now().Add(24 * time.Hour)
	}
	return authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1", ExpiresAt: jwtlib.NewNumericDate(exp)},
		Email:            "alice@example.com",
	}, nil
}

// protected wraps a handler that reports the subject it was given.
func protected(t *testing.T, v authithttp.SessionValidator, opts authithttp.SessionOptions) http.Handler {
	t.Helper()
	mw, err := authithttp.SessionMiddleware(v, opts)
	if err != nil {
		t.Fatalf("SessionMiddleware: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authithttp.ClaimsFrom(r.Context())
		if !ok {
			w.Write([]byte("anonymous"))
			return
		}
		w.Write([]byte(claims.Subject))
	}))
}

type req struct {
	method string
	target string
	cookie string
	accept string
	fetch  string // Sec-Fetch-Mode
}

func (q req) do(h http.Handler) *httptest.ResponseRecorder {
	method := q.method
	if method == "" {
		method = http.MethodGet
	}
	r := httptest.NewRequest(method, q.target, nil)
	if q.cookie != "" {
		r.AddCookie(&http.Cookie{Name: authithttp.DefaultSessionCookieName, Value: q.cookie})
	}
	if q.accept != "" {
		r.Header.Set("Accept", q.accept)
	}
	if q.fetch != "" {
		r.Header.Set("Sec-Fetch-Mode", q.fetch)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const browserAccept = "text/html,application/xhtml+xml,*/*;q=0.8"

func TestSessionMiddlewarePutsClaimsInTheContext(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{SignInURL: "/signin"})
	w := req{target: "/account", cookie: "good", accept: browserAccept}.do(h)
	if w.Code != http.StatusOK || w.Body.String() != "user-1" {
		t.Fatalf("got %d %q, want 200 user-1", w.Code, w.Body.String())
	}
}

func TestSessionMiddlewareRefusals(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{SignInURL: "/signin?app=1"})
	cases := []struct {
		name     string
		req      req
		status   int
		location string
	}{
		{"browser GET, no cookie", req{target: "/account?tab=keys", accept: browserAccept}, http.StatusSeeOther, "/signin?app=1&next=%2Faccount%3Ftab%3Dkeys"},
		{"browser GET by Sec-Fetch-Mode", req{target: "/account", fetch: "navigate"}, http.StatusSeeOther, "/signin?app=1&next=%2Faccount"},
		{"browser HEAD", req{method: http.MethodHead, target: "/account", accept: browserAccept}, http.StatusSeeOther, "/signin?app=1&next=%2Faccount"},
		{"browser GET, invalid session", req{target: "/account", cookie: "revoked", accept: browserAccept}, http.StatusSeeOther, "/signin?app=1&next=%2Faccount"},
		{"browser POST", req{method: http.MethodPost, target: "/account", accept: browserAccept}, http.StatusUnauthorized, ""},
		{"fetch() from a page", req{target: "/api/me", accept: browserAccept, fetch: "cors"}, http.StatusUnauthorized, ""},
		{"API client", req{target: "/api/me", accept: "application/json"}, http.StatusUnauthorized, ""},
		{"no Accept at all", req{target: "/api/me"}, http.StatusUnauthorized, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.req.do(h)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if got := w.Header().Get("Location"); got != tc.location {
				t.Fatalf("Location %q, want %q", got, tc.location)
			}
		})
	}
}

// The bug #17 was about, at the level a host meets it: a revoked session
// from a real user.Service must be a 401 -- or a redirect -- never a 500.
func TestSessionMiddlewareOverOpaqueUserService(t *testing.T) {
	ctx := context.Background()
	svc, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, hmacSigner(t), nil, user.Config{SessionMode: user.SessionModeOpaque, EmailVerification: user.EmailVerificationOptional})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	u, err := svc.Register(ctx, "alice@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	res, err := svc.Authenticate(ctx, "alice@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	h := protected(t, svc, authithttp.SessionOptions{})

	if w := (req{target: "/", cookie: res.Tokens.AccessToken}).do(h); w.Code != http.StatusOK || w.Body.String() != u.ID {
		t.Fatalf("live session: %d %q", w.Code, w.Body.String())
	}
	if err := svc.Logout(ctx, res.Tokens.AccessToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if w := (req{target: "/", cookie: res.Tokens.AccessToken}).do(h); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session: %d, want 401", w.Code)
	}
}

// A store that cannot answer is an outage. Redirecting to sign-in would
// send every signed-in user round the login loop for the duration.
func TestSessionMiddlewareStoreFailureIs500(t *testing.T) {
	var got error
	mw, err := authithttp.SessionMiddleware(fakeSessions{down: true}, authithttp.SessionOptions{
		SignInURL: "/signin",
		Optional:  true,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, status int, err error) {
			got = err
			w.WriteHeader(status)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	w := req{target: "/", cookie: "good", accept: browserAccept}.do(h)
	if w.Code != http.StatusInternalServerError || w.Header().Get("Location") != "" {
		t.Fatalf("got %d to %q, want a plain 500", w.Code, w.Header().Get("Location"))
	}
	if !errors.Is(got, errStoreDown) {
		t.Fatalf("ErrorHandler got %v, want the store's error", got)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("an outage must not clear a cookie that may be perfectly good")
	}
}

func TestSessionMiddlewareClearsAnInvalidCookie(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{})
	w := req{target: "/", cookie: "revoked"}.do(h)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authithttp.DefaultSessionCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected the session cookie to be cleared, got %+v", cookies)
	}
	// No cookie, nothing to clear.
	if w := (req{target: "/"}).do(h); len(w.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be written when none was sent")
	}
}

func TestSessionMiddlewareWithoutSignInURLNeverRedirects(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{})
	if w := (req{target: "/", accept: browserAccept}).do(h); w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

func TestSessionMiddlewareOptional(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{SignInURL: "/signin", Optional: true})
	for _, cookie := range []string{"", "revoked"} {
		w := req{target: "/", cookie: cookie, accept: browserAccept}.do(h)
		if w.Code != http.StatusOK || w.Body.String() != "anonymous" {
			t.Fatalf("cookie %q: got %d %q, want 200 anonymous", cookie, w.Code, w.Body.String())
		}
	}
	if w := (req{target: "/", cookie: "good"}).do(h); w.Body.String() != "user-1" {
		t.Fatalf("a valid session must still be seen: %q", w.Body.String())
	}
}

func TestSessionMiddlewareCustomIsAPIRequest(t *testing.T) {
	h := protected(t, fakeSessions{}, authithttp.SessionOptions{
		SignInURL:    "/signin",
		IsAPIRequest: func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/") },
	})
	if w := (req{target: "/api/me", accept: browserAccept}).do(h); w.Code != http.StatusUnauthorized {
		t.Fatalf("/api/: got %d, want 401", w.Code)
	}
	if w := (req{target: "/page"}).do(h); w.Code != http.StatusSeeOther {
		t.Fatalf("/page: got %d, want 303", w.Code)
	}
}

// The server extends an opaque session on use. A persistent cookie has to
// follow, or the browser drops it while the session is still alive.
func TestSessionMiddlewareSlidesAPersistentCookie(t *testing.T) {
	h := protected(t, fakeSessions{expires: time.Now().Add(90 * time.Minute)},
		authithttp.SessionOptions{Cookie: authithttp.SessionCookieOptions{MaxAge: 24 * time.Hour}})
	cookies := req{target: "/", cookie: "good"}.do(h).Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "good" {
		t.Fatalf("expected the session cookie re-issued, got %+v", cookies)
	}
	// Capped at the session's own expiry, not the configured MaxAge.
	if age := cookies[0].MaxAge; age <= 80*60 || age > 90*60 {
		t.Fatalf("MaxAge = %d, want about 5400", age)
	}

	// A browser-session cookie has nothing to slide.
	h = protected(t, fakeSessions{}, authithttp.SessionOptions{})
	if cookies := (req{target: "/", cookie: "good"}).do(h).Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no Set-Cookie for a browser-session cookie, got %+v", cookies)
	}
}

func TestSessionMiddlewareRejectsUnworkableOptions(t *testing.T) {
	if _, err := authithttp.SessionMiddleware(nil, authithttp.SessionOptions{}); err == nil {
		t.Fatal("expected an error for a nil validator")
	}
	if _, err := authithttp.SessionMiddleware(fakeSessions{}, authithttp.SessionOptions{
		Cookie: authithttp.SessionCookieOptions{Name: "__Host-s", AllowHTTP: true},
	}); !errors.Is(err, authithttp.ErrCookiePrefix) {
		t.Fatalf("expected ErrCookiePrefix, got %v", err)
	}
	if _, err := authithttp.SessionMiddleware(fakeSessions{}, authithttp.SessionOptions{SignInURL: "http://[::1"}); err == nil {
		t.Fatal("expected an error for an unparseable SignInURL")
	}
}

func TestContextWithClaimsRoundTrip(t *testing.T) {
	if _, ok := authithttp.ClaimsFrom(context.Background()); ok {
		t.Fatal("an empty context has no claims")
	}
	ctx := authithttp.ContextWithClaims(context.Background(), authitjwt.Claims{Email: "a@example.com"})
	if c, ok := authithttp.ClaimsFrom(ctx); !ok || c.Email != "a@example.com" {
		t.Fatalf("ClaimsFrom = %+v, %v", c, ok)
	}
}

func TestSafeReturnTo(t *testing.T) {
	for _, target := range []string{"/", "/account", "/account?tab=keys#top", "/a/b/../c", "/%2F%2Fevil.example"} {
		if got := authithttp.SafeReturnTo(target, "/home"); got != target {
			t.Errorf("SafeReturnTo(%q) = %q, want it kept", target, got)
		}
	}
	for _, target := range []string{
		"", "account", "https://evil.example/", "//evil.example", "///evil.example",
		`/\evil.example`, `\\evil.example`, "/\t/evil.example", "/\n/evil.example",
		"javascript:alert(1)", "JaVaScRiPt:alert(1)", " /account", "/acc\x00ount", "/back\\slash",
	} {
		if got := authithttp.SafeReturnTo(target, "/home"); got != "/home" {
			t.Errorf("SafeReturnTo(%q) = %q, want the fallback", target, got)
		}
	}
	// What the middleware puts in the query comes back out intact.
	loc := req{target: "/account?tab=keys", accept: browserAccept}.do(protected(t, fakeSessions{}, authithttp.SessionOptions{SignInURL: "/signin"})).Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := authithttp.SafeReturnTo(u.Query().Get("next"), "/home"); got != "/account?tab=keys" {
		t.Fatalf("round trip through the redirect gave %q", got)
	}
}
