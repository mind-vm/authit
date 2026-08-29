package authhandlers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/authhandlers"
	"github.com/mind-vm/authit/emaillogin"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/oidc"
	"github.com/mind-vm/authit/passkey"
	"github.com/mind-vm/authit/store"
)

// testSigner is the verifier the protected routes validate against.
func testSigner(t *testing.T) *authitjwt.HMACSigner {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authhandlers-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	return signer
}

// userToken mints an access token for the protected routes.
func userToken(t *testing.T) string {
	t.Helper()
	claims := authitjwt.Claims{Email: "user@example.com"}
	claims.Subject = "user-1"
	tok, err := testSigner(t).Generate(claims)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return tok
}

// echoIssuer stands in for a host minting a session. It records what it was
// handed so a test can assert the right user reached it.
type echoIssuer struct {
	user    store.User
	created bool
	calls   int
}

func (e *echoIssuer) issue() authhandlers.SessionIssuer {
	return func(w http.ResponseWriter, _ *http.Request, u store.User, created bool) error {
		e.user, e.created, e.calls = u, created, e.calls+1
		writeJSONBody(w, map[string]any{"user_id": u.ID, "created": created})
		return nil
	}
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// emaillogin
// ---------------------------------------------------------------------------

type recordingSender struct{ token, code string }

func (s *recordingSender) SendMagicLink(_ context.Context, _, token string) error {
	s.token = token
	return nil
}
func (s *recordingSender) SendSignInCode(_ context.Context, _, code string) error {
	s.code = code
	return nil
}

func newEmailLoginServer(t *testing.T, cfg emaillogin.Config) (http.Handler, *recordingSender, *echoIssuer) {
	t.Helper()
	sender := &recordingSender{}
	svc, err := emaillogin.NewService(emaillogin.Stores{
		Users: memstore.NewUserStore(), Tokens: memstore.NewEmailLoginStore(),
	}, sender, cfg)
	if err != nil {
		t.Fatalf("emaillogin.NewService: %v", err)
	}
	iss := &echoIssuer{}
	return authhandlers.NewEmailLoginHandler(svc, iss.issue()), sender, iss
}

func TestEmailLoginRoutes(t *testing.T) {
	h, sender, iss := newEmailLoginServer(t, emaillogin.Config{})

	if w := do(t, h, "POST", "/email/link/request", "", map[string]string{"email": "alice@example.com"}); w.Code != http.StatusNoContent {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	w := do(t, h, "POST", "/email/link/redeem", "", map[string]string{"token": sender.token})
	if w.Code != http.StatusOK {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	if iss.calls != 1 || !iss.created {
		t.Fatalf("the issuer should have been called once for a new account, got %d calls created=%v", iss.calls, iss.created)
	}

	// Codes go through the same shape.
	if w := do(t, h, "POST", "/email/code/request", "", map[string]string{"email": "bob@example.com"}); w.Code != http.StatusNoContent {
		t.Fatalf("code request: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "POST", "/email/code/redeem", "", map[string]string{"email": "bob@example.com", "code": sender.code})
	if w.Code != http.StatusOK {
		t.Fatalf("code redeem: %d %s", w.Code, w.Body)
	}
}

// TestEmailLoginRequestSaysNothingAboutTheAccount: this is a form anybody
// can type any address into, so a response that differed would be a
// membership oracle for the whole user table.
func TestEmailLoginRequestSaysNothingAboutTheAccount(t *testing.T) {
	h, _, _ := newEmailLoginServer(t, emaillogin.Config{DisableSignUp: true})
	known := do(t, h, "POST", "/email/link/request", "", map[string]string{"email": "known@example.com"})
	unknown := do(t, h, "POST", "/email/link/request", "", map[string]string{"email": "nobody@example.com"})
	if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
		t.Fatalf("responses differ: %d %q vs %d %q",
			known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
}

// TestEmailLoginFailuresAreIndistinguishable: the service deliberately does
// not tell wrong from expired from exhausted, and the handler must not
// reintroduce the distinction.
func TestEmailLoginFailuresAreIndistinguishable(t *testing.T) {
	h, sender, _ := newEmailLoginServer(t, emaillogin.Config{})
	if w := do(t, h, "POST", "/email/code/request", "", map[string]string{"email": "alice@example.com"}); w.Code != http.StatusNoContent {
		t.Fatalf("request: %d", w.Code)
	}
	wrong := do(t, h, "POST", "/email/code/redeem", "", map[string]string{"email": "alice@example.com", "code": "000000"})
	unknown := do(t, h, "POST", "/email/code/redeem", "", map[string]string{"email": "nobody@example.com", "code": "000000"})
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Fatalf("both should be 401: %d and %d", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("bodies differ: %q vs %q", wrong.Body.String(), unknown.Body.String())
	}
	_ = sender
}

func TestEmailLoginRequiresAnIssuer(t *testing.T) {
	svc, err := emaillogin.NewService(emaillogin.Stores{
		Users: memstore.NewUserStore(), Tokens: memstore.NewEmailLoginStore(),
	}, nil, emaillogin.Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a nil SessionIssuer must be refused at construction")
		}
	}()
	authhandlers.NewEmailLoginHandler(svc, nil)
}

// ---------------------------------------------------------------------------
// oidc
// ---------------------------------------------------------------------------

func newOIDCServer(t *testing.T) (http.Handler, *oidc.Service) {
	t.Helper()
	p := oidc.Provider{
		ID: "fake", ClientID: "client", ClientSecret: "secret",
		AuthURL:     "https://provider.example/authorize",
		TokenURL:    "https://provider.example/token",
		UserInfoURL: "https://provider.example/userinfo",
		Scopes:      []string{"openid", "email"},
	}
	svc, err := oidc.NewService(oidc.Stores{
		Users: memstore.NewUserStore(), Accounts: memstore.NewAccountStore(),
	}, []oidc.Provider{p}, oidc.Config{})
	if err != nil {
		t.Fatalf("oidc.NewService: %v", err)
	}
	iss := &echoIssuer{}
	h := authhandlers.NewOIDCHandler(svc, testSigner(t), iss.issue(),
		func(*http.Request, string) string { return "https://app.example/callback" },
		authhandlers.WithCeremonyKey(testCeremonyKey))
	return h, svc
}

// TestOIDCStartSetsALaxCookie is the detail that decides whether the flow
// works at all. The callback is a top-level navigation from the provider's
// origin, which is cross-site: a SameSite=Strict cookie is not sent with
// it, and the callback would then never find the state it must check.
func TestOIDCStartSetsALaxCookie(t *testing.T) {
	h, _ := newOIDCServer(t)
	r := httptest.NewRequest(http.MethodGet, "/oidc/fake/start", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("start should redirect, got %d %s", w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://provider.example/authorize?") {
		t.Fatalf("unexpected redirect target %q", loc)
	}
	if !strings.Contains(loc, "code_challenge=") || !strings.Contains(loc, "state=") {
		t.Fatalf("the authorization URL must carry PKCE and state: %q", loc)
	}

	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("the OAuth ceremony cookie must be SameSite=Lax or the callback cannot read it: %q", cookie)
	}
	for _, want := range []string{"HttpOnly", "Secure"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("ceremony cookie is missing %s: %q", want, cookie)
		}
	}
}

// TestOIDCCallbackWithoutStateIsRefused: no cookie means this browser
// started no sign-in here, so there is nothing worth exchanging a code for.
func TestOIDCCallbackWithoutStateIsRefused(t *testing.T) {
	h, _ := newOIDCServer(t)
	r := httptest.NewRequest(http.MethodGet, "/oidc/fake/callback?code=x&state=y", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", w.Code, w.Body)
	}
	if code := decode[map[string]any](t, w)["error"]; code != "state_missing" {
		t.Fatalf("error = %v, want state_missing", code)
	}
}

// TestOIDCProviderErrorIsReported: a user who pressed "cancel" arrives with
// error in the query rather than a failing status code.
func TestOIDCProviderErrorIsReported(t *testing.T) {
	h, _ := newOIDCServer(t)
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/fake/start", nil))

	r := httptest.NewRequest(http.MethodGet, "/oidc/fake/callback?error=access_denied", nil)
	r.Header.Set("Cookie", strings.SplitN(start.Header().Get("Set-Cookie"), ";", 2)[0])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", w.Code, w.Body)
	}
	if code := decode[map[string]any](t, w)["error"]; code != "provider_error" {
		t.Fatalf("error = %v, want provider_error", code)
	}
}

func TestOIDCUnknownProviderIs404(t *testing.T) {
	h, _ := newOIDCServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/nope/start", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d %s", w.Code, w.Body)
	}
}

func TestOIDCRequiresAnIssuerAndRedirectURI(t *testing.T) {
	_, svc := newOIDCServer(t)
	iss := &echoIssuer{}
	for name, run := range map[string]func(){
		"no issuer": func() {
			authhandlers.NewOIDCHandler(svc, testSigner(t), nil,
				func(*http.Request, string) string { return "x" },
				authhandlers.WithCeremonyKey(testCeremonyKey))
		},
		"no redirect uri": func() {
			authhandlers.NewOIDCHandler(svc, testSigner(t), iss.issue(), nil,
				authhandlers.WithCeremonyKey(testCeremonyKey))
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic at construction")
				}
			}()
			run()
		})
	}
}

// testCeremonyKey signs the ceremony cookies in these tests. A real host
// supplies its own; see authhandlers.WithCeremonyKey.
var testCeremonyKey = []byte("test-ceremony-key-not-for-production")

// ---------------------------------------------------------------------------
// passkey
// ---------------------------------------------------------------------------

func newPasskeyServer(t *testing.T) http.Handler {
	t.Helper()
	h, _ := newPasskeyServerWithService(t)
	return h
}

func newPasskeyServerWithService(t *testing.T) (http.Handler, *passkey.Service) {
	t.Helper()
	svc, err := passkey.NewService(passkey.Stores{
		Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore(),
		Challenges: memstore.NewWebAuthnChallengeStore(),
	}, passkey.Config{
		RPDisplayName: "Example", RPID: "example.com",
		RPOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("passkey.NewService: %v", err)
	}
	iss := &echoIssuer{}
	return authhandlers.NewPasskeyHandler(svc, testSigner(t), iss.issue(),
		authhandlers.WithCeremonyKey(testCeremonyKey)), svc
}

// TestPasskeyLoginBeginIsPublicAndSetsAStrictCookie. Unlike the OAuth
// cookie this ceremony is driven by XHR from the site's own page, so
// nothing is lost by refusing to send it cross-site.
func TestPasskeyLoginBeginIsPublicAndSetsAStrictCookie(t *testing.T) {
	h := newPasskeyServer(t)
	w := do(t, h, "POST", "/passkeys/login/begin", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	body := decode[map[string]any](t, w)
	pk, ok := body["publicKey"].(map[string]any)
	if !ok || pk["challenge"] == nil {
		t.Fatalf("expected WebAuthn request options, got %v", body)
	}
	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "SameSite=Strict") || !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("ceremony cookie should be HttpOnly and Strict: %q", cookie)
	}
}

// TestPasskeyRegistrationRequiresAuthentication is the one that matters.
// The registration ceremony proves possession of an authenticator and
// nothing about whose account it belongs on; unauthenticated, it lets
// anybody add their own passkey to somebody else's account.
func TestPasskeyRegistrationRequiresAuthentication(t *testing.T) {
	h := newPasskeyServer(t)
	for _, path := range []string{
		"/me/passkeys/register/begin", "/me/passkeys/register/finish",
	} {
		if w := do(t, h, "POST", path, "", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a token got %d, want 401: %s", path, w.Code, w.Body)
		}
	}
	if w := do(t, h, "GET", "/me/passkeys", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("listing without a token got %d, want 401", w.Code)
	}
	if w := do(t, h, "DELETE", "/me/passkeys/some-id", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("removing without a token got %d, want 401", w.Code)
	}
}

// TestPasskeyFinishWithoutACeremonyIsRefused: no cookie means no challenge
// this server issued, so there is nothing to verify against.
func TestPasskeyFinishWithoutACeremonyIsRefused(t *testing.T) {
	h := newPasskeyServer(t)
	w := do(t, h, "POST", "/passkeys/login/finish", "", map[string]string{"id": "x"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", w.Code, w.Body)
	}
	if code := decode[map[string]any](t, w)["error"]; code != "ceremony_missing" {
		t.Fatalf("error = %v, want ceremony_missing", code)
	}
}

func TestPasskeyRequiresAnIssuer(t *testing.T) {
	svc, err := passkey.NewService(passkey.Stores{
		Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore(),
		Challenges: memstore.NewWebAuthnChallengeStore(),
	}, passkey.Config{RPID: "example.com", RPOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a nil SessionIssuer must be refused at construction")
		}
	}()
	authhandlers.NewPasskeyHandler(svc, testSigner(t), nil,
		authhandlers.WithCeremonyKey(testCeremonyKey))
}

// TestForgedCeremonyCookieIsRejected is the property that decides whether
// the ceremony state is storage or an input.
//
// The cookie carries the WebAuthn challenge the assertion is checked
// against, and -- until it was signed -- nothing stopped a caller from
// writing one itself. That is not a cookie-theft scenario and HttpOnly does
// not touch it: the attacker never needs the victim's browser to hold or
// send anything, it mints the Cookie header with curl. A forged ceremony
// lets the caller choose the challenge, the expiry, and (before the passkey
// package stripped them) the origin allowlist the signature is verified
// against.
//
// The forged cookie carries a *complete and genuine* session payload, just
// without the MAC. That matters: a malformed one is refused by
// decodeSession, which reports ErrSession and therefore the same
// ceremony_missing this asserts -- so a cruder forgery passes this test
// whether or not the cookie is authenticated at all. Reusing a real payload
// leaves the signature as the only thing standing between the request and
// the ceremony.
func TestForgedCeremonyCookieIsRejected(t *testing.T) {
	h, svc := newPasskeyServerWithService(t)

	// A genuine session, minted straight from the service and encoded the
	// way a caller with curl would encode it: raw, unsigned. Deriving it
	// from a real Set-Cookie instead would mean stripping whatever the
	// implementation appends, which makes the forgery track the code it is
	// supposed to be testing -- strip 32 bytes from an unsigned cookie and
	// the leftover is malformed, refused by decodeSession, and the test
	// passes for a reason that has nothing to do with the MAC.
	_, sess, err := svc.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	forged := base64.RawURLEncoding.EncodeToString(sess)

	r := httptest.NewRequest("POST", "/passkeys/login/finish", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "authit_passkey_login", Value: forged})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("a cookie this server did not sign got %d, want 400: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); !strings.Contains(body, "ceremony_missing") {
		t.Fatalf("an unsigned cookie must be indistinguishable from an absent one, got %s", body)
	}
}

// TestCeremonyCookieIsBoundToItsName. Registration and login use separate
// cookie names so a half-finished registration cannot be presented to the
// login endpoint. Without the name inside the MAC that separation is only a
// convention the client is free to ignore -- it renames its own cookie and
// the signature still checks out.
func TestCeremonyCookieIsBoundToItsName(t *testing.T) {
	h := newPasskeyServer(t)
	begin := do(t, h, "POST", "/passkeys/login/begin", "", nil)
	var login string
	for _, c := range begin.Result().Cookies() {
		if c.Name == "authit_passkey_login" {
			login = c.Value
		}
	}
	if login == "" {
		t.Fatal("expected a login ceremony cookie")
	}

	// The same bytes, presented under the registration cookie's name.
	r := httptest.NewRequest("POST", "/me/passkeys/register/finish", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+userToken(t))
	r.AddCookie(&http.Cookie{Name: "authit_passkey_register", Value: login})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "ceremony_missing") {
		t.Fatalf("a login cookie presented as a registration cookie got %d: %s", w.Code, w.Body)
	}
}

// TestCeremonyKeyIsRequired. There is no safe default: a per-process key
// breaks across replicas and restarts, and anything derivable here is
// derivable by an attacker. Refused at construction rather than at the
// first ceremony.
func TestCeremonyKeyIsRequired(t *testing.T) {
	svc, err := passkey.NewService(passkey.Stores{
		Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore(),
		Challenges: memstore.NewWebAuthnChallengeStore(),
	}, passkey.Config{RPID: "example.com", RPOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	iss := &echoIssuer{}
	defer func() {
		if recover() == nil {
			t.Fatal("a missing ceremony key must be refused at construction")
		}
	}()
	authhandlers.NewPasskeyHandler(svc, testSigner(t), iss.issue())
}

// TestReplayedCeremonyIsRefusedOverHTTP is the end of the story the
// security review started: not "the cookie cannot be forged" but "the same
// request cannot be sent twice".
//
// Signing the ceremony cookie stopped a caller writing its own. It did not
// stop one replaying a genuine cookie together with the assertion that
// answered it -- both come from the same request, so a log line, an APM
// trace or a debug proxy that captured one captured both. The signature
// counter does not catch it either: go-webauthn exempts a counter of zero
// from the clone check and every synced passkey reports zero forever.
//
// Redeeming the ceremony exactly once is what closes it, and this asserts
// it where the attacker actually stands: at the HTTP boundary, replaying
// bytes.
func TestReplayedCeremonyIsRefusedOverHTTP(t *testing.T) {
	h, svc := newPasskeyServerWithService(t)

	// A real, signed ceremony cookie, exactly as the browser received it.
	begin := do(t, h, "POST", "/passkeys/login/begin", "", nil)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", begin.Code, begin.Body)
	}
	var cookie *http.Cookie
	for _, c := range begin.Result().Cookies() {
		if c.Name == "authit_passkey_login" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("expected a ceremony cookie")
	}

	// Replaying it, with any body at all, must not find the ceremony a
	// second time. The first request here stands in for the genuine
	// sign-in that spent it.
	spend := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/passkeys/login/finish", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// The body is not a valid assertion, so the ceremony fails to verify --
	// but it was found, which is the part that matters here.
	if w := spend(); w.Code == http.StatusBadRequest && strings.Contains(w.Body.String(), "ceremony_missing") {
		t.Fatalf("the first attempt should have found the ceremony, got %s", w.Body)
	}

	// Now it is gone: the handle was redeemed by the attempt above, and a
	// replay is indistinguishable from a handle that never existed.
	w := spend()
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "ceremony_missing") {
		t.Fatalf("a replayed ceremony got %d, want 400 ceremony_missing: %s", w.Code, w.Body)
	}

	// And the service agrees when asked directly, with no HTTP in the way.
	if _, err := svc.FinishDiscoverableLogin(context.Background(),
		passkey.Session("whatever"), httptest.NewRequest("POST", "/", strings.NewReader("{}"))); err == nil {
		t.Fatal("an unknown handle must not verify")
	}
}
