package authhandlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mind-vm/authit/authhandlers"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
)

type capturingEmailer struct {
	lastResetToken        string
	lastVerificationToken string
}

func (c *capturingEmailer) SendPasswordReset(_ context.Context, _, token string) error {
	c.lastResetToken = token
	return nil
}

func (c *capturingEmailer) SendEmailVerification(_ context.Context, _, token string) error {
	c.lastVerificationToken = token
	return nil
}

func newTestServer(t *testing.T) (http.Handler, *user.Service, *capturingEmailer) {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authhandlers-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	emailer := &capturingEmailer{}
	stores := user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}
	svc, err := user.NewService(stores, signer, emailer, user.Config{
		EmailVerification: user.EmailVerificationOptional,
	})
	if err != nil {
		t.Fatalf("user.NewService: %v", err)
	}
	return authhandlers.NewUserHandler(svc, signer), svc, emailer
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode response body: %v (body: %s)", err, rec.Body.String())
	}
	return v
}

func TestRegisterAndLogin(t *testing.T) {
	h, _, _ := newTestServer(t)

	rec := doJSON(t, h, "POST", "/register", map[string]string{"email": "alice@example.com", "password": "s3cret-passphrase!!"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/register", map[string]string{"email": "alice@example.com", "password": "s3cret-passphrase!!"}, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register: status = %d, want 409", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/login", map[string]string{"email": "alice@example.com", "password": "wrong"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: status = %d, want 401", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/login", map[string]string{"email": "alice@example.com", "password": "s3cret-passphrase!!"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	type loginResponse struct {
		Tokens *tokenResponse `json:"tokens"`
	}
	got := decode[loginResponse](t, rec)
	if got.Tokens == nil || got.Tokens.AccessToken == "" || got.Tokens.RefreshToken == "" {
		t.Fatalf("expected tokens in login response, got %+v", got)
	}
}

func TestProtectedRouteRequiresBearer(t *testing.T) {
	h, _, _ := newTestServer(t)

	rec := doJSON(t, h, "GET", "/me/sessions", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me/sessions: status = %d, want 401", rec.Code)
	}
}

func TestPasswordChangeAndSessionLifecycle(t *testing.T) {
	h, _, _ := newTestServer(t)

	doJSON(t, h, "POST", "/register", map[string]string{"email": "bob@example.com", "password": "s3cret-passphrase!!"}, "")
	rec := doJSON(t, h, "POST", "/login", map[string]string{"email": "bob@example.com", "password": "s3cret-passphrase!!"}, "")
	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	type loginResponse struct {
		Tokens *tokenResponse `json:"tokens"`
	}
	login := decode[loginResponse](t, rec)
	access := login.Tokens.AccessToken

	rec = doJSON(t, h, "GET", "/me/sessions", nil, access)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	type sessionResponse struct {
		ID string `json:"id"`
	}
	sessions := decode[[]sessionResponse](t, rec)
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	rec = doJSON(t, h, "POST", "/password/change", map[string]string{
		"current_password": "s3cret-passphrase!!", "new_password": "n3wpassword!!",
	}, access)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change password: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/login", map[string]string{"email": "bob@example.com", "password": "s3cret-passphrase!!"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with old password after change: status = %d, want 401", rec.Code)
	}

	rec = doJSON(t, h, "DELETE", "/me/sessions/"+sessions[0].ID, nil, access)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke session: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestTwoFactorSetupRequiresAuth(t *testing.T) {
	h, _, _ := newTestServer(t)

	rec := doJSON(t, h, "POST", "/me/two-factor/setup", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("two-factor setup unauthenticated: status = %d, want 401", rec.Code)
	}
}
