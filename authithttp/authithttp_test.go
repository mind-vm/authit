package authithttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/jryannel/authit/authithttp"
	authitjwt "github.com/jryannel/authit/jwt"
)

func testSigner(t *testing.T) *authitjwt.HMACSigner {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	s, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	return s
}

func requestWithAuth(header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"canonical", "Bearer abc.def.ghi", "abc.def.ghi", true},
		// RFC 7235 makes the scheme case-insensitive.
		{"lowercase scheme", "bearer abc.def.ghi", "abc.def.ghi", true},
		{"uppercase scheme", "BEARER abc.def.ghi", "abc.def.ghi", true},
		{"mixed-case scheme", "BeArEr abc.def.ghi", "abc.def.ghi", true},
		{"tab separator", "Bearer\tabc.def.ghi", "abc.def.ghi", true},
		{"extra whitespace around credential", "Bearer   abc.def.ghi  ", "abc.def.ghi", true},

		// The TrimPrefix trap: none of these may come back as a token.
		{"no header", "", "", false},
		{"scheme only", "Bearer", "", false},
		{"scheme and space only", "Bearer ", "", false},
		{"bare token, no scheme", "abc.def.ghi", "", false},
		{"different scheme", "Basic dXNlcjpwYXNz", "", false},
		{"scheme is a prefix of a longer word", "BearerToken abc.def.ghi", "", false},
		{"credential contains whitespace", "Bearer abc def", "", false},
		{"empty value", " ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := authithttp.BearerToken(requestWithAuth(tc.header))
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("BearerToken(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// Which of two Authorization headers the caller meant isn't knowable here,
// so neither is used.
func TestBearerTokenRejectsRepeatedHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Authorization", "Bearer first")
	r.Header.Add("Authorization", "Bearer second")
	if got, ok := authithttp.BearerToken(r); ok {
		t.Fatalf("expected repeated Authorization headers to be rejected, got %q", got)
	}
}

func TestValidateAcceptsAGenuineToken(t *testing.T) {
	signer := testSigner(t)
	token, err := signer.Generate(authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"},
		Email:            "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	claims, err := authithttp.Validate(signer, requestWithAuth("Bearer "+token))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "alice@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if authithttp.StatusFor(nil) != http.StatusOK {
		t.Fatal("StatusFor(nil) should be 200")
	}
}

func TestValidateMissingTokenIsUnauthorized(t *testing.T) {
	signer := testSigner(t)
	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer "} {
		_, err := authithttp.Validate(signer, requestWithAuth(header))
		if !errors.Is(err, authithttp.ErrNoToken) {
			t.Fatalf("header %q: expected ErrNoToken, got %v", header, err)
		}
		if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
			t.Fatalf("header %q: expected 401, got %d", header, got)
		}
	}
}

func TestValidateBadTokenIsUnauthorized(t *testing.T) {
	signer := testSigner(t)

	// Signed with a different secret: a forgery.
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i + 99)
	}
	otherSigner, err := authitjwt.NewHMACSigner(other, authitjwt.Defaults{Issuer: "elsewhere", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	forged, err := otherSigner.Generate(authitjwt.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	expired, err := signer.Generate(authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("Generate (expired): %v", err)
	}

	// alg=none: the classic confusion attack, and the one case that reaches
	// golang-jwt as ErrTokenUnverifiable. It must be a 401, not a 500.
	unsigned, err := jwtlib.NewWithClaims(jwtlib.SigningMethodNone,
		jwtlib.RegisteredClaims{Subject: "user-1", ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour))},
	).SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing alg=none token: %v", err)
	}

	for name, token := range map[string]string{
		"forged":    forged,
		"expired":   expired,
		"alg none":  unsigned,
		"gibberish": "not-a-jwt-at-all",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := authithttp.Validate(signer, requestWithAuth("Bearer "+token))
			if !errors.Is(err, authithttp.ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got %v", err)
			}
			if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", got)
			}
		})
	}
}

// The error keeps the signer's own cause, so a host that wants to tell
// "expired, go refresh" from "forged" still can.
func TestValidatePreservesTheUnderlyingCause(t *testing.T) {
	signer := testSigner(t)
	expired, err := signer.Generate(authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, err = authithttp.Validate(signer, requestWithAuth("Bearer "+expired))
	if !errors.Is(err, jwtlib.ErrTokenExpired) {
		t.Fatalf("expected the wrapped error to still be ErrTokenExpired, got %v", err)
	}
}

// errSigner is a Signer whose verification is broken for its own reasons —
// standing in for one that fetches keys and can't reach them.
type errSigner struct {
	authitjwt.Signer
	err error
}

func (s errSigner) Validate(string) (authitjwt.Claims, error) { return authitjwt.Claims{}, s.err }

// A signer that can't verify anything is this server's fault, not the
// caller's: the request must not be reported as a failed login.
func TestValidateSignerFailureIsAServerError(t *testing.T) {
	broken := errors.New("fetching signing keys: connection refused")
	_, err := authithttp.Validate(errSigner{err: broken}, requestWithAuth("Bearer abc.def.ghi"))
	if errors.Is(err, authithttp.ErrInvalidToken) || errors.Is(err, authithttp.ErrNoToken) {
		t.Fatalf("a signer-level failure must not be classified as an auth failure: %v", err)
	}
	if !errors.Is(err, broken) {
		t.Fatalf("expected the signer's error to be wrapped, got %v", err)
	}
	if got := authithttp.StatusFor(err); got != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", got)
	}
}

// An impersonation token is genuine, so it validates — the host is the one
// who decides whether acting-as is allowed on a given route.
func TestValidateAcceptsImpersonationTokensForTheHostToJudge(t *testing.T) {
	signer := testSigner(t)
	token, err := signer.Generate(authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"},
		ActorID:          "operator-9",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claims, err := authithttp.Validate(signer, requestWithAuth("Bearer "+token))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !claims.IsImpersonation() || claims.ActorID != "operator-9" {
		t.Fatalf("expected impersonation claims to survive validation, got %+v", claims)
	}
}

func TestValidateNilSigner(t *testing.T) {
	if _, err := authithttp.Validate(nil, requestWithAuth("Bearer abc")); err == nil {
		t.Fatal("expected an error for a nil signer")
	}
}
