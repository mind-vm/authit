package jwt_test

import (
	"testing"
	"time"

	authitjwt "github.com/jryannel/authit/jwt"
)

func newSigner(t *testing.T) authitjwt.Signer {
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

func TestGenerateAndValidate(t *testing.T) {
	signer := newSigner(t)
	token, err := signer.Generate(authitjwt.Claims{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claims, err := signer.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Email != "a@example.com" {
		t.Fatalf("got email %q", claims.Email)
	}
	if claims.Issuer != "authit-test" {
		t.Fatalf("expected default issuer to be applied, got %q", claims.Issuer)
	}
}

func TestValidateRejectsWrongSecret(t *testing.T) {
	signer := newSigner(t)
	token, err := signer.Generate(authitjwt.Claims{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	otherSecret := make([]byte, 32)
	for i := range otherSecret {
		otherSecret[i] = byte(255 - i)
	}
	other, err := authitjwt.NewHMACSigner(otherSecret, authitjwt.Defaults{})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	if _, err := other.Validate(token); err == nil {
		t.Fatal("expected validation with a different secret to fail")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	secret := make([]byte, 32)
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{TTL: time.Millisecond})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	token, err := signer.Generate(authitjwt.Claims{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := signer.Validate(token); err == nil {
		t.Fatal("expected validation of an expired token to fail")
	}
}

func TestNewHMACSignerRejectsShortSecret(t *testing.T) {
	if _, err := authitjwt.NewHMACSigner([]byte("too-short"), authitjwt.Defaults{}); err == nil {
		t.Fatal("expected short secret to be rejected")
	}
}

func TestIsImpersonation(t *testing.T) {
	c := authitjwt.Claims{}
	if c.IsImpersonation() {
		t.Fatal("empty claims should not report impersonation")
	}
	c.ActorID = "admin-1"
	if !c.IsImpersonation() {
		t.Fatal("claims with ActorID should report impersonation")
	}
}
