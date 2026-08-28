package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	authitjwt "github.com/mind-vm/authit/jwt"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func edKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// The whole point of T0.8: these types must satisfy the interfaces, and a
// verify-only value must NOT satisfy Signer.
var (
	_ authitjwt.Signer   = (*authitjwt.AsymmetricSigner)(nil)
	_ authitjwt.Verifier = (*authitjwt.AsymmetricSigner)(nil)
	_ authitjwt.Verifier = (*authitjwt.PublicKeyVerifier)(nil)
	_ authitjwt.Signer   = (*authitjwt.HMACSigner)(nil)
)

func TestAsymmetricRoundTrip(t *testing.T) {
	for name, newSigner := range map[string]func() (*authitjwt.AsymmetricSigner, error){
		"RS256": func() (*authitjwt.AsymmetricSigner, error) {
			return authitjwt.NewRS256Signer(rsaKey(t), authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
		},
		"EdDSA": func() (*authitjwt.AsymmetricSigner, error) {
			return authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := newSigner()
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}
			token, err := s.Generate(authitjwt.Claims{
				RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"},
				Email:            "alice@example.com",
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			claims, err := s.Validate(token)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if claims.Subject != "user-1" || claims.Email != "alice@example.com" || claims.Issuer != "authit-test" {
				t.Fatalf("unexpected claims: %+v", claims)
			}
			// The verify-only half accepts the same token.
			if _, err := s.Verifier().Validate(token); err != nil {
				t.Fatalf("Verifier().Validate: %v", err)
			}
			// A verifier built independently from the public key does too.
			v, err := authitjwt.NewVerifier(s.PublicKey())
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if _, err := v.Validate(token); err != nil {
				t.Fatalf("independent verifier: %v", err)
			}
		})
	}
}

// TestAlgorithmConfusionIsRejected: an attacker signs a token with HS256
// using the (public) RSA public key as the HMAC secret. A verifier that
// just hands "the key" to the library would accept it as genuine.
//
// golang-jwt refuses this on its own via its key-type check, so this test
// passes even with PublicKeyVerifier's algorithm pinning removed. It states
// the required behaviour; TestAlgorithmConfusionKeepsErrorSignalsDistinct
// covers what the pinning itself buys.
func TestAlgorithmConfusionIsRejected(t *testing.T) {
	priv := rsaKey(t)
	s, err := authitjwt.NewRS256Signer(priv, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewRS256Signer: %v", err)
	}
	pubBytes := priv.PublicKey.N.Bytes()

	forged := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, &authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "attacker",
			Issuer:    "authit-test",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	forged.Header["kid"] = s.KeyID()
	signed, err := forged.SignedString(pubBytes)
	if err != nil {
		t.Fatalf("signing the forgery: %v", err)
	}

	if _, err := s.Validate(signed); err == nil {
		t.Fatal("an HS256 token signed with the RSA public key must be rejected")
	}
	if _, err := s.Verifier().Validate(signed); err == nil {
		t.Fatal("the verify-only half must reject it too")
	}
}

// TestHMACSignerRejectsAsymmetricTokens is the mirror: an HMAC signer must
// not accept an RS256 token either.
func TestHMACSignerRejectsAsymmetricTokens(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	hs, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	rs, err := authitjwt.NewRS256Signer(rsaKey(t), authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewRS256Signer: %v", err)
	}
	token, err := rs.Generate(authitjwt.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := hs.Validate(token); err == nil {
		t.Fatal("HMACSigner must reject an RS256 token")
	}
}

// TestVerifierRejectsForeignKeys: a token from a different key pair of the
// same type must not verify.
func TestVerifierRejectsForeignKeys(t *testing.T) {
	mine, err := authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	theirs, err := authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	token, err := theirs.Generate(authitjwt.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := mine.Validate(token); err == nil {
		t.Fatal("a token signed by another key pair must be rejected")
	}
}

// TestKeyRotation: a verifier holding both keys accepts tokens from either,
// which is what makes a rollover possible without downtime.
func TestKeyRotation(t *testing.T) {
	oldSigner, err := authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	newSigner, err := authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	if oldSigner.KeyID() == newSigner.KeyID() {
		t.Fatal("distinct keys must get distinct thumbprints")
	}

	both, err := authitjwt.NewVerifier(oldSigner.PublicKey(), newSigner.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	for name, s := range map[string]*authitjwt.AsymmetricSigner{"old": oldSigner, "new": newSigner} {
		token, err := s.Generate(authitjwt.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"}})
		if err != nil {
			t.Fatalf("Generate (%s): %v", name, err)
		}
		if _, err := both.Validate(token); err != nil {
			t.Fatalf("verifier holding both keys rejected the %s key's token: %v", name, err)
		}
	}

	// Once the old key is retired, its tokens stop verifying.
	onlyNew, err := authitjwt.NewVerifier(newSigner.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	stale, err := oldSigner.Generate(authitjwt.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := onlyNew.Validate(stale); err == nil {
		t.Fatal("a retired key's tokens must stop verifying")
	}
}

func TestJWKS(t *testing.T) {
	rs, err := authitjwt.NewRS256Signer(rsaKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewRS256Signer: %v", err)
	}
	ed, err := authitjwt.NewEd25519Signer(edKey(t), authitjwt.Defaults{TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	doc, err := authitjwt.JWKS(rs.PublicKey(), ed.PublicKey())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		t.Fatalf("the document must be valid JSON: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(set.Keys))
	}
	// The kid must match what the signer stamps into its tokens, or a
	// relying party cannot select the key.
	if set.Keys[0]["kid"] != rs.KeyID() || set.Keys[1]["kid"] != ed.KeyID() {
		t.Fatal("JWKS kids must match the signers' key ids")
	}
	if set.Keys[0]["kty"] != "RSA" || set.Keys[0]["alg"] != "RS256" {
		t.Fatalf("unexpected RSA JWK: %v", set.Keys[0])
	}
	if set.Keys[1]["kty"] != "OKP" || set.Keys[1]["crv"] != "Ed25519" {
		t.Fatalf("unexpected Ed25519 JWK: %v", set.Keys[1])
	}
	// No private material, ever.
	for _, k := range set.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := k[private]; present {
				t.Fatalf("JWKS leaked private parameter %q", private)
			}
		}
	}
}

func TestRejectsUnsafeKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := authitjwt.NewRS256Signer(weak, authitjwt.Defaults{}); !errors.Is(err, authitjwt.ErrWeakKey) {
		t.Fatalf("expected ErrWeakKey for a 1024-bit key, got %v", err)
	}
	if _, err := authitjwt.NewVerifier(&weak.PublicKey); !errors.Is(err, authitjwt.ErrWeakKey) {
		t.Fatalf("expected ErrWeakKey from NewVerifier, got %v", err)
	}
	if _, err := authitjwt.NewRS256Signer(nil, authitjwt.Defaults{}); !errors.Is(err, authitjwt.ErrUnsupportedKey) {
		t.Fatalf("expected ErrUnsupportedKey for a nil key, got %v", err)
	}
	if _, err := authitjwt.NewEd25519Signer(ed25519.PrivateKey("too short"), authitjwt.Defaults{}); !errors.Is(err, authitjwt.ErrUnsupportedKey) {
		t.Fatalf("expected ErrUnsupportedKey, got %v", err)
	}
	if _, err := authitjwt.NewVerifier(); !errors.Is(err, authitjwt.ErrNoKeys) {
		t.Fatalf("expected ErrNoKeys, got %v", err)
	}
	// A private key must never be publishable as a JWK.
	if _, err := authitjwt.JWKS(rsaKey(t)); !errors.Is(err, authitjwt.ErrUnsupportedKey) {
		t.Fatalf("JWKS must refuse a private key, got %v", err)
	}
}

// TestAlgorithmConfusionKeepsErrorSignalsDistinct covers the narrow thing
// methodMatchesKey actually buys, and fails without it.
//
// Both with and without the pinning the forgery is refused and the error
// wraps ErrTokenSignatureInvalid, so the HTTP status is 401 either way.
// But without the pinning the error ALSO wraps ErrInvalidKeyType — the
// sentinel that everywhere else means "this server's key material is
// wrong". An operator watching that signal for a bad deployment would be
// paged by an attacker instead.
func TestAlgorithmConfusionKeepsErrorSignalsDistinct(t *testing.T) {
	priv := rsaKey(t)
	s, err := authitjwt.NewRS256Signer(priv, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewRS256Signer: %v", err)
	}
	forged := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, &authitjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "attacker",
			Issuer:    "authit-test",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	forged.Header["kid"] = s.KeyID()
	token, err := forged.SignedString(priv.PublicKey.N.Bytes())
	if err != nil {
		t.Fatalf("signing the forgery: %v", err)
	}

	_, err = s.Verifier().Validate(token)
	if err == nil {
		t.Fatal("the forged token must be rejected")
	}
	if !errors.Is(err, jwtlib.ErrTokenSignatureInvalid) {
		t.Fatalf("an attack must blame the token: %v", err)
	}
	if errors.Is(err, jwtlib.ErrInvalidKeyType) {
		t.Fatalf("an attack must not look like a misconfigured server: %v", err)
	}
}
