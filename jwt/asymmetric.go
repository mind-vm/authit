package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

var (
	// ErrUnsupportedKey is returned when a key is of a type this package
	// cannot sign or verify with.
	ErrUnsupportedKey = errors.New("authit/jwt: unsupported key type")
	// ErrWeakKey is returned for an RSA key too small to be safe.
	ErrWeakKey = errors.New("authit/jwt: RSA key must be at least 2048 bits")
	// ErrNoKeys is returned by NewVerifier when given no keys.
	ErrNoKeys = errors.New("authit/jwt: at least one public key is required")
)

// MinRSABits is the smallest RSA modulus this package will sign or verify
// with.
const MinRSABits = 2048

// NewRS256Signer returns a Signer using RSASSA-PKCS1-v1_5 with SHA-256.
//
// Prefer NewEd25519Signer for new deployments: the keys and signatures are
// far smaller and there is no parameter to get wrong. RS256 is here because
// it is what most existing JWT consumers and JWKS clients expect.
func NewRS256Signer(priv *rsa.PrivateKey, defaults Defaults) (*AsymmetricSigner, error) {
	if priv == nil {
		return nil, ErrUnsupportedKey
	}
	if priv.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("%w: got %d", ErrWeakKey, priv.N.BitLen())
	}
	return newAsymmetricSigner(priv, priv.Public(), jwtlib.SigningMethodRS256, defaults)
}

// NewEd25519Signer returns a Signer using EdDSA (Ed25519).
func NewEd25519Signer(priv ed25519.PrivateKey, defaults Defaults) (*AsymmetricSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrUnsupportedKey
	}
	return newAsymmetricSigner(priv, priv.Public(), jwtlib.SigningMethodEdDSA, defaults)
}

// AsymmetricSigner signs with a private key and verifies with the matching
// public one. Unlike HMACSigner, the verifying half can be handed out
// safely: call Verifier to get a value that can check tokens and nothing
// else, and PublicKey/JWKS to publish the key it needs.
type AsymmetricSigner struct {
	priv     crypto.PrivateKey
	pub      crypto.PublicKey
	method   jwtlib.SigningMethod
	kid      string
	verifier *PublicKeyVerifier
	defaults Defaults
}

func newAsymmetricSigner(priv crypto.PrivateKey, pub crypto.PublicKey, method jwtlib.SigningMethod, defaults Defaults) (*AsymmetricSigner, error) {
	kid, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	if defaults.TTL <= 0 {
		defaults.TTL = time.Hour
	}
	v, err := NewVerifier(pub)
	if err != nil {
		return nil, err
	}
	return &AsymmetricSigner{priv: priv, pub: pub, method: method, kid: kid, verifier: v, defaults: defaults}, nil
}

func (s *AsymmetricSigner) Defaults() Defaults { return s.defaults }

// PublicKey returns the verifying half of the key pair, for publishing.
func (s *AsymmetricSigner) PublicKey() crypto.PublicKey { return s.pub }

// KeyID returns the RFC 7638 thumbprint of the public key, which is the
// `kid` written into every token this signer produces.
func (s *AsymmetricSigner) KeyID() string { return s.kid }

// Verifier returns a value that can check this signer's tokens but cannot
// produce any. This is what a second service should be given.
func (s *AsymmetricSigner) Verifier() *PublicKeyVerifier { return s.verifier }

// JWKS returns this signer's public key as a single-key JWK Set, ready to
// serve at a .well-known endpoint.
func (s *AsymmetricSigner) JWKS() ([]byte, error) { return JWKS(s.pub) }

// Sign signs an arbitrary claims value, stamping the key's `kid` into the
// header so a verifier holding several keys can select the right one
// without trial and error — which is what makes key rotation possible.
func (s *AsymmetricSigner) Sign(claims jwtlib.Claims) (string, error) {
	token := jwtlib.NewWithClaims(s.method, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.priv)
}

// Verify parses and validates token, populating dst on success.
func (s *AsymmetricSigner) Verify(token string, dst jwtlib.Claims) error {
	return s.verifier.Verify(token, dst)
}

// Generate signs claims after applying issuer/TTL defaults for zero fields.
func (s *AsymmetricSigner) Generate(claims Claims) (string, error) {
	applyDefaults(&claims, s.defaults)
	return s.Sign(&claims)
}

// Validate verifies token as Claims.
func (s *AsymmetricSigner) Validate(token string) (Claims, error) { return s.verifier.Validate(token) }

// ---------------------------------------------------------------------------
// verify-only
// ---------------------------------------------------------------------------

// PublicKeyVerifier verifies tokens against one or more public keys. It has
// no signing method and holds no private key, so a service given one cannot
// mint a token no matter what it does with it — which is the property
// HMACSigner cannot offer.
//
// Several keys may be supplied to span a rotation: publish the new key
// alongside the old, let every verifier pick both up, then switch the
// signer over and retire the old key once no unexpired token bears it.
type PublicKeyVerifier struct {
	byKID map[string]crypto.PublicKey
	// order preserves insertion order for the no-kid fallback, so
	// verification is deterministic rather than map-iteration order.
	order []crypto.PublicKey
}

// NewVerifier returns a Verifier for the given public keys, which must be
// *rsa.PublicKey or ed25519.PublicKey. Keys are indexed by their RFC 7638
// thumbprint, matching the `kid` AsymmetricSigner writes.
func NewVerifier(keys ...crypto.PublicKey) (*PublicKeyVerifier, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	v := &PublicKeyVerifier{byKID: make(map[string]crypto.PublicKey, len(keys))}
	for _, k := range keys {
		if err := checkPublicKey(k); err != nil {
			return nil, err
		}
		kid, err := KeyID(k)
		if err != nil {
			return nil, err
		}
		v.byKID[kid] = k
		v.order = append(v.order, k)
	}
	return v, nil
}

func checkPublicKey(k crypto.PublicKey) error {
	switch key := k.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < MinRSABits {
			return fmt.Errorf("%w: got %d", ErrWeakKey, key.N.BitLen())
		}
		return nil
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return ErrUnsupportedKey
		}
		return nil
	default:
		return ErrUnsupportedKey
	}
}

// methodMatchesKey reports whether the token's algorithm is the one this
// key type is for.
//
// The attack it concerns is algorithm confusion: the RSA public key is, by
// design, public, so an attacker signs a token with HS256 using those bytes
// as the HMAC secret and hopes the verifier just hands "the key" to the
// library.
//
// Be clear about what this check is and is not. golang-jwt already defeats
// that attack on its own — SigningMethodHMAC wants a []byte and gets an
// *rsa.PublicKey — and the resulting error wraps ErrTokenSignatureInvalid
// either way, so the request is a 401 with or without this function. It is
// defence in depth, not the load-bearing control.
//
// What it does change is what else the error wraps. Without it the failure
// also wraps jwtlib.ErrInvalidKeyType, which every other appearance of that
// sentinel means "the verifying side is misconfigured" — see the note on
// authithttp's tokenFaults. A host that watches for ErrInvalidKeyType to
// catch a bad deployment would then see an attacker's forgery as its own
// outage. Rejecting the mismatch here keeps the two signals distinct.
func methodMatchesKey(method jwtlib.SigningMethod, key crypto.PublicKey) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		_, ok := method.(*jwtlib.SigningMethodRSA)
		return ok
	case ed25519.PublicKey:
		_, ok := method.(*jwtlib.SigningMethodEd25519)
		return ok
	default:
		return false
	}
}

// Verify parses and validates token, populating dst on success.
func (v *PublicKeyVerifier) Verify(token string, dst jwtlib.Claims) error {
	parsed, err := jwtlib.ParseWithClaims(token, dst, func(t *jwtlib.Token) (any, error) {
		// A kid names exactly one key. If it names one we do not hold,
		// that is a failure rather than a reason to try the others: a
		// token that says which key signed it is either verifiable with
		// that key or forged.
		if kid, ok := t.Header["kid"].(string); ok && kid != "" {
			key, found := v.byKID[kid]
			if !found {
				return nil, fmt.Errorf("%w: unknown kid %q", jwtlib.ErrTokenSignatureInvalid, kid)
			}
			if !methodMatchesKey(t.Method, key) {
				return nil, jwtlib.ErrTokenSignatureInvalid
			}
			return key, nil
		}
		// No kid: fall back to the single key, or refuse to guess.
		if len(v.order) != 1 {
			return nil, fmt.Errorf("%w: token has no kid and this verifier holds %d keys",
				jwtlib.ErrTokenSignatureInvalid, len(v.order))
		}
		if !methodMatchesKey(t.Method, v.order[0]) {
			return nil, jwtlib.ErrTokenSignatureInvalid
		}
		return v.order[0], nil
	})
	if err != nil {
		return err
	}
	if !parsed.Valid {
		return jwtlib.ErrTokenInvalidClaims
	}
	return nil
}

// Validate verifies token as Claims.
func (v *PublicKeyVerifier) Validate(token string) (Claims, error) {
	var claims Claims
	if err := v.Verify(token, &claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// JWKS returns the public keys as a JWK Set document, ready to serve.
func (v *PublicKeyVerifier) JWKS() ([]byte, error) { return JWKS(v.order...) }
