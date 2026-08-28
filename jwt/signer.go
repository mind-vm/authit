package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidSecret is returned by NewHMACSigner when the secret is too
// short to be a safe HMAC-SHA256 key.
var ErrInvalidSecret = errors.New("authit/jwt: secret must be at least 32 bytes")

// Defaults are applied by Signer.Generate/Validate (the Claims-typed
// convenience methods); callers using Sign/Verify with a custom claims type
// apply them explicitly.
type Defaults struct {
	Issuer string
	TTL    time.Duration
}

// Verifier checks that a token is genuine and unexpired. It cannot mint
// one, and that is the whole point of it existing separately from Signer.
//
// With HMACSigner, verifying and signing need the same secret, so any
// service that can check a token can also forge one — including an
// impersonation token, since Claims.ActorID is an ordinary field. Inside a
// single binary that is fine. Across two, it is not: the second service
// should hold a Verifier built from a public key (see NewVerifier), which
// is structurally incapable of issuing anything.
//
// Take a Verifier, not a Signer, in any function that only needs to check a
// token — authithttp.Validate does. A Signer satisfies Verifier, so
// narrowing a parameter this way never breaks a caller.
type Verifier interface {
	// Verify parses and validates token into dst, which must be a pointer
	// to a jwt.Claims-satisfying type.
	Verify(token string, dst jwt.Claims) error
	// Validate verifies token as the default Claims type.
	Validate(token string) (Claims, error)
}

// Signer mints and verifies JWTs. The generic Sign/Verify methods work with
// any jwt.Claims-satisfying type, so a host application can define its own
// claims struct (e.g. embedding a team ID) without authit needing to know
// about it. Generate/Validate are a convenience pair fixed to Claims.
type Signer interface {
	Verifier
	Sign(claims jwt.Claims) (string, error)
	Generate(claims Claims) (string, error)
	Defaults() Defaults
}

// HMACSigner is a Signer backed by HMAC-SHA256 with a shared secret.
type HMACSigner struct {
	secret   []byte
	defaults Defaults
}

// NewHMACSigner constructs an HMACSigner. secret must be at least 32 bytes.
func NewHMACSigner(secret []byte, defaults Defaults) (*HMACSigner, error) {
	if len(secret) < 32 {
		return nil, ErrInvalidSecret
	}
	if defaults.TTL <= 0 {
		defaults.TTL = time.Hour
	}
	return &HMACSigner{secret: secret, defaults: defaults}, nil
}

func (s *HMACSigner) Defaults() Defaults { return s.defaults }

// Sign signs an arbitrary claims value.
func (s *HMACSigner) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// Verify parses and validates token, populating dst on success. dst must be
// a pointer to a jwt.Claims-satisfying type.
func (s *HMACSigner) Verify(token string, dst jwt.Claims) error {
	parsed, err := jwt.ParseWithClaims(token, dst, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return s.secret, nil
	})
	if err != nil {
		return err
	}
	if !parsed.Valid {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}

// applyDefaults fills issuer and the timestamps for any zero fields, so
// every Signer implementation treats Defaults identically.
func applyDefaults(claims *Claims, d Defaults) {
	if claims.Issuer == "" {
		claims.Issuer = d.Issuer
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(d.TTL))
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
}

// Generate signs claims after applying issuer/TTL defaults for any zero
// fields.
func (s *HMACSigner) Generate(claims Claims) (string, error) {
	applyDefaults(&claims, s.defaults)
	return s.Sign(&claims)
}

// Validate verifies token as Claims.
func (s *HMACSigner) Validate(token string) (Claims, error) {
	var claims Claims
	if err := s.Verify(token, &claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}
