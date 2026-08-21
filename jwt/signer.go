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

// Signer signs and verifies JWTs. The generic Sign/Verify methods work with
// any jwt.Claims-satisfying type, so a host application can define its own
// claims struct (e.g. embedding a team ID) without authit needing to know
// about it. Generate/Validate are a convenience pair fixed to Claims.
type Signer interface {
	Sign(claims jwt.Claims) (string, error)
	Verify(token string, dst jwt.Claims) error
	Generate(claims Claims) (string, error)
	Validate(token string) (Claims, error)
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

// Generate signs claims after applying issuer/TTL defaults for any zero
// fields.
func (s *HMACSigner) Generate(claims Claims) (string, error) {
	if claims.Issuer == "" {
		claims.Issuer = s.defaults.Issuer
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(s.defaults.TTL))
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
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
