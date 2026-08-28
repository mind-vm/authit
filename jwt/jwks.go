package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// jwk is one key in a JWK Set (RFC 7517). Only the members needed to
// verify a signature are emitted; `d` and the other private parameters have
// no representation here at all, so there is no way to leak one by mistake.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// OKP (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

// JWKS renders public keys as a JWK Set document (RFC 7517), the format a
// relying party fetches from a `.well-known/jwks.json` endpoint to learn
// which keys may sign tokens it should trust.
//
// Serving one is what turns "every service shares the signing secret" into
// "one service signs, everyone else verifies". Publish it, point consumers
// at it, and rotate by adding the new key to the set before switching the
// signer over.
//
// Only *rsa.PublicKey and ed25519.PublicKey are supported. Passing anything
// else — in particular a private key — is an error rather than a
// best-effort encoding, so this cannot quietly publish a secret.
func JWKS(keys ...crypto.PublicKey) ([]byte, error) {
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: make([]jwk, 0, len(keys))}

	for _, k := range keys {
		j, err := toJWK(k)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, j)
	}
	return json.Marshal(set)
}

func toJWK(key crypto.PublicKey) (jwk, error) {
	kid, err := KeyID(key)
	if err != nil {
		return jwk{}, err
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return jwk{}, fmt.Errorf("%w: got %d", ErrWeakKey, k.N.BitLen())
		}
		return jwk{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
			N: b64(k.N.Bytes()),
			E: b64(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return jwk{}, ErrUnsupportedKey
		}
		return jwk{
			Kty: "OKP", Use: "sig", Alg: "EdDSA", Kid: kid,
			Crv: "Ed25519", X: b64(k),
		}, nil
	default:
		return jwk{}, ErrUnsupportedKey
	}
}

// KeyID returns the RFC 7638 JWK thumbprint of a public key: the
// base64url-encoded SHA-256 of a JSON object containing only the required
// members, with no whitespace and the members in lexicographic order.
//
// Deriving the identifier from the key itself, rather than assigning one,
// means two parties compute the same `kid` for the same key without having
// to agree on anything.
func KeyID(key crypto.PublicKey) (string, error) {
	var canonical string
	switch k := key.(type) {
	case *rsa.PublicKey:
		// Required members for RSA, in lexicographic order: e, kty, n.
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`,
			b64(big.NewInt(int64(k.E)).Bytes()), b64(k.N.Bytes()))
	case ed25519.PublicKey:
		// Required members for OKP, in lexicographic order: crv, kty, x.
		if len(k) != ed25519.PublicKeySize {
			return "", ErrUnsupportedKey
		}
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, b64(k))
	default:
		return "", ErrUnsupportedKey
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:]), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
