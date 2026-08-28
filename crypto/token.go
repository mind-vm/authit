package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// GenerateOpaqueToken returns a fresh cryptographically random token (used
// for refresh tokens, password reset links, email verification links, and
// pending-2FA sessions) together with its hash. Only the hash should ever
// be persisted; the raw value is returned to the caller exactly once.
func GenerateOpaqueToken() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

// HashToken hashes a raw opaque token for lookup/storage.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateStateToken returns a random, URL-safe value for an OAuth 2.0
// `state` parameter.
//
// Unlike the tokens above there is no hash to store: state is compared
// against a copy the host kept for the duration of one redirect, not looked
// up in a database, so there is nothing at rest to protect. It is separate
// from GenerateOpaqueToken only so that call sites say what they mean.
func GenerateStateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
