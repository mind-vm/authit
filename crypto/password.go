// Package crypto provides the low-level primitives authit's service
// packages build on: password hashing, opaque token generation/hashing,
// TOTP enrollment/validation, and secret-at-rest encryption. Nothing here
// touches storage or transport.
package crypto

import "golang.org/x/crypto/bcrypt"

// DefaultBcryptCost matches bcrypt's own default and is what HashPassword
// uses unless overridden via HashPasswordWithCost.
const DefaultBcryptCost = bcrypt.DefaultCost

// HashPassword hashes a plaintext password for storage.
func HashPassword(password string) (string, error) {
	return HashPasswordWithCost(password, DefaultBcryptCost)
}

// HashPasswordWithCost hashes a plaintext password using an explicit bcrypt
// cost, e.g. a lower cost in tests to keep them fast.
func HashPasswordWithCost(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword reports whether password matches the given bcrypt hash.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
