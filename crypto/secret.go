package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrInvalidKeySize is returned by EncryptSecret/DecryptSecret when the key
// is not 32 bytes (AES-256).
var ErrInvalidKeySize = errors.New("authit/crypto: key must be 32 bytes")

// EncryptSecret encrypts plaintext (e.g. a TOTP secret) with AES-256-GCM
// under key, so it can be stored at rest without exposing it to anyone with
// read access to the database alone.
func EncryptSecret(key []byte, plaintext string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// DecryptSecret reverses EncryptSecret.
func DecryptSecret(key []byte, ciphertext []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("authit/crypto: ciphertext too short")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
