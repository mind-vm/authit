package crypto

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret creates a new base32 TOTP secret for the given account
// (typically the user's email) under issuer (typically the host
// application's name).
func GenerateTOTPSecret(issuer, accountName string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
}

// ValidateTOTPCode reports whether code is a currently-valid TOTP code for
// secret.
func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// BackupCodeBytes is the entropy behind each generated recovery code. A
// recovery code is a complete bypass of the second factor, so it is sized
// as a standalone credential rather than as something a human is expected
// to memorise: 8 bytes is 64 bits, rendered as 16 hex characters.
//
// It was 4 bytes (32 bits) before, which is brute-forceable given enough
// attempts. Codes issued under the old size keep working -- they are stored
// hashed and verification does not check length -- but any account enrolled
// before this change should be prompted to regenerate.
const BackupCodeBytes = 8

// GenerateBackupCodes returns n single-use recovery codes in plaintext. The
// caller is responsible for showing them to the user exactly once and
// persisting only their hashes via HashBackupCode.
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		buf := make([]byte, BackupCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(buf)
	}
	return codes, nil
}

// HashBackupCode hashes a backup code for storage/comparison, using the
// same opaque-token hash as everywhere else in authit.
func HashBackupCode(code string) string {
	return HashToken(code)
}
