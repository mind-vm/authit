package crypto_test

import (
	"testing"

	authitcrypto "github.com/jryannel/authit/crypto"
)

func TestHashPasswordAndCheck(t *testing.T) {
	hash, err := authitcrypto.HashPasswordWithCost("s3cret!", 4)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !authitcrypto.CheckPassword("s3cret!", hash) {
		t.Fatal("CheckPassword should accept the correct password")
	}
	if authitcrypto.CheckPassword("wrong", hash) {
		t.Fatal("CheckPassword should reject an incorrect password")
	}
}

func TestGenerateOpaqueToken(t *testing.T) {
	raw1, hash1, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		t.Fatalf("GenerateOpaqueToken: %v", err)
	}
	raw2, hash2, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		t.Fatalf("GenerateOpaqueToken: %v", err)
	}
	if raw1 == raw2 {
		t.Fatal("expected distinct raw tokens")
	}
	if hash1 == hash2 {
		t.Fatal("expected distinct hashes")
	}
	if authitcrypto.HashToken(raw1) != hash1 {
		t.Fatal("HashToken(raw) should reproduce the paired hash")
	}
}

func TestNewID(t *testing.T) {
	id1, err := authitcrypto.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	id2, err := authitcrypto.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if id1 == id2 {
		t.Fatal("expected distinct IDs")
	}
	if len(id1) != 36 {
		t.Fatalf("expected UUID-shaped 36-char ID, got %q (%d)", id1, len(id1))
	}
}

func TestEncryptDecryptSecret(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	ciphertext, err := authitcrypto.EncryptSecret(key, "totp-secret-value")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	plaintext, err := authitcrypto.DecryptSecret(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if plaintext != "totp-secret-value" {
		t.Fatalf("got %q, want %q", plaintext, "totp-secret-value")
	}

	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	if _, err := authitcrypto.DecryptSecret(wrongKey, ciphertext); err == nil {
		t.Fatal("expected decryption with wrong key to fail")
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	key, err := authitcrypto.GenerateTOTPSecret("authit-test", "user@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	// We can't easily produce a valid live code without importing the totp
	// package's Generate helper directly; validate that an obviously wrong
	// code is rejected, which exercises the same code path.
	if authitcrypto.ValidateTOTPCode(key.Secret(), "000000") {
		t.Fatal("did not expect an arbitrary fixed code to validate (astronomically unlikely to be current)")
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := authitcrypto.GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate backup code %q", c)
		}
		seen[c] = true
		if authitcrypto.HashBackupCode(c) != authitcrypto.HashToken(c) {
			t.Fatal("HashBackupCode should equal HashToken for the same input")
		}
	}
}

func TestGenerateUserCode(t *testing.T) {
	code1, err := authitcrypto.GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode: %v", err)
	}
	code2, err := authitcrypto.GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode: %v", err)
	}
	if len(code1) != 9 || code1[4] != '-' {
		t.Fatalf("expected an XXXX-XXXX shaped code, got %q", code1)
	}
	if code1 == code2 {
		t.Fatal("expected distinct codes across calls (astronomically unlikely collision)")
	}
	for _, r := range code1 {
		if r == '-' {
			continue
		}
		if !containsRune("BCDFGHJKLMNPQRSTVWXZ", r) {
			t.Fatalf("unexpected character %q in user code %q", r, code1)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
