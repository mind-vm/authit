package crypto_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	authitcrypto "github.com/mind-vm/authit/crypto"
)

func TestArgon2idRoundTrip(t *testing.T) {
	h := authitcrypto.NewArgon2idHasher()
	hash, err := h.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=") {
		t.Fatalf("expected PHC-encoded argon2id, got %q", hash)
	}
	if !h.Verify("correct-horse-battery", hash) {
		t.Fatal("Verify should accept the correct password")
	}
	if h.Verify("wrong-horse-battery", hash) {
		t.Fatal("Verify should reject an incorrect password")
	}
	// Salted: the same password must not produce the same hash twice.
	again, err := h.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if again == hash {
		t.Fatal("two hashes of the same password must differ")
	}
}

// TestHashersVerifyEachOthersFormats is the property that makes swapping
// hashers safe: whichever is configured must accept every format authit has
// ever written, or changing it locks every existing user out.
func TestHashersVerifyEachOthersFormats(t *testing.T) {
	argon := authitcrypto.NewArgon2idHasher()
	bcryptHasher := authitcrypto.BcryptHasher{Cost: 4}

	argonHash, err := argon.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("argon Hash: %v", err)
	}
	bcryptHash, err := bcryptHasher.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("bcrypt Hash: %v", err)
	}

	for name, h := range map[string]authitcrypto.Hasher{"argon2id": argon, "bcrypt": bcryptHasher} {
		for format, hash := range map[string]string{"argon2id": argonHash, "bcrypt": bcryptHash} {
			if !h.Verify("shared-passphrase", hash) {
				t.Fatalf("%s hasher failed to verify a %s hash", name, format)
			}
			if h.Verify("not-the-passphrase", hash) {
				t.Fatalf("%s hasher accepted a wrong password against a %s hash", name, format)
			}
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	argon := authitcrypto.NewArgon2idHasher()
	bcryptHash, err := authitcrypto.BcryptHasher{Cost: 4}.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("bcrypt Hash: %v", err)
	}
	// The migration path: argon2id flags every bcrypt hash for upgrade.
	if !argon.NeedsRehash(bcryptHash) {
		t.Fatal("argon2id should flag a bcrypt hash for rehashing")
	}
	argonHash, err := argon.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if argon.NeedsRehash(argonHash) {
		t.Fatal("argon2id should not flag its own current-parameter hash")
	}
	// A hash written with weaker parameters is flagged; a stronger one is not.
	weak, err := authitcrypto.Argon2idHasher{Memory: 8 * 1024, Time: 1}.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !argon.NeedsRehash(weak) {
		t.Fatal("argon2id should flag a hash with weaker parameters")
	}
	strong, err := authitcrypto.Argon2idHasher{Memory: 64 * 1024, Time: 4}.Hash("shared-passphrase")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if argon.NeedsRehash(strong) {
		t.Fatal("argon2id should not flag a hash with stronger parameters")
	}
	if !argon.Verify("shared-passphrase", weak) || !argon.Verify("shared-passphrase", strong) {
		t.Fatal("parameters travel with the hash, so both must still verify")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	h := authitcrypto.NewArgon2idHasher()
	for _, bad := range []string{
		"", "not-a-hash", "$argon2id$", "$argon2id$v=19$m=x,t=2,p=1$aaa$bbb",
		"$argon2id$v=99$m=1024,t=1,p=1$YWJjZA$YWJjZA", "$argon2i$v=19$m=1024,t=1,p=1$YWJjZA$YWJjZA",
	} {
		if h.Verify("anything", bad) {
			t.Fatalf("Verify accepted malformed hash %q", bad)
		}
		if !h.NeedsRehash(bad) {
			t.Fatalf("NeedsRehash should flag unparseable hash %q", bad)
		}
	}
}

func TestPasswordPolicies(t *testing.T) {
	ctx := context.Background()
	def := authitcrypto.DefaultPasswordPolicy()

	if err := def(ctx, "a@b.com", "short"); !errors.Is(err, authitcrypto.ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword for a short password, got %v", err)
	}
	if err := def(ctx, "a@b.com", "long-enough-passphrase"); err != nil {
		t.Fatalf("expected an acceptable password to pass, got %v", err)
	}
	if err := def(ctx, "a@b.com", strings.Repeat("x", authitcrypto.DefaultMaxPasswordLength+1)); !errors.Is(err, authitcrypto.ErrWeakPassword) {
		t.Fatal("expected a password past the ceiling to be rejected")
	}
	// Length is counted in runes, not bytes: 12 three-byte characters is a
	// 12-character password, not a 36-character one.
	if err := def(ctx, "a@b.com", strings.Repeat("パ", authitcrypto.DefaultMinPasswordLength)); err != nil {
		t.Fatalf("expected rune-counted length, got %v", err)
	}
	if err := def(ctx, "a@b.com", strings.Repeat("パ", authitcrypto.DefaultMinPasswordLength-1)); !errors.Is(err, authitcrypto.ErrWeakPassword) {
		t.Fatal("expected a short multi-byte password to be rejected")
	}

	notEmail := authitcrypto.NotEmailPolicy()
	if err := notEmail(ctx, "alice@example.com", "my-alice-passphrase"); !errors.Is(err, authitcrypto.ErrWeakPassword) {
		t.Fatalf("expected a password containing the local part to be rejected, got %v", err)
	}
	if err := notEmail(ctx, "alice@example.com", "unrelated-passphrase"); err != nil {
		t.Fatalf("expected an unrelated password to pass, got %v", err)
	}

	combined := authitcrypto.AllPolicies(nil, authitcrypto.LengthPolicy(12, 0), notEmail)
	if err := combined(ctx, "alice@example.com", "alice-and-more-text"); !errors.Is(err, authitcrypto.ErrWeakPassword) {
		t.Fatal("AllPolicies should surface the first rejection")
	}
	if err := combined(ctx, "alice@example.com", "entirely-unrelated"); err != nil {
		t.Fatalf("AllPolicies should pass when every validator passes, got %v", err)
	}
}
