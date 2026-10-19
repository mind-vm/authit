package sqlitestore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	authitcrypto "github.com/mind-vm/authit/crypto"

	"github.com/mind-vm/authit/pin"
	"github.com/mind-vm/authit/store"
)

// TestPINFlowsOverSQLite runs package pin over the store: an imported
// bcrypt PIN and an imported hex(SHA-256) device token keep working, the
// lock holds against concurrent guesses, and revocation ends a device.
func TestPINFlowsOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	u := &store.User{ID: uuid.NewString(), Email: "field@example.com", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc, err := pin.NewService(pin.Stores{Users: s, PINs: s, Devices: s, Lockouts: s, Tx: s}, pin.ByEmail(s),
		pin.Config{Hasher: authitcrypto.Argon2idHasher{Memory: 64, Time: 1, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := bcrypt.GenerateFromPassword([]byte("135790"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ImportPINHash(ctx, "migration", u.ID, string(legacy)); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SignIn(ctx, "Field@Example.com", "135790", "Phone", "ua", "10.0.0.1")
	if err != nil {
		t.Fatalf("SignIn with an imported bcrypt PIN: %v", err)
	}
	if got, _, err := svc.ValidateDevice(ctx, res.Token); err != nil || got.ID != u.ID {
		t.Fatalf("ValidateDevice = %v, %v", got.ID, err)
	}

	token := "an-auftrag-device-token"
	sum := sha256.Sum256([]byte(token))
	imported, err := svc.ImportDevice(ctx, pin.ImportedDevice{UserID: u.ID, Name: "Gerät", TokenHash: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, d, err := svc.ValidateDevice(ctx, token); err != nil || d.ID != imported.ID {
		t.Fatalf("ValidateDevice of an imported token = %v, %v", d.ID, err)
	}

	// Concurrent wrong guesses: the lock must hold, the right PIN is then
	// refused, and a new PIN lifts it.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.SignIn(ctx, u.Email, "000000", "d", "ua", "ip")
			if !errors.Is(err, pin.ErrInvalidCredentials) && !errors.Is(err, pin.ErrLocked) {
				t.Errorf("a concurrent wrong guess = %v", err)
			}
		}()
	}
	wg.Wait()
	if _, err := svc.SignIn(ctx, u.Email, "135790", "d", "ua", "ip"); !errors.Is(err, pin.ErrLocked) {
		t.Fatalf("the right PIN after 12 wrong ones = %v, want ErrLocked", err)
	}
	if err := svc.SetPIN(ctx, "office", u.ID, "864200"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignIn(ctx, u.Email, "864200", "d", "ua", "ip"); err != nil {
		t.Fatalf("SignIn after a new PIN: %v", err)
	}

	if err := svc.RevokeDevice(ctx, "office", res.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateDevice(ctx, res.Token); !errors.Is(err, pin.ErrInvalidToken) {
		t.Fatalf("a revoked device = %v, want ErrInvalidToken", err)
	}
	if n, err := svc.RevokeAllDevices(ctx, "office", u.ID); err != nil || n != 2 {
		t.Fatalf("RevokeAllDevices = %d, %v; want the imported device and the last sign-in", n, err)
	}
}
