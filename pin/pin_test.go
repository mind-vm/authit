package pin_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/pin"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
)

// fastHasher is Argon2id at parameters cheap enough for a test. It still
// asks for a bcrypt hash to be re-hashed, which is what the import tests
// rely on.
var fastHasher = authitcrypto.Argon2idHasher{Memory: 64, Time: 1, Threads: 1}

// countingHasher counts Verify calls: how many PINs were actually tried.
type countingHasher struct {
	authitcrypto.Hasher
	verifies atomic.Int64
}

func (h *countingHasher) Verify(p, hash string) bool {
	h.verifies.Add(1)
	return h.Hasher.Verify(p, hash)
}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Log(_ context.Context, e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) last() audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[len(r.events)-1]
}

type fixture struct {
	svc      *pin.Service
	users    *memstore.UserStore
	lockouts *memstore.LockoutStore
	devices  *memstore.BoundDeviceStore
	pins     *memstore.PINStore
	audit    *recorder
	alice    store.User
}

// newFixture has one user, alice, with personnel number P-100 and email
// alice@example.com, both resolving to her.
func newFixture(t *testing.T, cfg pin.Config) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{
		users: memstore.NewUserStore(), lockouts: memstore.NewLockoutStore(),
		devices: memstore.NewBoundDeviceStore(), pins: memstore.NewPINStore(), audit: &recorder{},
	}
	now := time.Now()
	f.alice = store.User{ID: "u-alice", Email: "alice@example.com", CreatedAt: now, UpdatedAt: now}
	if err := f.users.CreateUser(ctx, &f.alice); err != nil {
		t.Fatal(err)
	}
	byEmail := pin.ByEmail(f.users)
	resolver := pin.LoginResolverFunc(func(ctx context.Context, login string) (string, error) {
		if strings.EqualFold(login, "P-100") {
			return f.alice.ID, nil
		}
		return byEmail.ResolveLogin(ctx, login)
	})
	if cfg.Hasher == nil {
		cfg.Hasher = fastHasher
	}
	cfg.AuditLogger = f.audit
	svc, err := pin.NewService(pin.Stores{
		Users: f.users, PINs: f.pins, Devices: f.devices, Lockouts: f.lockouts, Tx: &storetest.TxProbe{},
	}, resolver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	initial := "123456"
	if cfg.PINLength > 0 && cfg.PINLength < len(initial) {
		initial = initial[:cfg.PINLength]
	}
	if err := svc.SetPIN(ctx, "office", f.alice.ID, initial); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSignInBindsADevice(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	for _, login := range []string{"P-100", " p-100 ", "alice@example.com", "ALICE@example.com"} {
		res, err := f.svc.SignIn(ctx, login, "123456", "iPhone Safari", "ua", "10.0.0.1")
		if err != nil {
			t.Fatalf("SignIn(%q): %v", login, err)
		}
		if res.Token == "" || res.User.ID != f.alice.ID || res.Device.Name != "iPhone Safari" {
			t.Fatalf("SignIn(%q) = %+v", login, res)
		}
		if res.Device.ExpiresAt != nil {
			t.Fatal("a device token expires by default; it must not, for long offline periods")
		}
		u, d, err := f.svc.ValidateDevice(ctx, res.Token)
		if err != nil {
			t.Fatalf("ValidateDevice: %v", err)
		}
		if u.ID != f.alice.ID || d.ID != res.Device.ID {
			t.Fatalf("ValidateDevice = %s, %s", u.ID, d.ID)
		}
		// Only the hash is stored.
		stored, err := f.devices.GetBoundDevice(ctx, d.ID)
		if err != nil || stored.TokenHash == res.Token || stored.TokenHash != authitcrypto.HashToken(res.Token) {
			t.Fatalf("stored hash %q, err %v", stored.TokenHash, err)
		}
	}
	devices, err := f.svc.ListDevices(ctx, f.alice.ID)
	if err != nil || len(devices) != 4 {
		t.Fatalf("ListDevices = %d, %v", len(devices), err)
	}
	if f.audit.last().Type != audit.EventPINSignInSucceeded {
		t.Fatalf("last event = %s", f.audit.last().Type)
	}
}

// TestFailuresDoNotSayWhatWasWrong: an unknown login, a user without a PIN
// and a wrong PIN are one answer.
func TestFailuresDoNotSayWhatWasWrong(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	bob := store.User{ID: "u-bob", Email: "bob@example.com"}
	if err := f.users.CreateUser(ctx, &bob); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, login, pin string }{
		{"wrong PIN", "P-100", "000000"},
		{"unknown login", "P-999", "123456"},
		{"no PIN set", "bob@example.com", "123456"},
		{"empty login", "", "123456"},
		{"malformed PIN", "P-100", "12a"},
	} {
		_, err := f.svc.SignIn(ctx, c.login, c.pin, "d", "ua", "ip")
		if err != pin.ErrInvalidCredentials {
			t.Fatalf("%s: %v, want exactly ErrInvalidCredentials", c.name, err)
		}
		if e := f.audit.last(); e.Type != audit.EventPINSignInFailed || len(e.Metadata) != 0 {
			t.Fatalf("%s: audited %+v; the event must not record why", c.name, e)
		}
	}
}

func TestUnknownLoginCostsAHash(t *testing.T) {
	ctx := context.Background()
	h := &countingHasher{Hasher: fastHasher}
	f := newFixture(t, pin.Config{Hasher: h})
	before := h.verifies.Load()
	_, _ = f.svc.SignIn(ctx, "P-999", "123456", "d", "ua", "ip")
	if h.verifies.Load() != before+1 {
		t.Fatal("an unknown login was answered without the hash work a wrong PIN costs")
	}
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	for i := 0; i < 5; i++ {
		if _, err := f.svc.SignIn(ctx, "P-100", "000000", "d", "ua", "ip"); !errors.Is(err, pin.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	// Locked now, even with the right PIN, and through her other login too:
	// one person, one budget.
	for _, login := range []string{"P-100", "alice@example.com"} {
		if _, err := f.svc.SignIn(ctx, login, "123456", "d", "ua", "ip"); !errors.Is(err, pin.ErrLocked) {
			t.Fatalf("SignIn(%q) after 5 failures = %v, want ErrLocked", login, err)
		}
	}
	if f.audit.last().Type != audit.EventPINSignInLocked {
		t.Fatalf("last event = %s", f.audit.last().Type)
	}
	// A new PIN lifts the lock.
	if err := f.svc.SetPIN(ctx, "office", f.alice.ID, "654321"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "654321", "d", "ua", "ip"); err != nil {
		t.Fatalf("SignIn after a new PIN: %v", err)
	}
}

// TestUnknownLoginsLockToo: otherwise the lock itself would tell which
// logins exist.
func TestUnknownLoginsLockToo(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	for i := 0; i < 5; i++ {
		if _, err := f.svc.SignIn(ctx, "P-999", "000000", "d", "ua", "ip"); !errors.Is(err, pin.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := f.svc.SignIn(ctx, "p-999", "000000", "d", "ua", "ip"); !errors.Is(err, pin.ErrLocked) {
		t.Fatalf("an unknown login after 5 failures = %v, want ErrLocked", err)
	}
}

func TestLockIsConfigurableAndLifts(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{MaxFailedAttempts: 2, LockDuration: 200 * time.Millisecond})
	for i := 0; i < 2; i++ {
		_, _ = f.svc.SignIn(ctx, "P-100", "000000", "d", "ua", "ip")
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); !errors.Is(err, pin.ErrLocked) {
		t.Fatalf("after 2 failures with MaxFailedAttempts 2 = %v, want ErrLocked", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); err != nil {
		t.Fatalf("after LockDuration: %v", err)
	}
	// And a success clears the count: two more failures are allowed again.
	for i := 0; i < 2; i++ {
		if _, err := f.svc.SignIn(ctx, "P-100", "000000", "d", "ua", "ip"); !errors.Is(err, pin.ErrInvalidCredentials) {
			t.Fatalf("failure %d after a success: %v", i+1, err)
		}
	}
}

// TestConcurrentGuessesShareTheBudget: guesses that all arrive before any
// fails must not each get a try. With a six-digit PIN the limit is the
// whole defence.
func TestConcurrentGuessesShareTheBudget(t *testing.T) {
	ctx := context.Background()
	h := &countingHasher{Hasher: fastHasher}
	f := newFixture(t, pin.Config{Hasher: h})
	before := h.verifies.Load()
	var wg sync.WaitGroup
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			_, _ = f.svc.SignIn(ctx, "P-100", "000000", "d", "ua", "ip")
		}()
	}
	start.Done()
	wg.Wait()
	if tried := h.verifies.Load() - before; tried > 5 {
		t.Fatalf("%d concurrent guesses were checked, want at most 5", tried)
	}
}

func TestOperatorLock(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	res, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.lockouts.LockAccount(ctx, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); !errors.Is(err, pin.ErrLocked) {
		t.Fatalf("SignIn of a locked account = %v, want ErrLocked", err)
	}
	if _, _, err := f.svc.ValidateDevice(ctx, res.Token); !errors.Is(err, pin.ErrAccountLocked) {
		t.Fatalf("ValidateDevice of a locked account = %v, want ErrAccountLocked", err)
	}
}

func TestSetPINValidates(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	for _, p := range []string{"12345", "1234567", "12345a", "", "１２３４５６"} {
		if err := f.svc.SetPIN(ctx, "office", f.alice.ID, p); !errors.Is(err, pin.ErrInvalidPIN) {
			t.Fatalf("SetPIN(%q) = %v, want ErrInvalidPIN", p, err)
		}
	}
	g := newFixture(t, pin.Config{PINLength: 4})
	if err := g.svc.SetPIN(ctx, "office", g.alice.ID, "9876"); err != nil {
		t.Fatalf("a four-digit PIN with PINLength 4: %v", err)
	}
	if err := g.svc.SetPIN(ctx, "office", g.alice.ID, "123456"); !errors.Is(err, pin.ErrInvalidPIN) {
		t.Fatalf("a six-digit PIN with PINLength 4 = %v", err)
	}
	if err := f.svc.SetPIN(ctx, "office", "u-nobody", "123456"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetPIN for an unknown user = %v, want ErrNotFound", err)
	}
	stored, err := f.pins.GetPINCredential(ctx, f.alice.ID)
	if err != nil || !strings.HasPrefix(stored.PINHash, "$argon2id$") {
		t.Fatalf("stored PIN hash %q, %v; want Argon2id", stored.PINHash, err)
	}
}

func TestClearPIN(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	res, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ClearPIN(ctx, "office", f.alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); !errors.Is(err, pin.ErrInvalidCredentials) {
		t.Fatalf("SignIn without a PIN = %v", err)
	}
	// A bound device stays bound; that is RevokeAllDevices' job.
	if _, _, err := f.svc.ValidateDevice(ctx, res.Token); err != nil {
		t.Fatalf("ValidateDevice after ClearPIN: %v", err)
	}
}

// TestImportedBcryptPINVerifies: an existing bcrypt PIN hash keeps working,
// and is moved to Argon2id at the next sign-in.
func TestImportedBcryptPINVerifies(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	legacy, err := bcrypt.GenerateFromPassword([]byte("246810"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ImportPINHash(ctx, "migration", f.alice.ID, string(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "246810", "d", "ua", "ip"); err != nil {
		t.Fatalf("SignIn with an imported bcrypt PIN: %v", err)
	}
	stored, err := f.pins.GetPINCredential(ctx, f.alice.ID)
	if err != nil || !strings.HasPrefix(stored.PINHash, "$argon2id$") {
		t.Fatalf("after sign-in the hash is %q, want it re-hashed to Argon2id", stored.PINHash)
	}
	if _, err := f.svc.SignIn(ctx, "P-100", "246810", "d", "ua", "ip"); err != nil {
		t.Fatalf("SignIn after the re-hash: %v", err)
	}
	if err := f.svc.ImportPINHash(ctx, "migration", f.alice.ID, "plaintext"); !errors.Is(err, pin.ErrInvalidImport) {
		t.Fatalf("ImportPINHash of an unknown format = %v, want ErrInvalidImport", err)
	}
}

// TestImportedDeviceTokenStaysSignedIn: a device token stored elsewhere as
// hex(SHA-256(token)) -- auftrag's format -- imports and still validates.
func TestImportedDeviceTokenStaysSignedIn(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	for _, upper := range []bool{false, true} {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		sum := sha256.Sum256([]byte(token))
		hash := hex.EncodeToString(sum[:])
		if upper {
			hash = strings.ToUpper(hash)
		}
		bound := time.Now().Add(-90 * 24 * time.Hour)
		d, err := f.svc.ImportDevice(ctx, pin.ImportedDevice{
			UserID: f.alice.ID, Name: "Gerät", TokenHash: hash, CreatedAt: bound, LastUsedAt: &bound,
		})
		if err != nil {
			t.Fatalf("ImportDevice: %v", err)
		}
		u, got, err := f.svc.ValidateDevice(ctx, token)
		if err != nil {
			t.Fatalf("ValidateDevice of an imported token: %v", err)
		}
		if u.ID != f.alice.ID || got.ID != d.ID || !got.CreatedAt.Equal(bound) {
			t.Fatalf("ValidateDevice = %s, %+v", u.ID, got)
		}
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 62)} {
		if _, err := f.svc.ImportDevice(ctx, pin.ImportedDevice{UserID: f.alice.ID, TokenHash: bad}); !errors.Is(err, pin.ErrInvalidImport) {
			t.Fatalf("ImportDevice(%q) = %v, want ErrInvalidImport", bad, err)
		}
	}
}

func TestDeviceTokenTTL(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{DeviceTokenTTL: 100 * time.Millisecond})
	res, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if res.Device.ExpiresAt == nil {
		t.Fatal("DeviceTokenTTL set, but the device does not expire")
	}
	if _, _, err := f.svc.ValidateDevice(ctx, res.Token); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, _, err := f.svc.ValidateDevice(ctx, res.Token); !errors.Is(err, pin.ErrInvalidToken) {
		t.Fatalf("ValidateDevice after the TTL = %v, want ErrInvalidToken", err)
	}
}

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{})
	sign := func() pin.SignInResult {
		t.Helper()
		res, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	lost, self, a, b := sign(), sign(), sign(), sign()

	if err := f.svc.RevokeDevice(ctx, "office", lost.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ValidateDevice(ctx, lost.Token); !errors.Is(err, pin.ErrInvalidToken) {
		t.Fatalf("a revoked device = %v, want ErrInvalidToken", err)
	}
	if err := f.svc.RevokeDevice(ctx, "office", "no-such-device"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeDevice of an unknown device = %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := f.svc.RevokeDeviceByToken(ctx, self.Token); err != nil {
			t.Fatalf("RevokeDeviceByToken (%d): %v", i+1, err)
		}
	}
	if _, _, err := f.svc.ValidateDevice(ctx, self.Token); !errors.Is(err, pin.ErrInvalidToken) {
		t.Fatalf("a device that signed itself out = %v", err)
	}

	n, err := f.svc.RevokeAllDevices(ctx, "office", f.alice.ID)
	if err != nil || n != 2 {
		t.Fatalf("RevokeAllDevices = %d, %v; want the 2 still signed in", n, err)
	}
	for _, res := range []pin.SignInResult{a, b} {
		if _, _, err := f.svc.ValidateDevice(ctx, res.Token); !errors.Is(err, pin.ErrInvalidToken) {
			t.Fatalf("after RevokeAllDevices = %v", err)
		}
	}
	if _, _, err := f.svc.ValidateDevice(ctx, "garbage"); !errors.Is(err, pin.ErrInvalidToken) {
		t.Fatalf("an unknown token = %v", err)
	}
}

func TestLastUsedIsThrottled(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pin.Config{LastUsedInterval: time.Hour})
	res, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	_, d, err := f.svc.ValidateDevice(ctx, res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !d.LastUsedAt.Equal(*res.Device.LastUsedAt) {
		t.Fatal("LastUsedAt was written although the interval had not passed")
	}

	g := newFixture(t, pin.Config{LastUsedInterval: -1})
	res, err = g.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, d, err = g.svc.ValidateDevice(ctx, res.Token); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.devices.GetBoundDevice(ctx, d.ID)
	if !stored.LastUsedAt.After(*res.Device.LastUsedAt) {
		t.Fatal("LastUsedAt was not written with a negative interval")
	}
}

func TestHooks(t *testing.T) {
	ctx := context.Background()
	inactive := errors.New("employee is not active")
	var afterInTx bool
	f := newFixture(t, pin.Config{Hooks: pin.Hooks{
		BeforeBind: func(_ context.Context, u store.User) error {
			if u.Email == "alice@example.com" {
				return inactive
			}
			return nil
		},
	}})
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); !errors.Is(err, inactive) {
		t.Fatalf("SignIn refused by BeforeBind = %v", err)
	}
	if devices, _ := f.svc.ListDevices(ctx, f.alice.ID); len(devices) != 0 {
		t.Fatal("a refused sign-in bound a device")
	}
	// Refused after the PIN was right: not a failure against the budget.
	for i := 0; i < 6; i++ {
		if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); !errors.Is(err, inactive) {
			t.Fatalf("attempt %d = %v; BeforeBind refusals must not lock the PIN", i+1, err)
		}
	}

	g := newFixture(t, pin.Config{Hooks: pin.Hooks{
		AfterSignIn: func(ctx context.Context, u store.User, d store.BoundDevice) error {
			afterInTx = storetest.InTx(ctx)
			return nil
		},
	}})
	if _, err := g.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "ip"); err != nil {
		t.Fatal(err)
	}
	if !afterInTx {
		t.Fatal("AfterSignIn ran outside the transaction")
	}
}

func TestRateLimiterIsConsulted(t *testing.T) {
	ctx := context.Background()
	refused := &refuseAll{}
	f := newFixture(t, pin.Config{RateLimiter: refused})
	if _, err := f.svc.SignIn(ctx, "P-100", "123456", "d", "ua", "10.0.0.1"); !errors.Is(err, pin.ErrRateLimited) {
		t.Fatalf("SignIn under a refusing limiter = %v", err)
	}
	// By source address and by login, before anything is looked up.
	if strings.Join(refused.keys, ",") != "pin:ip:10.0.0.1,pin:login:p-100" {
		t.Fatalf("limiter keys = %v", refused.keys)
	}
}

type refuseAll struct{ keys []string }

func (r *refuseAll) Allow(_ context.Context, key string) error {
	r.keys = append(r.keys, key)
	return &ratelimitError{}
}

type ratelimitError struct{}

func (*ratelimitError) Error() string { return "refused" }
func (*ratelimitError) Unwrap() error { return pin.ErrRateLimited }
