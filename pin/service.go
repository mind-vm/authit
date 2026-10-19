// Package pin implements sign-in with a short numeric PIN on a device that
// is then bound to the user: the pattern of an offline field app, where an
// operator sets a PIN, the phone signs in once, and from then on holds a
// long-lived, revocable device token instead of asking for a password.
//
// It is not the device package, which is the RFC 8628 grant a CLI uses to
// borrow a browser session. Here the device itself is the credential.
//
// # The flow
//
//   - An operator calls SetPIN (or ClearPIN). A new PIN lifts a lock.
//   - The device calls SignIn with a login and the PIN. The login is
//     resolved by the host through LoginResolver, so it can be a personnel
//     number as readily as an email address. SignIn returns a device token,
//     shown once and stored as its hash.
//   - Every request from the device calls ValidateDevice with that token.
//   - The office revokes a lost device with RevokeDevice or every device of
//     a user with RevokeAllDevices; the device signs itself out with
//     RevokeDeviceByToken.
//
// # Guessing
//
// A six-digit PIN is a million guesses, and its hash protects it from
// nobody who has the table. What protects it is the limit on wrong guesses:
// Config.MaxFailedAttempts within Config.LockDuration lock the login, 5 in
// 15 minutes by default, so at most that many PINs can be tried per window.
// The failures are recorded in the store.LockoutStore the user plane uses,
// under keys of this package's own, and Config.RateLimiter is consulted
// first, by source address and by login, before any hash is computed.
//
// The answer to a wrong login and to a wrong PIN is the same
// ErrInvalidCredentials, and an unknown login locks like a known one.
//
// # Coming from another implementation
//
// PIN hashes in bcrypt verify as they are, and are re-hashed to the
// configured Hasher (Argon2id by default) at the next successful sign-in;
// ImportPINHash stores one. Device tokens are stored as hex(SHA-256(token)),
// the format crypto.HashToken writes, so a table of such hashes imports
// unchanged through ImportDevice and the devices stay signed in.
//
// # Not here yet
//
// Binding a device once through a stronger sign-in (a magic link, OIDC) and
// using the PIN only on that device afterwards is not implemented. The
// device rows do not record how they were bound, so such a mode can bind
// the same rows; SignIn is the only binding method today.
package pin

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the pin package needs.
type Stores struct {
	Users    store.UserStore
	PINs     store.PINStore
	Devices  store.BoundDeviceStore
	Lockouts store.LockoutStore
	// Tx is optional. Supplying it makes binding the device and the
	// AfterSignIn hook one step, so a hook's error leaves no device
	// behind. See store.TxRunner.
	Tx store.TxRunner
}

// LoginResolver turns what a person types into the login field into the id
// of the authit user it names. It is the host's, because only the host
// knows what a login is in its domain: a personnel number, an email
// address, either.
//
// An unknown login is store.ErrNotFound; any other error is a fault and is
// returned from SignIn as it is.
type LoginResolver interface {
	ResolveLogin(ctx context.Context, login string) (userID string, err error)
}

// LoginResolverFunc adapts a function to LoginResolver.
type LoginResolverFunc func(ctx context.Context, login string) (string, error)

func (f LoginResolverFunc) ResolveLogin(ctx context.Context, login string) (string, error) {
	return f(ctx, login)
}

// ByEmail resolves a login as the email address of an authit user.
func ByEmail(users store.UserStore) LoginResolver {
	return LoginResolverFunc(func(ctx context.Context, login string) (string, error) {
		u, err := users.GetUserByEmail(ctx, store.NormalizeEmail(login))
		if err != nil {
			return "", err
		}
		return u.ID, nil
	})
}

// Hooks are optional callbacks into the host, in the shape of user.Hooks:
// every field is nil-safe, and a hook's error is returned unchanged.
type Hooks struct {
	// BeforeBind runs once the PIN has been verified and before the device
	// is bound. It is where a host refuses a user who may sign in in
	// principle but not here: an inactive employee, a role that has no
	// business on the field app. It runs after the PIN check on purpose,
	// so its answer reaches only someone who knows the PIN.
	BeforeBind func(ctx context.Context, u store.User) error
	// AfterSignIn runs once the device is bound. With Stores.Tx set it runs
	// in the same transaction, and its error undoes the binding.
	AfterSignIn func(ctx context.Context, u store.User, d store.BoundDevice) error
}

// Config tunes the pin package.
type Config struct {
	// PINLength is the number of digits SetPIN requires. Defaults to 6.
	PINLength int
	// MaxFailedAttempts wrong PINs within LockDuration lock the login.
	// Defaults to 5.
	MaxFailedAttempts int
	// LockDuration is the window failures are counted in, and so the
	// longest a lock lasts: it lifts as the failures age out of it.
	// Defaults to 15 minutes.
	LockDuration time.Duration
	// DeviceTokenTTL, when positive, signs a device out that long after
	// it was bound. Zero, the default, keeps it signed in until revoked,
	// for devices that spend long stretches offline.
	DeviceTokenTTL time.Duration
	// LastUsedInterval is how stale a device's LastUsedAt may get before
	// ValidateDevice writes it again, so a busy device does not cost a
	// write per request. Defaults to one minute; negative writes it on
	// every use.
	LastUsedInterval time.Duration
	// Hasher hashes new PINs. Defaults to crypto.DefaultHasher, Argon2id.
	// Whatever it is, bcrypt and Argon2id hashes both verify.
	Hasher authitcrypto.Hasher
	// RateLimiter is consulted before every sign-in, by source address and
	// by login. Nil means ratelimit.Noop.
	RateLimiter ratelimit.Limiter
	// AuditLogger receives the package's events. Nil means none are
	// recorded.
	AuditLogger audit.Logger
	Hooks       Hooks
}

func (c Config) withDefaults() Config {
	if c.PINLength <= 0 {
		c.PINLength = 6
	}
	if c.MaxFailedAttempts <= 0 {
		c.MaxFailedAttempts = 5
	}
	if c.LockDuration <= 0 {
		c.LockDuration = 15 * time.Minute
	}
	if c.LastUsedInterval == 0 {
		c.LastUsedInterval = time.Minute
	}
	if c.Hasher == nil {
		c.Hasher = authitcrypto.DefaultHasher()
	}
	if c.RateLimiter == nil {
		c.RateLimiter = ratelimit.Noop{}
	}
	if c.AuditLogger == nil {
		c.AuditLogger = audit.NoopLogger{}
	}
	return c
}

// Service implements PIN sign-in and device binding.
type Service struct {
	stores   Stores
	resolver LoginResolver
	audit    audit.Logger
	cfg      Config

	// dummyHash is verified against when there is no real hash to check,
	// so an unknown login costs what a wrong PIN does.
	dummyOnce sync.Once
	dummyHash string
}

// NewService constructs a Service. Every Stores field but Tx is required,
// and so is resolver.
func NewService(stores Stores, resolver LoginResolver, cfg Config) (*Service, error) {
	if stores.Users == nil || stores.PINs == nil || stores.Devices == nil || stores.Lockouts == nil {
		return nil, errors.New("authit/pin: Stores.Users, PINs, Devices and Lockouts are required")
	}
	if resolver == nil {
		return nil, errors.New("authit/pin: a LoginResolver is required")
	}
	cfg = cfg.withDefaults()
	return &Service{stores: stores, resolver: resolver, audit: cfg.AuditLogger, cfg: cfg}, nil
}
