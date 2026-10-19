package store

import (
	"context"
	"time"
)

// PINCredential is a user's short numeric PIN, for the pin package's
// sign-in on a field device. Only its hash is stored, in the same
// self-describing formats as a password hash (PHC argon2id, or $2 bcrypt
// for a PIN imported from elsewhere).
//
// A PIN is low-entropy by design: six digits are a million guesses, which
// no hash makes expensive enough to survive an offline attack on a leaked
// table. What protects it is the online limit on wrong guesses, kept in the
// LockoutStore under a key of the pin package's own, so the lock state has
// no column here.
type PINCredential struct {
	UserID    string
	PINHash   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PINStore persists one PINCredential per user.
type PINStore interface {
	// SetPINCredential creates the user's PIN, or replaces the one they
	// have. UserID must be UNIQUE: a user has one PIN.
	SetPINCredential(ctx context.Context, c *PINCredential) error
	GetPINCredential(ctx context.Context, userID string) (*PINCredential, error)
	// DeletePINCredential is idempotent: deleting a PIN that is not there
	// is not an error.
	DeletePINCredential(ctx context.Context, userID string) error
}

// BoundDevice is a device a user has signed in on, holding a long-lived
// bearer token for it: the field phone that stays signed in through days
// without a connection. Only the token's hash is stored, hex(SHA-256(raw)),
// which is crypto.HashToken -- and also the format apps that rolled their
// own device tokens commonly used, so such rows import unchanged.
//
// It is a separate thing from DeviceAuthorization, which is one RFC 8628
// grant in flight for a CLI. Nothing here says how the device was bound;
// the pin package binds by PIN today, and another method could bind the
// same rows.
type BoundDevice struct {
	ID        string
	UserID    string
	Name      string
	TokenHash string
	UserAgent string
	IPAddress string
	// ExpiresAt is nil for a device that stays signed in until revoked,
	// which is the pin package's default.
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// BoundDeviceStore persists BoundDevice records.
type BoundDeviceStore interface {
	CreateBoundDevice(ctx context.Context, d *BoundDevice) error
	GetBoundDevice(ctx context.Context, id string) (*BoundDevice, error)
	// GetBoundDeviceByTokenHash returns revoked and expired devices too:
	// the service reads both columns itself. token_hash must be UNIQUE.
	GetBoundDeviceByTokenHash(ctx context.Context, hash string) (*BoundDevice, error)
	// ListBoundDevicesByUser lists every device of one user, revoked ones
	// included, oldest first.
	ListBoundDevicesByUser(ctx context.Context, userID string) ([]*BoundDevice, error)
	// TouchBoundDevice records a use at at, and reports ErrNotFound for a
	// device that is gone or revoked, so a use racing a revocation cannot
	// write over it.
	TouchBoundDevice(ctx context.Context, id string, at time.Time) error
	// RevokeBoundDevice revokes the device at at. Revoking a revoked device
	// keeps the first instant and is not an error; a missing one is
	// ErrNotFound.
	RevokeBoundDevice(ctx context.Context, id string, at time.Time) error
	// RevokeAllBoundDevices revokes every live device of userID and reports
	// how many it revoked.
	RevokeAllBoundDevices(ctx context.Context, userID string, at time.Time) (int, error)
}
