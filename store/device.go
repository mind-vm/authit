package store

import (
	"context"
	"time"
)

// DeviceAuthorizationStatus is the lifecycle state of a DeviceAuthorization.
type DeviceAuthorizationStatus string

const (
	DeviceAuthorizationPending  DeviceAuthorizationStatus = "pending"
	DeviceAuthorizationApproved DeviceAuthorizationStatus = "approved"
	DeviceAuthorizationDenied   DeviceAuthorizationStatus = "denied"
)

// DeviceAuthorization is one in-flight RFC 8628 device-authorization-grant
// request. UserCode is stored as plaintext (not hashed): it is short and
// low-entropy by design — the security property comes from rate-limiting
// guesses at the approval endpoint (the host application's job), not from
// the code being a secret. DeviceCode, by contrast, IS a secret (the CLI's
// poll credential) and only its hash is persisted.
type DeviceAuthorization struct {
	ID              string
	DeviceCodeHash  string
	UserCode        string
	ClientID        string
	Scope           string
	Status          DeviceAuthorizationStatus
	UserID          *string // set once Status is Approved
	ExpiresAt       time.Time
	IntervalSeconds int
	LastPolledAt    *time.Time
	CreatedAt       time.Time
}

// DeviceAuthorizationStore persists DeviceAuthorization records.
type DeviceAuthorizationStore interface {
	CreateDeviceAuthorization(ctx context.Context, d *DeviceAuthorization) error
	GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (*DeviceAuthorization, error)
	GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*DeviceAuthorization, error)
	UpdateDeviceAuthorization(ctx context.Context, d *DeviceAuthorization) error
	DeleteDeviceAuthorization(ctx context.Context, id string) error
}
