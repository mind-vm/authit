// Package device implements RFC 8628's OAuth 2.0 Device Authorization
// Grant: the "visit this URL and enter this code" flow used by headless or
// browser-less CLIs (no local browser or listening port assumed — see
// https://datatracker.ietf.org/doc/html/rfc8628).
//
// This package deliberately does not mint a credential itself. A
// successful PollDeviceToken tells the caller which user approved the
// request; the host application decides what to hand the CLI in
// response — a authit/user session, a authit/pat token, or its own
// credential shape. This keeps device flow reusable regardless of what
// kind of token a given host application issues.
//
// Rate-limiting guesses against the (short, low-entropy-by-design)
// user_code at the approval endpoint is the host application's
// responsibility (RFC 8628 §5.2) — typically ordinary HTTP-layer
// rate-limiting middleware in front of ApproveDeviceAuthorization/
// DenyDeviceAuthorization.
package device

import (
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the device package needs.
type Stores struct {
	Authorizations store.DeviceAuthorizationStore
}

// Config tunes the device package's flows.
type Config struct {
	// DeviceCodeTTL is how long a device authorization request stays valid
	// before the user must restart it. Defaults to 15 minutes (matches
	// GitHub's device flow).
	DeviceCodeTTL time.Duration
	// PollInterval is the minimum gap the CLI is told to leave between
	// polls. Defaults to 5 seconds.
	PollInterval time.Duration
	// SlowDownIncrement is added to a device authorization's effective
	// interval, permanently, the first time the CLI is caught polling
	// faster than instructed. Defaults to 5 seconds, per RFC 8628 §3.5.
	SlowDownIncrement time.Duration
	// AuditLogger receives security-relevant events (approval, denial).
	// Nil means events are not recorded — see package audit.
	AuditLogger audit.Logger
	// RateLimiter bounds guessing at user codes. Nil means ratelimit.Noop.
	//
	// Setting this is not optional in the way the other nil-safe fields
	// are. A user code carries about 34.5 bits (crypto.GenerateUserCode),
	// which is deliberately low so a human can read it off one screen and
	// type it into another — RFC 8628 §5.2 is explicit that the security
	// of that choice rests on rate-limiting guesses at the verification
	// endpoint. With no limiter, an attacker who can call
	// ApproveDeviceAuthorization or DenyDeviceAuthorization in a loop can
	// search for a pending code.
	//
	// Keys:
	//
	//	device:approve:<caller user id>  per authenticated caller
	//	device:user-code:failures        global, charged on a failed lookup
	//
	// The global key is charged only when a lookup FAILS, so ordinary use
	// never consumes it and an enumeration sweep exhausts it almost
	// immediately. The trade is real and worth stating: an attacker who
	// burns that budget also stops legitimate users from entering a code
	// until it refills. Size Burst for your traffic — a nuisance outage on
	// one flow is the better end of this trade against an exhaustible
	// 34.5-bit space, but it is a trade.
	RateLimiter ratelimit.Limiter
}

func (c Config) withDefaults() Config {
	if c.DeviceCodeTTL <= 0 {
		c.DeviceCodeTTL = 15 * time.Minute
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.SlowDownIncrement <= 0 {
		c.SlowDownIncrement = 5 * time.Second
	}
	if c.RateLimiter == nil {
		c.RateLimiter = ratelimit.Noop{}
	}
	return c
}

// Authorization is what StartDeviceAuthorization hands back to the CLI.
// Building the full verification_uri / verification_uri_complete is left
// to the host application, which is the only party that knows its own
// domain and routing.
type Authorization struct {
	DeviceCode string
	UserCode   string
	ExpiresIn  time.Duration
	Interval   time.Duration
}

// Service implements the device-authorization-grant flow.
type Service struct {
	stores Stores
	audit  audit.Logger
	cfg    Config
}

// NewService constructs a Service. Config.AuditLogger may be nil, in which
// case audit.NoopLogger is used.
func NewService(stores Stores, cfg Config) (*Service, error) {
	if stores.Authorizations == nil {
		return nil, errors.New("authit/device: Stores.Authorizations is required")
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}
