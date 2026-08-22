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

	"github.com/jryannel/sqlb"
)

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
	db  *sqlb.DB
	cfg Config
}

// NewService constructs a Service over db, which must be backed by a database
// carrying authit's tables — see authitschema.Declare.
func NewService(db *sqlb.DB, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("authit/device: db is required")
	}
	return &Service{db: db, cfg: cfg.withDefaults()}, nil
}
