// Package pat implements personal access tokens: long-lived, named, scoped
// bearer credentials a user creates for themselves (a CLI, a script, an
// integration) outside of an interactive login. It has no notion of HTTP —
// a host application resolves an incoming bearer header via Resolve and
// decides what to do with the result.
package pat

import (
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the pat package needs.
type Stores struct {
	Tokens store.PersonalAccessTokenStore
}

// Config tunes the pat package's behavior.
type Config struct {
	// Prefix is prepended to every generated token, e.g. "ghp_" or "mb_",
	// so a token is recognizable at a glance (in a shell history, a leaked
	// log line, a secret scanner's rule). Defaults to "authit_".
	Prefix string
	// MaxExpiry, if set, caps how far in the future CreateToken will allow
	// ExpiresAt to be. nil means no cap.
	MaxExpiry *time.Duration
	// RequireExpiry, if true, makes CreateToken reject a nil expiresAt.
	// Off by default; GitHub and GitLab have both moved toward mandatory
	// expiry over time, so a host application that wants that stance can
	// opt in here rather than authit assuming it.
	RequireExpiry bool
	// AuditLogger receives security-relevant events (token creation,
	// revocation). Nil means events are not recorded — see package audit.
	AuditLogger audit.Logger
}

func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = "authit_"
	}
	return c
}

// Service implements personal-access-token issuance, resolution, and
// revocation.
type Service struct {
	stores Stores
	audit  audit.Logger
	cfg    Config
}

// NewService constructs a Service. Config.AuditLogger may be nil, in which
// case audit.NoopLogger is used.
func NewService(stores Stores, cfg Config) (*Service, error) {
	if stores.Tokens == nil {
		return nil, errors.New("authit/pat: Stores.Tokens is required")
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}
