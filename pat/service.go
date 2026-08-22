// Package pat implements personal access tokens: long-lived, named, scoped
// bearer credentials a user creates for themselves (a CLI, a script, an
// integration) outside of an interactive login. It has no notion of HTTP —
// a host application resolves an incoming bearer header via Resolve and
// decides what to do with the result.
package pat

import (
	"errors"
	"time"

	"github.com/jryannel/sqlb"
)

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
	db  *sqlb.DB
	cfg Config
}

// NewService constructs a Service over db, which must be backed by a database
// carrying authit's tables — see authitschema.Declare.
//
// db is *sqlb.DB rather than the narrower sqlb.Executor because operations
// that write more than one row need a transaction, and WithTx joins an outer
// one rather than nesting — so a caller that already has a transaction open
// passes its tx-scoped *sqlb.DB and authit's writes land inside it.
func NewService(db *sqlb.DB, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("authit/pat: db is required")
	}
	return &Service{db: db, cfg: cfg.withDefaults()}, nil
}
