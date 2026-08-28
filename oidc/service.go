package oidc

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// LinkingPolicy decides whether a social sign-in may attach itself to an
// authit account that already exists with the same email address.
//
// This is the security decision in social login, which is why it has a
// named type and a deliberately inconvenient default rather than a boolean
// buried in a config struct.
//
// The attack it governs: an attacker who can make a provider assert an
// email address they do not own — by registering it at a provider that
// never verifies addresses, or by changing their address at one that
// verified a different one — signs in, is silently linked to the victim's
// existing account, and is now the victim. Every "sign in with X" takeover
// works this way.
type LinkingPolicy int

const (
	// LinkingManual never links automatically. An unknown provider
	// identity whose email matches an existing account is refused with
	// ErrAccountNotLinked, and the user has to sign in by the means they
	// already have and link deliberately with Link.
	//
	// This is the zero value, and it is the only policy that is safe
	// regardless of which providers you enable and how much you trust
	// them. It costs one extra step the first time.
	LinkingManual LinkingPolicy = iota

	// LinkingVerifiedEmail links automatically when the provider claims to
	// have verified the address, and refuses otherwise.
	//
	// It is only as good as that claim. "Verified" means the provider
	// checked at some point, not that the address still belongs to this
	// person, and providers vary in how seriously they mean it — a
	// self-hosted or badly run one can assert whatever it likes. Use this
	// when you control the providers, or trust them the way you would
	// trust them to hold your users' sessions. Do not use it with a
	// provider users can register at freely.
	LinkingVerifiedEmail
)

// Stores are the ports the oidc package needs.
type Stores struct {
	Users    store.UserStore
	Accounts store.AccountStore
	// Tx is optional; see store.TxRunner. With it, creating a user and
	// linking their first provider account is atomic, so a crash between
	// the two cannot leave a user who exists and cannot sign in.
	Tx store.TxRunner
}

// Config tunes the oidc package.
type Config struct {
	// Linking decides whether an unknown identity may attach to an
	// existing account. Defaults to LinkingManual. Read LinkingPolicy.
	Linking LinkingPolicy
	// DisableSignUp refuses to create an account for an identity that
	// matches no existing user, for deployments where accounts are
	// provisioned some other way.
	DisableSignUp bool
	// ProviderTokenKey, when set, is a 32-byte AES-256-GCM key used to
	// encrypt the provider's own access and refresh tokens at rest, so
	// they can be used later to call the provider's API. Leave it nil and
	// the tokens are simply not kept, which is the right default: a
	// credential you do not store is one that cannot leak.
	ProviderTokenKey []byte
	// HTTPClient talks to the provider. Defaults to a client with a
	// 10-second timeout -- not http.DefaultClient, which has no timeout at
	// all and would let a hanging provider pin a request goroutine
	// indefinitely.
	HTTPClient *http.Client
	// AuditLogger receives sign-in, link and unlink events. Nil means
	// events are not recorded.
	AuditLogger audit.Logger
}

// DefaultHTTPTimeout bounds a call to a provider.
const DefaultHTTPTimeout = 10 * time.Second

// maxUserInfoBytes caps how much of a userinfo response is read. A provider
// is not hostile, but it is remote, and an unbounded read from a remote
// party is an unbounded allocation.
const maxUserInfoBytes = 1 << 20

func limitBody(resp *http.Response) io.Reader {
	return io.LimitReader(resp.Body, maxUserInfoBytes)
}

func (c Config) withDefaults() Config {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return c
}

// Service resolves external identities to authit users.
type Service struct {
	stores    Stores
	providers map[string]Provider
	audit     audit.Logger
	cfg       Config
}

// NewService constructs a Service over the given providers.
//
// Every provider is validated here rather than at the first sign-in: a
// missing client secret or a plain-HTTP endpoint should fail at startup,
// where somebody is watching.
func NewService(stores Stores, providers []Provider, cfg Config) (*Service, error) {
	if stores.Users == nil || stores.Accounts == nil {
		return nil, errors.New("authit/oidc: Stores.Users and Stores.Accounts are required")
	}
	if len(cfg.ProviderTokenKey) != 0 && len(cfg.ProviderTokenKey) != 32 {
		return nil, errors.New("authit/oidc: ProviderTokenKey must be exactly 32 bytes")
	}
	byID := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if err := p.validate(); err != nil {
			return nil, err
		}
		if _, dup := byID[p.ID]; dup {
			return nil, errors.New("authit/oidc: duplicate provider ID " + p.ID)
		}
		byID[p.ID] = p
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, providers: byID, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}

// Provider returns the registered provider with the given id.
func (s *Service) Provider(id string) (Provider, error) {
	p, ok := s.providers[id]
	if !ok {
		return Provider{}, ErrUnknownProvider
	}
	return p, nil
}
