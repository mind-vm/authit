// Package user implements user registration, authentication, session
// management, password reset, email verification, and TOTP-based
// two-factor auth.
//
// It stores what it needs in authit's own tables (see authitschema) rather
// than behind storage-port interfaces a host implements. What that buys is in
// authitschema's package doc; the practical consequence here is that
// NewService takes a database instead of seven ports, and none of these flows
// can be half-configured.
package user

import (
	"errors"

	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/sqlb"
)

// Service implements user auth flows.
type Service struct {
	db      *sqlb.DB
	signer  authitjwt.Signer
	emailer EmailSender
	cfg     Config
}

// NewService constructs a Service over db, which must be backed by a database
// carrying authit's tables — see authitschema.Declare.
//
// db is *sqlb.DB rather than the narrower sqlb.Executor because several flows
// write more than one row and must do so atomically: rotating a refresh token
// revokes one and issues another, and resetting a password consumes a token,
// rewrites the hash and revokes every session. WithTx joins an outer
// transaction rather than nesting, so a caller that already has one open
// passes its tx-scoped *sqlb.DB and authit's writes land inside it.
//
// emailer may be nil, in which case NoopEmailSender is used (useful for tests
// or apps that deliver links out of band).
func NewService(db *sqlb.DB, signer authitjwt.Signer, emailer EmailSender, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("authit/user: db is required")
	}
	if signer == nil {
		return nil, errors.New("authit/user: signer is required")
	}
	if emailer == nil {
		emailer = NoopEmailSender{}
	}
	return &Service{db: db, signer: signer, emailer: emailer, cfg: cfg.withDefaults()}, nil
}
