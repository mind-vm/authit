package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/sqlbstore/refschema"
	"github.com/mind-vm/authit/superuser"
	"github.com/mind-vm/sqlb"
	"golang.org/x/term"
)

func superuserCreate(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("superuser create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dsn := fs.String("dsn", os.Getenv("AUTHIT_DSN"), "Postgres connection string (or AUTHIT_DSN)")
	email := fs.String("email", "", "operator's email address")
	displayName := fs.String("display-name", "", "operator's display name")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	switch {
	case *dsn == "":
		return usagef("superuser create: --dsn is required (or set AUTHIT_DSN)")
	case *email == "":
		return usagef("superuser create: --email is required")
	case fs.NArg() > 0:
		return usagef("superuser create: unexpected argument %q", fs.Arg(0))
	}

	password, err := readPassword()
	if err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connecting: %w", err)
	}

	svc, err := newSuperuserService(sqlb.New(pool))
	if err != nil {
		return err
	}

	// Bootstrap for the first operator, CreateSuperuser for any later one.
	// The difference is not cosmetic: Bootstrap refuses once any operator
	// exists, and CreateSuperuser records who did the creating. A CLI has
	// no authenticated creator to record, so it can only make the first.
	su, err := svc.Bootstrap(ctx, *email, password, *displayName)
	switch {
	case errors.Is(err, superuser.ErrAlreadyBootstrapped):
		return errors.New("an operator already exists; create further ones through your " +
			"application's own operator surface, which can record who created them")
	case err != nil:
		return err
	}
	fmt.Fprintf(stdout, "created operator %s <%s>\n", su.ID, su.Email)
	return nil
}

// newSuperuserService builds the service over the reference schema.
//
// The password is hashed by the same Config.PasswordHasher the application
// will verify it with, and validated by the same policy, rather than by an
// INSERT that happens to agree today. That is the whole reason this goes
// through the service instead of writing the row directly.
func newSuperuserService(db sqlb.Executor) (*superuser.Service, error) {
	// superuser.NewService requires a signer because it can mint login
	// tokens. This command never does, so the key is random, never
	// persisted, and discarded when the process exits -- nothing it
	// produces is verifiable by anything, which is correct, because it
	// produces nothing.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	signer, err := authitjwt.NewHMACSigner(key, authitjwt.Defaults{Issuer: "authitctl"})
	if err != nil {
		return nil, err
	}
	return superuser.NewService(refschema.SuperuserStores(db), signer, superuser.Config{})
}

// readPassword reads from the terminal, never from a flag.
//
// A password in argv is in the process list while it runs and in the shell
// history afterwards, which is the sharp edge this command exists to
// remove -- putting it back as a flag would be worse than the psql heredoc
// it replaces.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal: this command reads the password " +
			"interactively, and will not take it from a flag or a pipe")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords did not match")
	}
	if strings.TrimSpace(string(first)) == "" {
		return "", errors.New("password is empty")
	}
	return string(first), nil
}
