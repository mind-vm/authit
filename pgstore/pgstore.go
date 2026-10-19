// Package pgstore implements auth's store ports on Postgres through sqlc:
// the user plane (users, sessions, reset and verification tokens, TOTP,
// lockout, linked accounts, passkeys and email login), the team plane
// (teams, members and invitations), personal access tokens, RFC 8628 device
// authorizations and the operator plane.
//
// Its tables live in the auth schema and migrate with their own goose
// version table, so an app runs Migrate beside its own migrations and
// neither sees the other's history.
package pgstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// VersionTable is goose's bookkeeping for the auth schema, kept apart from
// the app's own goose_db_version.
const VersionTable = "auth.goose_db_version"

// Migrate brings the auth schema to the current version.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	// goose creates its version table before the first migration runs, so
	// the schema that table lives in has to exist first.
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth"); err != nil {
		return fmt.Errorf("pgstore: creating schema: %w", err)
	}
	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("pgstore: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations,
		goose.WithTableName(VersionTable))
	if err != nil {
		return fmt.Errorf("pgstore: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("pgstore: %w", err)
	}
	return nil
}

// Store implements every port above and store.TxRunner over one pool.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a Store over pool. The schema must already be migrated.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

var (
	_ store.UserStore               = (*Store)(nil)
	_ store.RefreshTokenStore       = (*Store)(nil)
	_ store.PasswordResetStore      = (*Store)(nil)
	_ store.EmailVerificationStore  = (*Store)(nil)
	_ store.TOTPStore               = (*Store)(nil)
	_ store.PendingTwoFactorStore   = (*Store)(nil)
	_ store.LockoutStore            = (*Store)(nil)
	_ store.AccountStore            = (*Store)(nil)
	_ store.WebAuthnCredentialStore = (*Store)(nil)
	_ store.WebAuthnChallengeStore  = (*Store)(nil)
	_ store.EmailLoginStore         = (*Store)(nil)
	_ store.TxRunner                = (*Store)(nil)
)

type txKey struct{}

// RunInTx runs fn in one transaction. store.TxRunner requires every store
// call made with fn's context to join it, so q reads the transaction back
// out of the context; a call inside an open transaction joins that one.
func (s *Store) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}

// q returns queries bound to the context's transaction, or to the pool.
func (s *Store) q(ctx context.Context) *db.Queries {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return db.New(tx)
	}
	return db.New(s.pool)
}

// mapErr translates driver errors into the sentinels every auth service
// branches on: a missing row is store.ErrNotFound and a unique violation is
// store.ErrConflict, never pgx's own.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", store.ErrConflict, pgErr.ConstraintName)
	}
	return fmt.Errorf("pgstore: %w", err)
}

// affected reports a write that matched no row as store.ErrNotFound.
func affected(n int64, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// isID reports whether id can name a row. Ids are uuid columns, and a
// string that is not one names nothing rather than failing to encode.
func isID(id string) bool {
	return uuid.Validate(id) == nil
}
