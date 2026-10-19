// Package pgtest gives a test its own migrated Postgres database.
//
// Each call creates a database on the server PGTEST_DSN points at, runs the
// app's migrations into it, and drops it when the test ends. Tests fail
// rather than skip when the server is unreachable, because a skipped suite
// reads as a green run; -short is the one way to opt out.
package pgtest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DSNEnv names the admin connection: any database on the server, as a role
// that may CREATE DATABASE.
const DSNEnv = "PGTEST_DSN"

const defaultDSN = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

var counter atomic.Int64

// Pool returns a pool on a fresh database with migrate applied to it. The
// app passes its own migrations.Apply, so whatever the binary does at
// `migrate` is what a test database gets.
func Pool(t *testing.T, migrate func(context.Context, *pgxpool.Pool) error) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("pgtest: needs Postgres; skipped under -short")
	}
	ctx := context.Background()

	adminDSN := os.Getenv(DSNEnv)
	if adminDSN == "" {
		adminDSN = defaultDSN
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("pgtest: connecting to %s (set %s): %v", adminDSN, DSNEnv, err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	name := fmt.Sprintf("t_%d_%d", os.Getpid(), counter.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("pgtest: creating %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			"DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})

	cfg, err := pgxpool.ParseConfig(withDatabase(adminDSN, name))
	if err != nil {
		t.Fatalf("pgtest: parsing DSN: %v", err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgtest: connecting to %s: %v", name, err)
	}
	t.Cleanup(pool.Close)

	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("pgtest: migrating %s: %v", name, err)
	}
	return pool
}

// withDatabase swaps the database name in a URL-form DSN.
func withDatabase(dsn, name string) string {
	q := ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		dsn, q = dsn[:i], dsn[i:]
	}
	i := strings.LastIndex(dsn, "/")
	return dsn[:i+1] + name + q
}
