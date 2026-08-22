// Package authittest is authit's own test harness: a real Postgres, a fresh
// database per test, and authit's declared schema applied to it.
//
// # Why there is no in-memory fake here
//
// authit used to ship memstore, a hand-written in-memory implementation of
// every storage port, and its test suite ran against that. It was fast and it
// needed nothing installed, and it was also the reason the suite could not
// speak to the things authit most needs to be right about: counting failed
// logins over a time window, expiring a token, a unique index refusing a second
// signup on one address under contention, an ON DELETE actually cascading. A
// fake's behaviour drifts from Postgres exactly where the questions get
// interesting, and a suite that passes without a database is not evidence that
// the code works against one.
//
// # Why it fails rather than skips
//
// A missing DSN is a hard failure, not a t.Skip. "No database, so everything
// passed" is the same problem wearing a different hat: it turns a gate into a
// decoration, silently, on precisely the machine where nobody is looking.
//
// # Why not testcontainers
//
// Provisioning is the caller's job. testcontainers brings docker/docker and
// the modules behind it into the test dependency set, and its reaper reaps by
// label — which can and has removed long-lived containers belonging to someone
// else. A DSN has neither problem. See the repository README for a one-line
// docker command, and compose.yaml for the same thing declared.
package authittest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jryannel/authit/authitschema"
	"github.com/jryannel/sqlb"
	"github.com/jryannel/sqlb/migrate"
	"github.com/jryannel/sqlb/schema"
)

// DSNEnv names the Postgres these tests run against.
const DSNEnv = "AUTHIT_TEST_POSTGRES"

var (
	adminOnce sync.Once
	adminPool *pgxpool.Pool
	adminErr  error
	renderDSN func(database string) string
)

// admin opens (once) the connection to the server's maintenance database.
// Tests never use it directly; FreshDB creates a database of its own through
// it, which is far cheaper than a server each and keeps tests independent.
func admin(t testing.TB) (*pgxpool.Pool, func(string) string) {
	t.Helper()
	adminOnce.Do(func() {
		dsn := os.Getenv(DSNEnv)
		if dsn == "" {
			adminErr = fmt.Errorf(
				"%s is not set.\n\nauthit's tests need a real Postgres; there is no in-memory mode.\nStart one with:\n\n    docker run -d --name authit-test -e POSTGRES_PASSWORD=authit -p 5433:5432 postgres:16-alpine\n    export %s=postgres://postgres:authit@127.0.0.1:5433/postgres\n",
				DSNEnv, DSNEnv)
			return
		}
		if renderDSN, adminErr = dsnRenderer(dsn); adminErr != nil {
			return
		}
		adminPool, adminErr = pgxpool.New(context.Background(), renderDSN("postgres"))
		if adminErr != nil {
			adminErr = fmt.Errorf("opening the admin connection: %w", adminErr)
			return
		}
		if err := adminPool.Ping(context.Background()); err != nil {
			adminErr = fmt.Errorf("%s is set but nothing answered: %w", DSNEnv, err)
		}
	})
	if adminErr != nil {
		t.Fatalf("authittest: %v", adminErr)
	}
	return adminPool, renderDSN
}

// dsnRenderer turns one DSN into a function that renders the same server with
// a different database name, so each test can have its own.
func dsnRenderer(dsn string) (func(string) string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", DSNEnv, err)
	}
	return func(database string) string {
		withDB := *u
		withDB.Path = "/" + database
		return withDB.String()
	}, nil
}

// FreshDB returns a *sqlb.DB over a database of this test's own, with authit's
// declared schema already applied. The database is dropped when the test ends.
func FreshDB(t testing.TB) *sqlb.DB {
	t.Helper()
	return FreshDBWith(t, authitschema.Registry())
}

// FreshDBWith is FreshDB over an arbitrary registry — for the tests that
// compose authit's tables with a host's and need both created together, which
// is the arrangement Declare exists to support.
func FreshDBWith(t testing.TB, reg *schema.Registry) *sqlb.DB {
	t.Helper()
	pool, dsn := admin(t)
	ctx := context.Background()

	name := databaseName(t)
	// Dropped first so a crashed run leaves nothing that makes the next one
	// fail with a confusing "already exists" instead of its real problem.
	mustExec(t, pool, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	mustExec(t, pool, `CREATE DATABASE `+quoteIdent(name))

	testPool, err := pgxpool.New(ctx, dsn(name))
	if err != nil {
		t.Fatalf("authittest: opening %s: %v", name, err)
	}
	t.Cleanup(func() {
		testPool.Close()
		// A dropped database cannot have open connections, and a pool holds
		// them, so closing above is not always enough on its own.
		_, _ = pool.Exec(context.Background(),
			`DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})

	applySchema(t, testPool, reg)
	return sqlb.New(testPool)
}

// applySchema diffs authit's declaration against an empty database and runs
// the result. This is the same path a host's migration generation takes, so a
// declaration that cannot be turned into DDL fails here rather than in a
// consumer's first migration.
func applySchema(t testing.TB, pool *pgxpool.Pool, reg *schema.Registry) {
	t.Helper()
	changes, err := migrate.Diff(schema.NewRegistry(), reg)
	if err != nil {
		t.Fatalf("authittest: diffing authit's schema: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("authittest: creating authit's schema from nothing produced no statements")
	}
	for i, c := range changes {
		if strings.TrimSpace(c.Up) == "" {
			continue
		}
		if _, err := pool.Exec(context.Background(), c.Up); err != nil {
			t.Fatalf("authittest: statement %d of %d failed: %v\n%s\n\n(comment: %s)",
				i+1, len(changes), err, strings.TrimSpace(c.Up), c.Comment)
		}
	}
}

// databaseName derives a legal, unique-per-test database name from the test's
// own name, so a failure names the test that left the database behind.
func databaseName(t testing.TB) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, t.Name())
	const prefix = "authit_test_"
	// Postgres truncates identifiers at 63 bytes, and a truncated name can
	// collide with another test's.
	if max := 63 - len(prefix); len(name) > max {
		name = name[:max]
	}
	return prefix + name
}

func mustExec(t testing.TB, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("authittest: %s: %v", sql, err)
	}
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
