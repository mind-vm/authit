package sqlbstore_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jryannel/sqlb"
)

// testPool connects to MYBRAIN_DATABASE_URL (any reachable Postgres
// works; this package has no relation to mybrain's schema). Skips if no
// DSN is configured, so this suite doesn't fail CI environments with no
// Postgres available.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MYBRAIN_DATABASE_URL")
	if dsn == "" {
		t.Skip("MYBRAIN_DATABASE_URL not set; skipping sqlbstore integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// applyDDL runs ddl (expected to create one or more tables), registers
// cleanup to drop every name in tables, and returns an sqlb.Executor over
// pool.
func applyDDL(t *testing.T, pool *pgxpool.Pool, ddl string, tables ...string) sqlb.Executor {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("applying test DDL: %v", err)
	}
	t.Cleanup(func() {
		for _, name := range tables {
			_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+name)
		}
	})
	for _, name := range tables {
		if _, err := pool.Exec(ctx, `TRUNCATE `+name); err != nil {
			t.Fatalf("truncating %s: %v", name, err)
		}
	}
	return sqlb.New(pool)
}
