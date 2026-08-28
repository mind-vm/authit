// Package sqlbstore is a generic bridge between authit's DB-agnostic
// store interfaces and sqlb-generated row types. It is its own Go module
// (separate go.mod, requiring both authit and sqlb) so that authit's root
// module never gains an sqlb/pgx dependency — the same reason sqlb itself
// keeps its own auth-provider adapters under example/ rather than in its
// core module.
//
// Table[R, T] is the shared primitive: given a two-way conversion between
// an app's row type R (e.g. a sqlb-generated struct like mybrain.APIToken)
// and authit's canonical type T (e.g. store.PersonalAccessToken), plus a
// small amount of column-name config, it implements the CRUD mechanics
// every authit store interface needs — so a concrete per-interface adapter
// (see pat.go for PersonalAccessTokenAdapter) only has to supply that
// conversion and config, not hand-write Create/Get/List/Update against
// sqlb's query builder.
//
// Create goes through sqlb's InsertRows; Update goes through raw
// UpdateRows(...).Set(...) rather than an upsert — see ToUpdateColumns for
// why they can't share one code path despite both starting from the same
// T.
//
// # Running the tests
//
// Every test in this package needs a real Postgres and skips without one,
// so a bare `go test ./...` here is green whether or not the adapters
// work. Point MYBRAIN_DATABASE_URL at any reachable Postgres to actually
// run them:
//
//	MYBRAIN_DATABASE_URL=postgres://user:pass@localhost:5432/db go test ./... -race
//
// The name is historical; this package has no relation to mybrain's
// schema and any database will do. The tests are self-contained: the
// conformance and flow tests create, use and drop an isolated
// authit_reference_schema_test schema, and the per-adapter tests create
// and drop their own sqlbstore_test_* tables. Nothing else in the target
// database is touched, but prefer a scratch database anyway.
//
// Do not treat a skipped run as a passing one. Both bugs the first live
// run found were invisible to the in-memory suite — see the T1.6 section
// of docs/comparison.md.
package sqlbstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// Table binds authit's canonical type T to an app's sqlb row type R.
type Table[R, T any] struct {
	// ToRow converts a fully-populated T into the row to insert, EXCEPT the
	// primary key — Create handles that separately via SetID, so ToRow's
	// own handling of R's ID field is irrelevant and can be left however's
	// convenient. Used only by Create; Update uses ToUpdateColumns
	// instead (see there for why they aren't the same function).
	ToRow func(T) R
	// FromRow converts a row read back from the database into T. Called
	// after every Create/Update/Get/List, so DB-generated values (a
	// defaulted ID, created_at) make it into the value the caller
	// receives even though ToRow never sent them.
	FromRow func(R) T
	// GetID extracts T's primary key.
	GetID func(T) string
	// SetID returns a copy of row with its primary key column set to id.
	// Create calls this with "" (so a defaulted column, e.g. a generated
	// UUIDv7, is left to the database rather than whatever the row
	// happened to hold), then inserts — sqlb's InsertRows only writes an
	// explicit value for a database-defaulted column when the Go field is
	// non-zero, so leaving ID at its zero value here is what makes the
	// database generate one.
	SetID func(R, string) R
	// IDColumn is the row's primary key column name — used by GetByID and
	// as Update's WHERE clause.
	IDColumn string
	// ToUpdateColumns extracts exactly the (column name, value) pairs
	// Update should write, as explicit bound parameters via
	// UpdateRows(...).Set(...) — deliberately NOT built from ToRow's
	// output. ToRow feeds Create's InsertRows, which treats a Go zero
	// value on a database-defaulted column as "leave this to the
	// database" (so a fresh row's ID/created_at defer to their defaults,
	// as intended) — but Update has no such thing as "leave it unset": v
	// is always an already-fetched, already-mutated value, so a field
	// that's genuinely false/0/"" must be written as exactly that. Reusing
	// ToRow for Update silently reverts any explicitly-zero,
	// database-defaulted column (e.g. an `is_active boolean DEFAULT true`
	// column being set to false) back to its default, with no error —
	// caught by this package's own test suite before it shipped.
	ToUpdateColumns func(T) map[string]any
}

// Create inserts v and returns what was actually persisted (DB defaults
// included).
func (t Table[R, T]) Create(ctx context.Context, db sqlb.Executor, v T) (T, error) {
	row := t.SetID(t.ToRow(v), "")
	rows, err := sqlb.InsertRows(&row).Exec(ctx, db)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("sqlbstore: creating: %w", err)
	}
	return t.FromRow(rows[0]), nil
}

// Update writes exactly ToUpdateColumns(v) to the row identified by
// GetID(v).
func (t Table[R, T]) Update(ctx context.Context, db sqlb.Executor, v T) error {
	stmt := sqlb.UpdateRows[R]().Where(sqlb.F(t.IDColumn).Eq(t.GetID(v)))
	for column, value := range t.ToUpdateColumns(v) {
		stmt = stmt.Set(column, value)
	}
	if _, err := stmt.Exec(ctx, db); err != nil {
		return fmt.Errorf("sqlbstore: updating: %w", err)
	}
	return nil
}

// GetBy returns the row where column equals value, or store.ErrNotFound.
// Sugar for the common single-column case of GetWhere.
func (t Table[R, T]) GetBy(ctx context.Context, db sqlb.Executor, column string, value any) (T, error) {
	return t.GetWhere(ctx, db, sqlb.F(column).Eq(value))
}

// ListBy returns every row where column equals value. Sugar for the
// common single-column case of ListWhere.
func (t Table[R, T]) ListBy(ctx context.Context, db sqlb.Executor, column string, value any) ([]T, error) {
	return t.ListWhere(ctx, db, sqlb.F(column).Eq(value))
}

// GetWhere returns the row matching every pred (AND'd together), or
// store.ErrNotFound — for lookups GetBy's single-column shape can't
// express, e.g. a compound key (user_id = ? AND team_id = ?).
func (t Table[R, T]) GetWhere(ctx context.Context, db sqlb.Executor, preds ...sqlb.Pred) (T, error) {
	row, err := sqlb.Query[R]().Where(preds...).One(ctx, db)
	switch {
	case errors.Is(err, sqlb.ErrNotFound):
		var zero T
		return zero, store.ErrNotFound
	case err != nil:
		var zero T
		return zero, fmt.Errorf("sqlbstore: getting: %w", err)
	}
	return t.FromRow(row), nil
}

// ListWhere returns every row matching every pred (AND'd together).
func (t Table[R, T]) ListWhere(ctx context.Context, db sqlb.Executor, preds ...sqlb.Pred) ([]T, error) {
	rows, err := sqlb.Query[R]().Where(preds...).All(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("sqlbstore: listing: %w", err)
	}
	out := make([]T, len(rows))
	for i, row := range rows {
		out[i] = t.FromRow(row)
	}
	return out, nil
}

// CountWhere counts rows matching every pred (AND'd together).
func (t Table[R, T]) CountWhere(ctx context.Context, db sqlb.Executor, preds ...sqlb.Pred) (int64, error) {
	n, err := sqlb.Query[R]().Where(preds...).Count(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("sqlbstore: counting: %w", err)
	}
	return n, nil
}

// ExistsWhere reports whether any row matches every pred (AND'd
// together).
func (t Table[R, T]) ExistsWhere(ctx context.Context, db sqlb.Executor, preds ...sqlb.Pred) (bool, error) {
	ok, err := sqlb.Query[R]().Where(preds...).Exists(ctx, db)
	if err != nil {
		return false, fmt.Errorf("sqlbstore: checking existence: %w", err)
	}
	return ok, nil
}

// Delete removes the row identified by id (IDColumn). Idempotent: deleting
// an already-gone row is not an error.
func (t Table[R, T]) Delete(ctx context.Context, db sqlb.Executor, id string) error {
	_, err := t.DeleteWhere(ctx, db, sqlb.F(t.IDColumn).Eq(id))
	return err
}

// DeleteWhere removes every row matching every pred (AND'd together).
// Idempotent: matching zero rows is not an error — a caller wanting "was
// anything actually deleted" should check the returned count.
func (t Table[R, T]) DeleteWhere(ctx context.Context, db sqlb.Executor, preds ...sqlb.Pred) (int64, error) {
	n, err := sqlb.DeleteRows[R]().Where(preds...).Exec(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("sqlbstore: deleting: %w", err)
	}
	return n, nil
}

// SetColumnWhere writes value to column on every row matching every pred
// (AND'd together) — for a bulk state change across many rows at once
// (e.g. "revoke every refresh token for this user") that isn't shaped like
// Update's "one row, identified by ID." Same explicit-bound-parameter
// mechanism as Update, so it has no zero-value trap either.
func (t Table[R, T]) SetColumnWhere(ctx context.Context, db sqlb.Executor, column string, value any, preds ...sqlb.Pred) error {
	if _, err := sqlb.UpdateRows[R]().Set(column, value).Where(preds...).Exec(ctx, db); err != nil {
		return fmt.Errorf("sqlbstore: bulk-updating %s: %w", column, err)
	}
	return nil
}
