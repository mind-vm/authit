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
// Create and Update both go through sqlb's InsertRows(...).OnConflictUpdate,
// using the exact same ToRow conversion: Update is only ever called on an
// already-fetched, already-persisted value (every authit service follows a
// fetch-mutate-write pattern), so "insert, or update on conflict" is
// exactly the semantics wanted — no separate field-by-field Set() calls,
// and no risk of a stringly-typed column name drifting out of sync with a
// renamed struct field, since ToRow/FromRow are ordinary typed Go code.
package sqlbstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// Table binds authit's canonical type T to an app's sqlb row type R.
type Table[R, T any] struct {
	// ToRow converts a fully-populated T into the row to insert/upsert,
	// EXCEPT the primary key — Table handles that separately via
	// GetID/SetID (see Create/Update), so ToRow's own handling of R's ID
	// field is irrelevant and can be left however's convenient.
	//
	// A field present in T but missing from ToRow's output is NOT an
	// error at Create (the column just gets R's zero value, same as any
	// other field ToRow doesn't set) — but at Update, if that column is
	// also listed in UpdatableColumns, the omission silently writes the
	// zero value on every update, with no error: `col = EXCLUDED.col`
	// upserts whatever ToRow put in the proposed row, and a Go zero value
	// is a perfectly valid, silently-wrong SQL value. Double-check that
	// ToRow includes every field named in UpdatableColumns.
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
	// UUIDv7, is left to the database rather than whatever GetID(v)
	// happened to already hold); Update calls it with the real ID, since
	// an upsert's ON CONFLICT target only matches if the row being written
	// actually carries the ID being conflicted on.
	SetID func(R, string) R
	// IDColumn is the row's primary key column name — used by GetByID and
	// as Update's upsert conflict target.
	IDColumn string
	// UpdatableColumns lists every column Update is allowed to write,
	// typically every column except IDColumn and anything immutable (e.g.
	// created_at, a hash set once at creation).
	UpdatableColumns []string
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

// Update upserts v by IDColumn, writing exactly UpdatableColumns.
func (t Table[R, T]) Update(ctx context.Context, db sqlb.Executor, v T) error {
	row := t.SetID(t.ToRow(v), t.GetID(v))
	if _, err := sqlb.InsertRows(&row).OnConflictUpdate([]string{t.IDColumn}, t.UpdatableColumns...).Exec(ctx, db); err != nil {
		return fmt.Errorf("sqlbstore: updating: %w", err)
	}
	return nil
}

// GetBy returns the row where column equals value, or store.ErrNotFound.
func (t Table[R, T]) GetBy(ctx context.Context, db sqlb.Executor, column string, value any) (T, error) {
	row, err := sqlb.Query[R]().Where(sqlb.F(column).Eq(value)).One(ctx, db)
	switch {
	case errors.Is(err, sqlb.ErrNotFound):
		var zero T
		return zero, store.ErrNotFound
	case err != nil:
		var zero T
		return zero, fmt.Errorf("sqlbstore: getting by %s: %w", column, err)
	}
	return t.FromRow(row), nil
}

// ListBy returns every row where column equals value.
func (t Table[R, T]) ListBy(ctx context.Context, db sqlb.Executor, column string, value any) ([]T, error) {
	rows, err := sqlb.Query[R]().Where(sqlb.F(column).Eq(value)).All(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("sqlbstore: listing by %s: %w", column, err)
	}
	out := make([]T, len(rows))
	for i, row := range rows {
		out[i] = t.FromRow(row)
	}
	return out, nil
}
