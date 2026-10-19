// Package sqlitestore implements auth's user-plane, team-plane and
// operator-plane store ports on SQLite: the same ports pgstore implements,
// for a CLI, a single-host service or a test suite that has no Postgres to
// run against.
//
// It uses modernc.org/sqlite, a pure-Go driver, so a binary embedding this
// package still cross-compiles with nothing but GOOS and GOARCH.
//
// Its tables carry an auth_ prefix, since SQLite has no schemas, and migrate
// with their own goose version table, so an app keeping its own tables in
// the same file runs Migrate beside its own migrations and neither sees the
// other's history.
//
// # Where it differs from pgstore
//
// The ports behave the same; storetest holds both to that. What differs is
// what SQLite is:
//
//   - One writer at a time. Every transaction begins IMMEDIATE, taking the
//     write lock up front, and a writer that cannot get it waits up to the
//     busy timeout and then fails. Under sustained concurrent writes that
//     surfaces as an error where Postgres would have queued the work.
//   - Ids are TEXT. Each id is parsed as a uuid and stored in its canonical
//     lower-case form, which is what makes an upper-case id find its row as
//     it would against a uuid column.
//   - Instants are TEXT in a fixed-width UTC layout, read back in UTC.
//   - Lists (scopes, transports, recovery-code hashes) are JSON arrays.
package sqlitestore

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/mind-vm/authit/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// VersionTable is goose's bookkeeping for the auth tables, kept apart from
// the app's own goose_db_version.
const VersionTable = "auth_goose_db_version"

// Open opens (creating if needed) the SQLite database at path, configures
// it as Store requires and migrates it. It is the whole setup for a CLI or
// a small service; Close the Store when done.
//
// path is a file. An in-memory database is refused: database/sql opens a
// fresh one per connection, so writes would land in databases nobody reads.
// A test wants a file under t.TempDir(), or memstore.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" || path == ":memory:" || strings.Contains(path, "mode=memory") {
		return nil, errors.New("sqlitestore: a database file path is required; use a temporary file or memstore for an ephemeral store")
	}
	db, err := sql.Open("sqlite", DSN(path))
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open %s: %w", path, err)
	}
	enableWAL(ctx, db)
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	s := New(db)
	s.owned = true
	return s, nil
}

// DSN returns the modernc.org/sqlite data source name Store expects for the
// database file at path. A host that opens its own *sql.DB and hands it to
// New must open it with these settings:
//
//   - foreign_keys(1): SQLite ignores REFERENCES unless every connection
//     asks it not to, and the cascades are part of the schema.
//   - busy_timeout(5000): a writer waits for the lock rather than failing
//     at once.
//   - _txlock=immediate: a transaction takes the write lock when it begins,
//     not at its first write, where SQLite would fail it without waiting.
func DSN(path string) string {
	return "file:" + path + "?" + url.Values{
		"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "synchronous(NORMAL)"},
		"_txlock": {"immediate"},
	}.Encode()
}

// enableWAL puts the database in write-ahead logging mode, where readers do
// not block the writer. It is best-effort and not a DSN pragma, for the
// reason thinking-core's agentloopsql gives: switching the mode needs an
// exclusive lock that SQLite refuses without consulting the busy handler, so
// two processes opening one file at once would fail on it. WAL is a
// property of the file, so one successful switch is enough.
func enableWAL(ctx context.Context, db *sql.DB) {
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || strings.EqualFold(mode, "wal") {
		return
	}
	_ = db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&mode)
}

// Migrate brings the auth tables to the current version.
func Migrate(ctx context.Context, db *sql.DB) error {
	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("sqlitestore: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations,
		goose.WithTableName(VersionTable))
	if err != nil {
		return fmt.Errorf("sqlitestore: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("sqlitestore: %w", err)
	}
	return nil
}

// Store implements every port pgstore does, and store.TxRunner, over one
// database.
type Store struct {
	db    *sql.DB
	owned bool
}

// New returns a Store over db, which must have been opened with DSN's
// settings and migrated. Open does both.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Close closes the database if Open opened it, and does nothing if the host
// handed it to New.
func (s *Store) Close() error {
	if !s.owned {
		return nil
	}
	return s.db.Close()
}

// DB exposes the handle, for an app keeping its own tables in the same file.
func (s *Store) DB() *sql.DB { return s.db }

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

// querier is what *sql.DB and *sql.Tx have in common.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// RunInTx runs fn in one transaction. store.TxRunner requires every store
// call made with fn's context to join it, so q reads the transaction back
// out of the context; a call inside an open transaction joins that one.
func (s *Store) RunInTx(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: begin: %w", err)
	}
	committed := false
	defer func() {
		// Also runs while a panic in fn unwinds, so the panic propagates
		// with the transaction already rolled back.
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit: %w", err)
	}
	committed = true
	return nil
}

// q returns the context's transaction, or the database.
func (s *Store) q(ctx context.Context) querier {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// exec runs a write that may match no row.
func (s *Store) exec(ctx context.Context, query string, args ...any) error {
	_, err := s.q(ctx).ExecContext(ctx, query, args...)
	return mapErr(err)
}

// execCount runs a write and reports how many rows it matched.
func (s *Store) execCount(ctx context.Context, query string, args ...any) (int64, error) {
	res, err := s.q(ctx).ExecContext(ctx, query, args...)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return n, mapErr(err)
}

// execRow runs a write that must match a row, and reports one that matched
// none as store.ErrNotFound.
func (s *Store) execRow(ctx context.Context, query string, args ...any) error {
	res, err := s.q(ctx).ExecContext(ctx, query, args...)
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// mapErr translates driver errors into the sentinels every auth service
// branches on: a missing row is store.ErrNotFound and a unique or primary
// key violation is store.ErrConflict, never the driver's own.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("%w: %s", store.ErrConflict, se.Error())
		}
	}
	return fmt.Errorf("sqlitestore: %w", err)
}

// canon returns id in the canonical form it is stored in, and whether it is
// a uuid at all. A string that is not one names nothing.
func canon(id string) (string, bool) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", false
	}
	return u.String(), true
}

// newID canonicalises the id a record is created with, assigning one when it
// is empty, and writes it back so the caller holds the stored id.
func newID(id *string) error {
	if *id == "" {
		*id = uuid.NewString()
		return nil
	}
	c, ok := canon(*id)
	if !ok {
		return fmt.Errorf("sqlitestore: %q is not a uuid", *id)
	}
	*id = c
	return nil
}

// ref canonicalises an id that refers to another row.
func ref(id string) (string, error) {
	c, ok := canon(id)
	if !ok {
		return "", fmt.Errorf("sqlitestore: %q is not a uuid", id)
	}
	return c, nil
}

// refPtr canonicalises an optional reference; nil stays NULL.
func refPtr(id *string) (any, error) {
	if id == nil {
		return nil, nil
	}
	return ref(*id)
}

// timeLayout is fixed-width UTC, so instants compare in SQL as they sort.
// time.RFC3339Nano trims trailing zeros, and "…:05Z" then sorts after
// "…:05.1Z".
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func ts(t time.Time) string { return t.UTC().Format(timeLayout) }

func tsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func now() string { return ts(time.Now()) }

// tm scans an instant column into a time.Time.
type tm struct{ dst *time.Time }

func (c tm) Scan(src any) error {
	t, err := parseTime(src)
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("sqlitestore: NULL in a NOT NULL instant column")
	}
	*c.dst = *t
	return nil
}

// tmPtr scans a nullable instant column into a *time.Time.
type tmPtr struct{ dst **time.Time }

func (c tmPtr) Scan(src any) error {
	t, err := parseTime(src)
	if err != nil {
		return err
	}
	*c.dst = t
	return nil
}

func parseTime(src any) (*time.Time, error) {
	var s string
	switch v := src.(type) {
	case nil:
		return nil, nil
	case string:
		s = v
	case []byte:
		s = string(v)
	case time.Time:
		u := v.UTC()
		return &u, nil
	default:
		return nil, fmt.Errorf("sqlitestore: cannot read %T as an instant", src)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: instant %q: %w", s, err)
	}
	return &t, nil
}

// list encodes a []string as the JSON array its column holds; nil is the
// empty array, as it is the empty text[] in pgstore.
func list(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: %w", err)
	}
	return string(b), nil
}

// strs scans a JSON array column into a []string, never nil.
type strs struct{ dst *[]string }

func (c strs) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case nil:
		*c.dst = []string{}
		return nil
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		return fmt.Errorf("sqlitestore: cannot read %T as a list", src)
	}
	out := []string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("sqlitestore: list %q: %w", b, err)
	}
	*c.dst = out
	return nil
}

// scanner is what *sql.Row and *sql.Rows have in common.
type scanner interface {
	Scan(dest ...any) error
}

// collect reads every row of a query through scan.
func collect[T any](ctx context.Context, q querier, scan func(scanner) (*T, error), query string, args ...any) ([]*T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []*T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// one reads a single row through scan; no row is store.ErrNotFound.
func one[T any](ctx context.Context, q querier, scan func(scanner) (*T, error), query string, args ...any) (*T, error) {
	v, err := scan(q.QueryRowContext(ctx, query, args...))
	if err != nil {
		return nil, mapErr(err)
	}
	return v, nil
}
