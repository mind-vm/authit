// Package store defines the persistence ports that authit's service packages
// depend on. authit assumes no specific database: a host application supplies
// a concrete implementation of the interfaces in this package (Postgres,
// SQLite, in-memory, ...). The memstore package ships a reference in-memory
// implementation of every interface here, suitable for tests and small apps.
//
// authit ships no DDL: your schema, naming and migrations are yours. It does
// ship a reference one. schema.sql in the repository root is a complete,
// non-binding table set for every interface here, annotated with the places
// where the column set is not guessable from the struct definitions -- and
// sqlbstore/example_test.go applies it and runs the real flows over it, so it
// is checked rather than merely asserted. Start there rather than
// reverse-engineering the columns one type at a time.
package store

import "errors"

// ErrNotFound is returned by lookup methods when no matching record exists.
var ErrNotFound = errors.New("authit/store: not found")

// ErrConflict is returned when a create would violate a uniqueness
// constraint (e.g. an email or slug that already exists).
var ErrConflict = errors.New("authit/store: conflict")
