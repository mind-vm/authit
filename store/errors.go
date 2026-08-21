// Package store defines the persistence ports that authit's service packages
// depend on. authit assumes no specific database: a host application supplies
// a concrete implementation of the interfaces in this package (Postgres,
// SQLite, in-memory, ...). The memstore package ships a reference in-memory
// implementation of every interface here, suitable for tests and small apps.
package store

import "errors"

// ErrNotFound is returned by lookup methods when no matching record exists.
var ErrNotFound = errors.New("authit/store: not found")

// ErrConflict is returned when a create would violate a uniqueness
// constraint (e.g. an email or slug that already exists).
var ErrConflict = errors.New("authit/store: conflict")
