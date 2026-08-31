// An internal test package, which every other test in this repository
// deliberately is not. A command has no importable surface: from outside,
// run and schemaPrint do not exist, and the alternative is building a
// binary and parsing its output, which tests the shell as much as the code.
package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mind-vm/authit"
)

func TestSchemaPrintEmitsTheReferenceSchemaVerbatim(t *testing.T) {
	// Verbatim matters. The comments in schema.sql are most of its value --
	// they say which constraints authit actually depends on -- so anything
	// that reformats or regenerates on the way out has thrown away the part
	// that stops a host dropping an index the library needs.
	var out strings.Builder
	if err := run([]string{"schema", "print"}, &out, io.Discard); err != nil {
		t.Fatalf("schema print: %v", err)
	}
	if out.String() != authit.ReferenceSchema {
		t.Fatal("schema print did not emit schema.sql byte for byte")
	}
	if !strings.Contains(out.String(), "CREATE TABLE users") {
		t.Fatal("output does not look like the schema")
	}
}

func TestUnsupportedDialectIsRefusedByName(t *testing.T) {
	// Not "emit Postgres and hope". authit ships no SQLite or MySQL
	// adapter and no conformance run for either, so DDL for them would be
	// hand-written and untestable -- in the file people copy to create
	// production tables. Refusing says so; emitting Postgres under another
	// name would surface as a query error much later.
	for _, dialect := range []string{"sqlite", "mysql", "oracle", ""} {
		t.Run(dialect, func(t *testing.T) {
			err := run([]string{"schema", "print", "--dialect", dialect}, io.Discard, io.Discard)
			var usage usageError
			if !errors.As(err, &usage) {
				t.Fatalf("dialect %q: got %v, want a usage error (exit 2)", dialect, err)
			}
			if !strings.Contains(err.Error(), "postgres") {
				t.Fatalf("the refusal should name what is available, got: %v", err)
			}
		})
	}
}

func TestUsageErrorsAreDistinguishable(t *testing.T) {
	// Exit 2 for "you typed it wrong" and 1 for "it did not work" is the
	// difference a script needs. Everything here is the former.
	for name, args := range map[string][]string{
		"no command":      {},
		"unknown command": {"frobnicate"},
		"partial command": {"schema"},
		"stray argument":  {"schema", "print", "extra"},
		"missing dsn":     {"superuser", "create", "--email", "a@b.c"},
		"missing email":   {"superuser", "create", "--dsn", "postgres://x"},
		"unknown flag":    {"schema", "print", "--colour"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(args, io.Discard, io.Discard)
			var usage usageError
			if !errors.As(err, &usage) {
				t.Fatalf("got %v, want a usage error (exit 2)", err)
			}
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	var out strings.Builder
	if err := run([]string{"help"}, &out, io.Discard); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(out.String(), "superuser create") {
		t.Fatalf("help does not mention the commands: %q", out.String())
	}
}
