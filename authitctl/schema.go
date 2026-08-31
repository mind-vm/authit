package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mind-vm/authit"
)

// dialects are the ones this command can emit.
//
// One, and that is the finding rather than an omission. authit ships no
// SQLite or MySQL store adapter and no conformance run for either, so DDL
// for them would be hand-written, unrunnable, and placed in front of people
// about to create production tables. This repository has twice found the
// reference wiring wrong the moment a real database was pointed at it; the
// same bet on two dialects nothing can execute is not one worth taking for
// a printing convenience.
//
// When a conformance run exists that can verify another dialect, its DDL
// becomes worth shipping. Until then this refuses by name rather than
// quietly emitting Postgres and letting the mismatch surface as a query
// error much later.
var dialects = map[string]string{
	"postgres": authit.ReferenceSchema,
}

func schemaPrint(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("schema print", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dialect := fs.String("dialect", "postgres", "SQL dialect to emit")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if fs.NArg() > 0 {
		return usagef("schema print: unexpected argument %q", fs.Arg(0))
	}

	ddl, ok := dialects[*dialect]
	if !ok {
		return usagef("schema print: no schema for dialect %q; authit ships %s.\n"+
			"Other dialects are absent because nothing here can test them — "+
			"write your own DDL and map it with sqlbstore.Table.",
			*dialect, strings.Join(supported(), ", "))
	}
	_, err := fmt.Fprint(stdout, ddl)
	return err
}

func supported() []string {
	out := make([]string, 0, len(dialects))
	for name := range dialects {
		out = append(out, name)
	}
	return out
}
