// Command authitctl does the two things a host cannot conveniently do for
// itself before its application exists: print the reference schema, and
// create the first operator account.
//
// It is deliberately not a migration tool. authit does not own your tables
// — that is the library's central claim, and a CLI that migrated them would
// have to assume it did. There is no `schema diff` for the same reason: it
// could not tell a deviation from the reference apart from a decision.
//
// It is its own module, so that the `pgx` driver `superuser create` needs
// does not reach the library's dependency graph. Installing it costs a host
// nothing who does not.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "authitctl:", err)
		os.Exit(1)
	}
}

// usageError is the caller getting the command line wrong, which exits 2.
// Anything else — a database that refuses, an email already taken — exits 1.
// Scripts distinguish "I typed it wrong" from "it did not work".
type usageError struct{ error }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

const usage = `authitctl — operator tooling for authit

  schema print [--dialect postgres]
        Write the reference schema to stdout.

  superuser create --dsn DSN --email EMAIL [--display-name NAME]
        Create an operator account. Reads the password from the terminal.
        Set AUTHIT_DSN instead of passing --dsn.
`

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return usagef("authitctl: a command is required")
	}
	switch {
	case args[0] == "schema" && len(args) > 1 && args[1] == "print":
		return schemaPrint(args[2:], stdout)
	case args[0] == "superuser" && len(args) > 1 && args[1] == "create":
		return superuserCreate(context.Background(), args[2:], stdout)
	case args[0] == "help", args[0] == "-h", args[0] == "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return usagef("authitctl: unknown command %q", strings.Join(args, " "))
	}
}
