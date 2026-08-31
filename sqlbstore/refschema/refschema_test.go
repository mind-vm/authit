package refschema_test

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/mind-vm/authit/sqlbstore/refschema"
)

// rowTypes is every table binding this package defines.
func rowTypes() []interface{ TableName() string } {
	return []interface{ TableName() string }{
		refschema.User{}, refschema.RefreshToken{}, refschema.PasswordResetToken{},
		refschema.EmailVerificationToken{}, refschema.TOTPSettings{},
		refschema.PendingTwoFactorSession{}, refschema.FailedLoginAttempt{},
		refschema.AccountLock{}, refschema.WebAuthnChallenge{},
		refschema.Superuser{}, refschema.SuperuserRefreshToken{},
	}
}

// TestRowTypesMatchTheReferenceSchema is a drift guard, and it is the one
// test here that needs no database.
//
// This package claims to bind schema.sql exactly. Nothing enforced that:
// rename a column in the DDL and the mismatch surfaces only as a query
// error, on a machine that has Postgres, in whichever flow happens to touch
// that column first. Since the suite that would catch it skips silently
// without a DSN, "nobody noticed" and "it works" look identical.
//
// Comparing tags against the file is cheap and catches the whole class.
func TestRowTypesMatchTheReferenceSchema(t *testing.T) {
	ddl, err := os.ReadFile("../../schema.sql")
	if err != nil {
		t.Fatalf("reading schema.sql: %v", err)
	}
	tables := parseTables(string(ddl))

	for _, row := range rowTypes() {
		name := row.TableName()
		columns, ok := tables[name]
		if !ok {
			t.Errorf("%T names table %q, which schema.sql does not create", row, name)
			continue
		}
		rt := reflect.TypeOf(row)
		for i := range rt.NumField() {
			col := rt.Field(i).Tag.Get("db")
			if col == "" {
				continue
			}
			if !columns[col] {
				t.Errorf("%T maps %s.%s, which schema.sql's table does not have",
					row, name, col)
			}
		}
	}
}

var (
	createTable = regexp.MustCompile(`(?is)CREATE TABLE (\w+)\s*\((.*?)\n\);`)
	columnName  = regexp.MustCompile(`^\s*(\w+)\s`)
)

// parseTables reads CREATE TABLE statements into table -> column set. It is
// deliberately crude: it only has to understand the DDL in this repository,
// and a parser that understood more would be a thing to maintain.
func parseTables(ddl string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, m := range createTable.FindAllStringSubmatch(ddl, -1) {
		cols := map[string]bool{}
		for _, line := range strings.Split(m[2], "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			// Skip table-level constraints, which start with a keyword
			// rather than a column name.
			if c := columnName.FindStringSubmatch(line); c != nil {
				switch strings.ToUpper(c[1]) {
				case "UNIQUE", "PRIMARY", "FOREIGN", "CHECK", "CONSTRAINT":
				default:
					cols[c[1]] = true
				}
			}
		}
		out[m[1]] = cols
	}
	return out
}

// TestParseTablesFoundSomething guards the guard. A regex that matched
// nothing would make the test above pass by examining an empty map, which
// is the failure mode of every homemade parser.
func TestParseTablesFoundSomething(t *testing.T) {
	ddl, err := os.ReadFile("../../schema.sql")
	if err != nil {
		t.Fatalf("reading schema.sql: %v", err)
	}
	tables := parseTables(string(ddl))
	if len(tables) < 10 {
		t.Fatalf("parsed %d tables from schema.sql; the parser has stopped working", len(tables))
	}
	users, ok := tables["users"]
	if !ok || !users["email"] || !users["password_hash"] {
		t.Fatalf("users parsed as %v; expected at least email and password_hash", users)
	}
}
