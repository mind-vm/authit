package authitschema

//go:generate go run github.com/jryannel/sqlb/cmd/sqlb generate .

import "github.com/jryannel/sqlb/codegen"

// SqlbProject tells `sqlb generate` what authit emits and where.
//
// Registry is set explicitly rather than left to the default one, because
// authit builds its own (see decls): a library that populated the default
// registry on import would contribute its tables to any host that merely
// imported the package, rather than to the host that called Declare.
//
// MigrationsDir is deliberately empty. authit generates no migrations, and
// that is the whole point of the design: a library that owns a migration
// sequence cannot be pointed at by the host's foreign keys, because the two
// sequences are applied independently and nothing orders them. The host runs
// the diff over its own registry -- authit's tables included, via Declare --
// and gets one history with real references across the boundary.
//
// No REST surface either: nothing here calls Expose, so no resource file is
// emitted and the generated package never acquires a dependency on huma.
// Whether authit's tables should be reachable over HTTP is a decision only a
// host can make, and for most of these the answer is plainly no.
func SqlbProject() codegen.Project {
	return codegen.Project{
		Options: codegen.Options{
			Registry: decls,
			Dir:      "store",
			Package:  "store",
		},
	}
}
