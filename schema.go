// Package authit exposes the reference schema as data.
//
// It exists only so that schema.sql can be read by something other than a
// human with a checkout: a host consuming authit as a module has no copy of
// the file on disk, and "go and find it in your module cache" is how a
// schema gets stale.
//
// Nothing else lives at the root of this module, and nothing here is
// required to use authit. The library still reads no schema and owns no
// tables — see the store package.
package authit

import _ "embed"

// ReferenceSchema is schema.sql verbatim, comments and all.
//
// The comments are most of its value: they say which constraints authit
// actually depends on (the UNIQUE on refresh_tokens.token_hash, the one on
// account_locks.user_id) and which are merely the shape this file happened
// to choose. Anything that reformats or regenerates this must keep them, or
// it has thrown away the part that stops a host dropping an index authit
// needs.
//
// It is a starting point, not a requirement. Every column name here is
// mapped explicitly in an adapter — see sqlbstore/refschema for the binding
// that matches this file exactly — so a host renaming any of them changes
// the adapter, not this file.
//
//go:embed schema.sql
var ReferenceSchema string
