package store

import "strings"

// NormalizeEmail returns the canonical form of an email address: leading
// and trailing whitespace removed, and the whole address lower-cased.
//
// This is part of the storage contract, not a convenience. Every service
// package normalises an address before it reaches a store -- both when
// writing it and when looking it up -- so an implementation can rely on the
// email column holding exactly this form, and on GetUserByEmail /
// GetSuperuserByEmail receiving exactly this form. That means a plain
// case-sensitive equality comparison is correct, and a store does NOT need
// a citext column, a functional index on lower(email), or a
// case-insensitive collation. If you add one anyway it is harmless.
//
// Without it, "Alice@example.com" and "alice@example.com" are two accounts
// on a case-sensitive store and one account on a case-insensitive one --
// authit's behaviour would be decided by your collation. Worse, the
// failed-login counter is keyed by email, so an attacker could have reset
// their own throttle just by varying the case they sent.
//
// RFC 5321 does make the local part case-sensitive, so lower-casing all of
// it is formally lossy. It matches what mail providers actually do, and the
// alternative -- letting case create duplicate accounts -- is the worse
// failure. Anything more aggressive is deliberately absent: stripping dots
// or +tags is Gmail-specific behaviour that silently merges genuinely
// distinct addresses at other providers.
//
// # Upgrading
//
// If you have rows written before authit normalised, an address stored with
// upper-case characters will no longer be found: the lookup key is now
// normalised and the stored value is not. Normalise the column once, and
// resolve any rows that collide, before deploying:
//
//	UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
