package authittest

import (
	"context"
	"testing"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// NewUser inserts a user and returns its id.
//
// It exists because authit's tables now carry real foreign keys: a refresh
// token, a personal access token or a team membership naming "user-1" is
// refused by the database rather than quietly stored. That refusal is the
// point — a fixture that could name a user who does not exist was a fixture
// testing something the production path cannot do.
func NewUser(t testing.TB, db *sqlb.DB, email string) string {
	t.Helper()
	return NewUserWithPassword(t, db, email, "correct-horse-battery-staple")
}

// NewUserWithPassword is NewUser with a known password, for tests that then
// authenticate as that user.
func NewUserWithPassword(t testing.TB, db *sqlb.DB, email, password string) string {
	t.Helper()
	hash, err := authitcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("authittest: hashing the fixture password: %v", err)
	}
	row := store.User{Email: email, PasswordHash: hash, EmailVerified: true}
	inserted, err := sqlb.InsertRows(&row).Exec(context.Background(), db)
	if err != nil {
		t.Fatalf("authittest: creating the fixture user %q: %v", email, err)
	}
	return inserted[0].ID
}

// NewSuperuser inserts an operator account and returns its id.
func NewSuperuser(t testing.TB, db *sqlb.DB, email, password string) string {
	t.Helper()
	hash, err := authitcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("authittest: hashing the fixture password: %v", err)
	}
	row := store.Superuser{Email: email, PasswordHash: hash, IsActive: true}
	inserted, err := sqlb.InsertRows(&row).Exec(context.Background(), db)
	if err != nil {
		t.Fatalf("authittest: creating the fixture superuser %q: %v", email, err)
	}
	return inserted[0].ID
}
