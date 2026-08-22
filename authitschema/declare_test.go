package authitschema_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jryannel/authit/authitschema"
	"github.com/jryannel/authit/internal/authittest"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
	"github.com/jryannel/sqlb/schema"
)

// coach is a host's own table, declared into the same registry as authit's and
// pointing a real foreign key at authit's users. It stands in for coachai's
// coaches table, which is the case that motivated declaring rather than
// abstracting: a coach identity is meaningless without the account behind it,
// so deleting the account has to take it along.
type coach struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string    `db:"user_id" sqlb:"type:uuid"`
	Bio       string    `db:"bio" sqlb:"type:text,default"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt time.Time `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (coach) TableName() string { return "coaches" }

// hostRegistry is the composition root a host writes: one registry, authit's
// tables and its own, so one migration sequence covers both and the references
// between them are ordinary foreign keys.
func hostRegistry(t *testing.T) (*schema.Registry, authitschema.Tables) {
	t.Helper()
	reg := schema.NewRegistry()
	auth := authitschema.Declare(reg)

	reg.Table("coaches",
		schema.UUID("id").PrimaryKey().Default(schema.GenUUIDv4()),
		schema.Ref("user", auth.User).OnDelete(schema.Cascade).Unique(),
		schema.Text("bio").Default(schema.Value("")),
		schema.Timestamps(),
	)

	if err := reg.Validate(); err != nil {
		t.Fatalf("the composed registry should validate: %v", err)
	}
	return reg, auth
}

// The whole argument for declaring instead of abstracting: a host table can
// point at authit's users and the database enforces it. Under the store
// interfaces this was a bare UUID enforcing nothing, because authit's tables
// lived in a migration sequence the host's could not reference.
func TestAHostForeignKeyReachesAuthitsUsers(t *testing.T) {
	reg, _ := hostRegistry(t)
	db := authittest.FreshDBWith(t, reg)
	ctx := context.Background()

	userID := authittest.NewUser(t, db, "coach@example.com")
	row := coach{UserID: userID, Bio: "Ten years of it."}
	if _, err := sqlb.InsertRows(&row).Exec(ctx, db); err != nil {
		t.Fatalf("inserting a coach for a real user: %v", err)
	}

	// Deleting the account takes the coach identity with it. This is the
	// behaviour that was inexpressible before, not merely inconvenient.
	if _, err := sqlb.DeleteRows[store.User]().
		Where(store.UserCols.ID.Eq(userID)).
		Exec(ctx, db); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	left, err := sqlb.Query[coach]().Count(ctx, db)
	if err != nil {
		t.Fatalf("counting coaches: %v", err)
	}
	if left != 0 {
		t.Fatalf("expected the coach row to cascade away with its user, %d left", left)
	}
}

// The other half of a real reference: it refuses a row naming a user who does
// not exist. Under a bare UUID this was accepted silently and discovered later
// as a join returning nothing.
func TestAHostForeignKeyRefusesAnAbsentUser(t *testing.T) {
	reg, _ := hostRegistry(t)
	db := authittest.FreshDBWith(t, reg)

	row := coach{UserID: "00000000-0000-0000-0000-000000000000"}
	_, err := sqlb.InsertRows(&row).Exec(context.Background(), db)
	var c *sqlb.ConstraintError
	if !errors.As(err, &c) || c.Kind != sqlb.ConstraintForeignKey {
		t.Fatalf("expected a foreign key violation, got %v", err)
	}
}

// Declare contributes to the host's registry rather than keeping a sequence of
// its own, so the host's migration covers everything and ordering is not a
// question anyone has to answer.
func TestDeclareContributesEveryTableToTheHostRegistry(t *testing.T) {
	reg := schema.NewRegistry()
	auth := authitschema.Declare(reg)

	for _, table := range auth.All() {
		if table == nil {
			t.Fatal("Tables has a nil field; every declared table should be reachable")
		}
		if reg.Get(table.Name()) == nil {
			t.Errorf("%s was not contributed to the host registry", table.Name())
		}
	}
	if got, want := len(reg.Tables()), len(auth.All()); got != want {
		t.Errorf("the registry holds %d tables, Tables.All lists %d", got, want)
	}
}

// authit's names are authit's, even in a module registry that prefixes its
// own. The generated row structs carry a fixed TableName, so a name the host
// could vary would desynchronise them from the migration.
func TestAuthitKeepsItsNamesInAModuleRegistry(t *testing.T) {
	auth := authitschema.Declare(schema.NewModule("platform"))
	if got := auth.User.Name(); got != "users" {
		t.Errorf("authit's users table should stay %q under a module prefix, got %q", "users", got)
	}
	if got := (store.User{}).TableName(); got != auth.User.Name() {
		t.Errorf("the generated struct says %q but the declaration says %q", got, auth.User.Name())
	}
}
