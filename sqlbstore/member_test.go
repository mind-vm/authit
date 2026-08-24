package sqlbstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jryannel/authit/sqlbstore"
	"github.com/jryannel/authit/store"
)

type testMember struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	TeamID    string    `db:"team_id" sqlb:"type:uuid"`
	UserID    *string   `db:"user_id" sqlb:"type:uuid"`
	Role      string    `db:"role" sqlb:"type:text"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (testMember) TableName() string { return "sqlbstore_test_members" }

func TestMemberAdapterCompoundLookup(t *testing.T) {
	pool := testPool(t)
	db := applyDDL(t, pool, `
		CREATE TABLE IF NOT EXISTS sqlbstore_test_members (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id uuid NOT NULL,
			user_id uuid,
			role text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now()
		)`, "sqlbstore_test_members")

	a := sqlbstore.MemberAdapter[testMember]{
		Table: sqlbstore.Table[testMember, store.Member]{
			ToRow: func(m store.Member) testMember {
				return testMember{TeamID: m.TeamID, UserID: m.UserID, Role: string(m.Role)}
			},
			FromRow: func(r testMember) store.Member {
				return store.Member{ID: r.ID, TeamID: r.TeamID, UserID: r.UserID, Role: store.Role(r.Role), CreatedAt: r.CreatedAt}
			},
			GetID:    func(m store.Member) string { return m.ID },
			SetID:    func(r testMember, id string) testMember { r.ID = id; return r },
			IDColumn: "id",
		},
		DB:           db,
		TeamIDColumn: "team_id",
		UserIDColumn: "user_id",
	}
	ctx := context.Background()

	teamA, teamB := "aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"
	userX := "bbbbbbbb-0000-0000-0000-000000000001"
	uid := userX

	// Same user, two different teams — GetMemberByUserAndTeam must
	// distinguish them (the whole point of a compound predicate).
	m1 := &store.Member{TeamID: teamA, UserID: &uid, Role: store.RoleOwner}
	m2 := &store.Member{TeamID: teamB, UserID: &uid, Role: store.RoleMember}
	if err := a.CreateMember(ctx, m1); err != nil {
		t.Fatalf("CreateMember (teamA): %v", err)
	}
	if err := a.CreateMember(ctx, m2); err != nil {
		t.Fatalf("CreateMember (teamB): %v", err)
	}

	got, err := a.GetMemberByUserAndTeam(ctx, userX, teamA)
	if err != nil {
		t.Fatalf("GetMemberByUserAndTeam(teamA): %v", err)
	}
	if got.ID != m1.ID || got.Role != store.RoleOwner {
		t.Fatalf("expected teamA's owner membership, got %+v", got)
	}

	got, err = a.GetMemberByUserAndTeam(ctx, userX, teamB)
	if err != nil {
		t.Fatalf("GetMemberByUserAndTeam(teamB): %v", err)
	}
	if got.ID != m2.ID || got.Role != store.RoleMember {
		t.Fatalf("expected teamB's member membership, got %+v", got)
	}

	noSuchTeam := "aaaaaaaa-0000-0000-0000-000000000099"
	if _, err := a.GetMemberByUserAndTeam(ctx, userX, noSuchTeam); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for a team the user isn't in, got %v", err)
	}
}
