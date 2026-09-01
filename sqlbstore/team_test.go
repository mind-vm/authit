package sqlbstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/sqlbstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/team"
	"github.com/mind-vm/sqlb"
)

// The team plane against the reference schema.
//
// It exists because two bugs lived here undetected: the id a service generates
// being discarded by Create, and team_invitations.invited_by_id referencing the
// wrong table. Neither is visible from a unit test of the adapters — both need
// a service call landing on real DDL with real foreign keys.

const teamPlaneDDL = `
CREATE TABLE IF NOT EXISTS sqlbstore_test_users (
    id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL
);
CREATE TABLE IF NOT EXISTS sqlbstore_test_teams (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    slug       text        NOT NULL UNIQUE,
    owner_id   uuid        NOT NULL REFERENCES sqlbstore_test_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sqlbstore_test_members (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      uuid        NOT NULL REFERENCES sqlbstore_test_teams(id) ON DELETE CASCADE,
    user_id      uuid        REFERENCES sqlbstore_test_users(id) ON DELETE CASCADE,
    role         text        NOT NULL,
    display_name text        NOT NULL DEFAULT '',
    email        text        NOT NULL DEFAULT '',
    is_active    boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sqlbstore_test_invitations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id       uuid        NOT NULL REFERENCES sqlbstore_test_teams(id) ON DELETE CASCADE,
    email         text        NOT NULL,
    token_hash    text        NOT NULL UNIQUE,
    role          text        NOT NULL,
    status        text        NOT NULL DEFAULT 'pending',
    invited_by_id uuid        NOT NULL REFERENCES sqlbstore_test_members(id) ON DELETE CASCADE,
    expires_at    timestamptz NOT NULL,
    accepted_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);`

type testTeamUser struct {
	ID    string `db:"id" sqlb:"type:uuid,pk,default"`
	Email string `db:"email" sqlb:"type:text"`
}

func (testTeamUser) TableName() string { return "sqlbstore_test_users" }

type testTeam struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	Name      string    `db:"name" sqlb:"type:text"`
	Slug      string    `db:"slug" sqlb:"type:text"`
	OwnerID   string    `db:"owner_id" sqlb:"type:uuid"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt time.Time `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (testTeam) TableName() string { return "sqlbstore_test_teams" }

type testTeamMember struct {
	ID          string    `db:"id" sqlb:"type:uuid,pk,default"`
	TeamID      string    `db:"team_id" sqlb:"type:uuid"`
	UserID      *string   `db:"user_id" sqlb:"type:uuid"`
	Role        string    `db:"role" sqlb:"type:text"`
	DisplayName string    `db:"display_name" sqlb:"type:text,default"`
	Email       string    `db:"email" sqlb:"type:text,default"`
	IsActive    bool      `db:"is_active" sqlb:"type:boolean,default"`
	CreatedAt   time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt   time.Time `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (testTeamMember) TableName() string { return "sqlbstore_test_members" }

type testInvitation struct {
	ID          string     `db:"id" sqlb:"type:uuid,pk,default"`
	TeamID      string     `db:"team_id" sqlb:"type:uuid"`
	Email       string     `db:"email" sqlb:"type:text"`
	TokenHash   string     `db:"token_hash" sqlb:"type:text"`
	Role        string     `db:"role" sqlb:"type:text"`
	Status      string     `db:"status" sqlb:"type:text,default"`
	InvitedByID string     `db:"invited_by_id" sqlb:"type:uuid"`
	ExpiresAt   time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	AcceptedAt  *time.Time `db:"accepted_at" sqlb:"type:timestamptz"`
	CreatedAt   time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
	UpdatedAt   time.Time  `db:"updated_at" sqlb:"type:timestamptz,default"`
}

func (testInvitation) TableName() string { return "sqlbstore_test_invitations" }

func testTeamStores(db sqlb.Executor) team.Stores {
	return team.Stores{
		Teams: sqlbstore.TeamAdapter[testTeam]{
			Table: sqlbstore.Table[testTeam, store.Team]{
				ToRow: func(t store.Team) testTeam {
					return testTeam{Name: t.Name, Slug: t.Slug, OwnerID: t.OwnerID}
				},
				FromRow: func(r testTeam) store.Team {
					return store.Team{
						ID: r.ID, Name: r.Name, Slug: r.Slug, OwnerID: r.OwnerID,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(t store.Team) string { return t.ID },
				SetID:    func(r testTeam, id string) testTeam { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(t store.Team) map[string]any {
					return map[string]any{"name": t.Name, "slug": t.Slug, "updated_at": t.UpdatedAt}
				},
			},
			DB:         db,
			SlugColumn: "slug",
		},
		Members: sqlbstore.MemberAdapter[testTeamMember]{
			Table: sqlbstore.Table[testTeamMember, store.Member]{
				ToRow: func(m store.Member) testTeamMember {
					return testTeamMember{
						TeamID: m.TeamID, UserID: m.UserID, Role: string(m.Role),
						DisplayName: m.DisplayName, Email: m.Email, IsActive: m.IsActive,
					}
				},
				FromRow: func(r testTeamMember) store.Member {
					return store.Member{
						ID: r.ID, TeamID: r.TeamID, UserID: r.UserID, Role: store.Role(r.Role),
						DisplayName: r.DisplayName, Email: r.Email, IsActive: r.IsActive,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(m store.Member) string { return m.ID },
				SetID:    func(r testTeamMember, id string) testTeamMember { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(m store.Member) map[string]any {
					return map[string]any{
						"role": string(m.Role), "display_name": m.DisplayName,
						"email": m.Email, "is_active": m.IsActive, "updated_at": m.UpdatedAt,
					}
				},
			},
			DB:           db,
			TeamIDColumn: "team_id",
			UserIDColumn: "user_id",
		},
		Invitations: sqlbstore.InvitationAdapter[testInvitation]{
			Table: sqlbstore.Table[testInvitation, store.Invitation]{
				ToRow: func(i store.Invitation) testInvitation {
					return testInvitation{
						TeamID: i.TeamID, Email: i.Email, TokenHash: i.TokenHash,
						Role: string(i.Role), Status: string(i.Status),
						InvitedByID: i.InvitedByID, ExpiresAt: i.ExpiresAt, AcceptedAt: i.AcceptedAt,
					}
				},
				FromRow: func(r testInvitation) store.Invitation {
					return store.Invitation{
						ID: r.ID, TeamID: r.TeamID, Email: r.Email, TokenHash: r.TokenHash,
						Role: store.Role(r.Role), Status: store.InvitationStatus(r.Status),
						InvitedByID: r.InvitedByID, ExpiresAt: r.ExpiresAt, AcceptedAt: r.AcceptedAt,
						CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					}
				},
				GetID:    func(i store.Invitation) string { return i.ID },
				SetID:    func(r testInvitation, id string) testInvitation { r.ID = id; return r },
				IDColumn: "id",
				ToUpdateColumns: func(i store.Invitation) map[string]any {
					return map[string]any{
						"status": string(i.Status), "accepted_at": i.AcceptedAt,
						"updated_at": i.UpdatedAt,
					}
				},
			},
			DB:              db,
			TeamIDColumn:    "team_id",
			TokenHashColumn: "token_hash",
		},
	}
}

// teamPlaneFixture applies the DDL above and returns a service over it.
//
// It does not use applyDDL: that helper truncates each table on its own, which
// Postgres refuses for a table another table's foreign key references. These
// four reference each other, so they are emptied together.
func teamPlaneFixture(t *testing.T) (*team.Service, sqlb.Executor) {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()

	names := []string{
		"sqlbstore_test_invitations", "sqlbstore_test_members",
		"sqlbstore_test_teams", "sqlbstore_test_users",
	}
	if _, err := pool.Exec(ctx, teamPlaneDDL); err != nil {
		t.Fatalf("applying the team-plane DDL: %v", err)
	}
	t.Cleanup(func() {
		for _, n := range names {
			_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+n+` CASCADE`)
		}
	})
	if _, err := pool.Exec(ctx, `TRUNCATE `+strings.Join(names, ", ")+` CASCADE`); err != nil {
		t.Fatalf("truncating the team-plane tables: %v", err)
	}
	db := sqlb.New(pool)
	svc, err := team.NewService(testTeamStores(db), nil, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}
	return svc, db
}

func newTestUser(t *testing.T, db sqlb.Executor, email string) string {
	t.Helper()
	row := testTeamUser{Email: email}
	rows, err := sqlb.InsertRows(&row).Exec(context.Background(), db)
	if err != nil {
		t.Fatalf("creating a user: %v", err)
	}
	return rows[0].ID
}

// TestCreateTeamKeepsTheIDItGenerated is the regression test for the bug that
// made the whole team plane unusable over sqlbstore.
//
// team.CreateTeam generates an id, creates the team with it, and then creates
// the owner member pointing at that same id. Create used to blank the primary
// key unconditionally so the column default assigned a different one, and the
// member insert then failed against a team that did not exist — a foreign key
// violation naming neither the id substitution nor the service that assumed
// otherwise, with an orphaned team row left behind.
func TestCreateTeamKeepsTheIDItGenerated(t *testing.T) {
	svc, db := teamPlaneFixture(t)
	ctx := context.Background()
	owner := newTestUser(t, db, "owner@example.com")

	tm, err := svc.CreateTeam(ctx, "Acme", "acme", owner, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	members, err := svc.ListMembersByTeam(ctx, tm.ID)
	if err != nil {
		t.Fatalf("ListMembersByTeam: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("the team has %d members, want the owner", len(members))
	}
	if members[0].TeamID != tm.ID {
		t.Errorf("the owner member points at team %q, but the team is %q",
			members[0].TeamID, tm.ID)
	}
	if members[0].Role != store.RoleOwner {
		t.Errorf("the first member's role is %q, want %q", members[0].Role, store.RoleOwner)
	}
}

// TestCreateStillDefersAnUnsetIDToTheDatabase pins the other half of the
// contract: a caller that supplies no id still gets the column default, which
// is what sqlbstore's own adapters rely on.
func TestCreateStillDefersAnUnsetIDToTheDatabase(t *testing.T) {
	_, db := teamPlaneFixture(t)
	ctx := context.Background()
	owner := newTestUser(t, db, "nodefault@example.com")

	tbl := testTeamStores(db).Teams.(sqlbstore.TeamAdapter[testTeam]).Table
	got, err := tbl.Create(ctx, db, store.Team{Name: "No ID", Slug: "no-id", OwnerID: owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.ID == "" {
		t.Fatal("Create returned a row with no id; the column default should have assigned one")
	}
}

// TestInvitationRoundTrip covers the second bug: invited_by_id holds a MEMBER
// id (team.CreateInvitation's parameter is invitedByMemberID), so a schema
// pointing that foreign key at users cannot ever satisfy it.
func TestInvitationRoundTrip(t *testing.T) {
	svc, db := teamPlaneFixture(t)
	ctx := context.Background()
	owner := newTestUser(t, db, "inviter@example.com")
	invitee := newTestUser(t, db, "invitee@example.com")

	tm, err := svc.CreateTeam(ctx, "Acme", "acme", owner, "Owner", "inviter@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	members, err := svc.ListMembersByTeam(ctx, tm.ID)
	if err != nil {
		t.Fatalf("ListMembersByTeam: %v", err)
	}
	ownerMember := members[0]

	raw, inv, err := svc.CreateInvitation(ctx, tm.ID, ownerMember.ID, "invitee@example.com", store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.InvitedByID != ownerMember.ID {
		t.Errorf("InvitedByID = %q, want the inviting member %q", inv.InvitedByID, ownerMember.ID)
	}

	joined, err := svc.AcceptInvitation(ctx, raw, invitee, "invitee@example.com", "Invitee")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if joined.TeamID != tm.ID {
		t.Errorf("the new member joined team %q, want %q", joined.TeamID, tm.ID)
	}
}
