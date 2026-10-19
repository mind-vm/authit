package sqlitestore_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/team"
	"github.com/mind-vm/authit/user"
)

// TestTeamFlowsOverSQLite runs team.Service over the store with the
// TxRunner wired: an invitation accepted, the last-owner guard held against
// two owners demoting each other at once, and the cascades the schema owns.
func TestTeamFlowsOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	alice := &store.User{ID: uuid.NewString(), Email: "alice@example.com", CreatedAt: now, UpdatedAt: now}
	bob := &store.User{ID: uuid.NewString(), Email: "bob@example.com", CreatedAt: now, UpdatedAt: now}
	for _, u := range []*store.User{alice, bob} {
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := team.NewService(team.Stores{Teams: s, Members: s, Invitations: s, Tx: s}, nil, team.Config{})
	if err != nil {
		t.Fatal(err)
	}

	acme, err := svc.CreateTeam(ctx, "Acme", "acme", alice.ID, "Alice", alice.Email)
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := svc.CreateTeam(ctx, "Acme 2", "acme", bob.ID, "Bob", bob.Email); !errors.Is(err, team.ErrSlugTaken) {
		t.Fatalf("CreateTeam with a taken slug = %v, want ErrSlugTaken", err)
	}
	owner, err := svc.GetMemberByUserAndTeam(ctx, alice.ID, acme.ID)
	if err != nil {
		t.Fatalf("the creator has no membership: %v", err)
	}
	raw, inv, err := svc.CreateInvitation(ctx, acme.ID, owner.ID, bob.Email, store.RoleOwner)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	second, err := svc.AcceptInvitation(ctx, raw, bob.ID, bob.Email, "Bob")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, raw, bob.ID, bob.Email, "Bob"); !errors.Is(err, team.ErrInvitationInvalid) {
		t.Fatalf("a second acceptance = %v, want ErrInvitationInvalid", err)
	}

	// Two owners demote each other at once. Exactly one may win: both
	// winning leaves a team nobody can administer.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{owner.ID, second.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = svc.UpdateMemberRole(ctx, id, store.RoleMember)
		}()
	}
	wg.Wait()
	won, lost := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, team.ErrLastOwner):
			lost++
		default:
			t.Fatalf("UpdateMemberRole: %v", err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("concurrent demotions: %d won and %d were refused, want one of each", won, lost)
	}
	members, err := svc.ListMembersByTeam(ctx, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	owners := 0
	for _, m := range members {
		if m.Role == store.RoleOwner && m.IsActive {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("the team has %d active owners, want 1", owners)
	}

	// The inviter leaving clears the invitation's reference to them
	// rather than withdrawing it.
	if err := s.DeleteMember(ctx, owner.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetInvitation(ctx, inv.ID)
	if err != nil {
		t.Fatalf("the invitation went with its inviter: %v", err)
	}
	if got.InvitedByID != "" {
		t.Fatalf("InvitedByID = %q, want it cleared", got.InvitedByID)
	}

	// Deleting the team takes its members and invitations with it.
	if err := s.DeleteTeam(ctx, acme.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMember(ctx, second.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a member outlived its team: %v", err)
	}
	if _, err := s.GetInvitation(ctx, inv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an invitation outlived its team: %v", err)
	}
}

// TestActiveTeamOverSQLite runs SwitchTeam over the store in opaque mode:
// the team survives the round trip into the claims, leaving the team ends
// the session, and deleting a team ends the sessions acting in it.
func TestActiveTeamOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	signer, err := authitjwt.NewHMACSigner([]byte(strings.Repeat("k", 32)), authitjwt.Defaults{Issuer: "t", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	users, err := user.NewService(user.Stores{
		Users: s, RefreshTokens: s, PasswordResets: s, EmailVerifications: s,
		TOTP: s, PendingTwoFactor: s, Lockouts: s, Tx: s, Members: s,
	}, signer, nil, user.Config{SessionMode: user.SessionModeOpaque, EmailVerification: user.EmailVerificationOptional})
	if err != nil {
		t.Fatal(err)
	}
	teams, err := team.NewService(team.Stores{Teams: s, Members: s, Invitations: s, Tx: s, Sessions: s}, nil, team.Config{})
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(email string) (store.User, string) {
		t.Helper()
		u, err := users.Register(ctx, email, "correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
		res, err := users.Authenticate(ctx, email, "correct horse battery staple", "ua", "ip")
		if err != nil || res.Tokens == nil {
			t.Fatalf("Authenticate: %v", err)
		}
		return u, res.Tokens.AccessToken
	}
	alice, aliceSession := signIn("alice@example.com")
	bob, bobSession := signIn("bob@example.com")

	acme, err := teams.CreateTeam(ctx, "Acme", "acme", alice.ID, "Alice", alice.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.SwitchTeam(ctx, bobSession, acme.ID, "ua", "ip"); !errors.Is(err, user.ErrNotTeamMember) {
		t.Fatalf("SwitchTeam into a team bob is not in = %v, want ErrNotTeamMember", err)
	}
	owner, err := teams.GetMemberByUserAndTeam(ctx, alice.ID, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := teams.CreateInvitation(ctx, acme.ID, owner.ID, bob.Email, store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	member, err := teams.AcceptInvitation(ctx, raw, bob.ID, bob.Email, "Bob")
	if err != nil {
		t.Fatal(err)
	}

	pair, err := users.SwitchTeam(ctx, bobSession, acme.ID, "ua", "ip")
	if err != nil {
		t.Fatalf("SwitchTeam: %v", err)
	}
	c, err := users.ValidateSession(ctx, pair.AccessToken)
	if err != nil || c.TeamID != acme.ID {
		t.Fatalf("ValidateSession = %+v, %v; want team %s", c, err, acme.ID)
	}
	if err := teams.SetMemberActive(ctx, member.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := users.ValidateSession(ctx, pair.AccessToken); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("ValidateSession after deactivation = %v, want ErrInvalidToken", err)
	}

	alicePair, err := users.SwitchTeam(ctx, aliceSession, acme.ID, "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTeam(ctx, acme.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := users.ValidateSession(ctx, alicePair.AccessToken); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("ValidateSession after the team was deleted = %v, want ErrInvalidToken", err)
	}
}
