package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/team"
	"github.com/mind-vm/authit/user"
)

// teamFixture is a user.Service and a team.Service sharing their member and
// session stores, the way an app using teams as tenants wires them.
type teamFixture struct {
	users   *user.Service
	teams   *team.Service
	members store.MemberStore
	signer  *authitjwt.HMACSigner
	userID  string
	login   user.TokenPair
}

// newTeamFixture registers alice and signs her in. revokeOnChange wires
// team.Stores.Sessions, so a membership change ends sessions at once rather
// than at their next use.
func newTeamFixture(t *testing.T, mode user.SessionMode, revokeOnChange bool) teamFixture {
	t.Helper()
	ctx := context.Background()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 7)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sessions := memstore.NewRefreshTokenStore()
	members := memstore.NewMemberStore()
	users, err := user.NewService(user.Stores{
		Users: memstore.NewUserStore(), RefreshTokens: sessions,
		PasswordResets: memstore.NewPasswordResetStore(), EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP: memstore.NewTOTPStore(), PendingTwoFactor: memstore.NewPendingTwoFactorStore(),
		Lockouts: memstore.NewLockoutStore(), Members: members,
	}, signer, nil, user.Config{SessionMode: mode, EmailVerification: user.EmailVerificationOptional})
	if err != nil {
		t.Fatal(err)
	}
	ts := team.Stores{Teams: memstore.NewTeamStore(), Members: members, Invitations: memstore.NewInvitationStore()}
	if revokeOnChange {
		ts.Sessions = sessions
	}
	teams, err := team.NewService(ts, nil, team.Config{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := users.Register(ctx, "alice@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	res, err := users.Authenticate(ctx, "alice@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1")
	if err != nil || res.Tokens == nil {
		t.Fatalf("Authenticate: %v, %+v", err, res)
	}
	return teamFixture{users: users, teams: teams, members: members, signer: signer, userID: u.ID, login: *res.Tokens}
}

// session returns the token that names the session in either mode.
func (f teamFixture) session(p user.TokenPair) string {
	if p.RefreshToken != "" {
		return p.RefreshToken
	}
	return p.AccessToken
}

// claims resolves a token pair the way a protected route would in its mode.
func (f teamFixture) claims(t *testing.T, p user.TokenPair) (authitjwt.Claims, error) {
	t.Helper()
	if f.users.SessionMode() == user.SessionModeOpaque {
		return f.users.ValidateSession(context.Background(), p.AccessToken)
	}
	return f.signer.Validate(p.AccessToken)
}

func (f teamFixture) createTeam(t *testing.T, slug string) store.Team {
	t.Helper()
	tm, err := f.teams.CreateTeam(context.Background(), slug, slug, f.userID, "Alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func eachMode(t *testing.T, fn func(t *testing.T, mode user.SessionMode)) {
	t.Run("jwt", func(t *testing.T) { fn(t, user.SessionModeJWT) })
	t.Run("opaque", func(t *testing.T) { fn(t, user.SessionModeOpaque) })
}

// TestSwitchTeam: the switched session carries the team into its claims,
// across rotation, and the session it replaces is spent.
func TestSwitchTeam(t *testing.T) {
	eachMode(t, func(t *testing.T, mode user.SessionMode) {
		ctx := context.Background()
		f := newTeamFixture(t, mode, false)
		acme := f.createTeam(t, "acme")

		switched, err := f.users.SwitchTeam(ctx, f.session(f.login), acme.ID, "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("SwitchTeam: %v", err)
		}
		c, err := f.claims(t, switched)
		if err != nil {
			t.Fatalf("claims of the switched session: %v", err)
		}
		if c.TeamID != acme.ID || c.Subject != f.userID {
			t.Fatalf("claims = %+v, want team %s for %s", c, acme.ID, f.userID)
		}
		// The old token must not act in either team any more.
		if _, err := f.users.SwitchTeam(ctx, f.session(f.login), "", "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidToken) {
			t.Fatalf("reusing the replaced session = %v, want ErrInvalidToken", err)
		}

		sessions, err := f.users.ListSessions(ctx, f.userID, "")
		if err != nil {
			t.Fatal(err)
		}
		if mode == user.SessionModeJWT {
			// Presenting the spent refresh token was reuse, which ends
			// every session. Sign in again for the rotation check.
			if len(sessions) != 0 {
				t.Fatalf("after reuse %d sessions survive, want 0", len(sessions))
			}
			return
		}
		if len(sessions) != 1 || sessions[0].TeamID != acme.ID {
			t.Fatalf("sessions = %+v, want one acting in %s", sessions, acme.ID)
		}
	})
}

// TestRefreshKeepsTheTeam: rotation carries the session's team over.
func TestRefreshKeepsTheTeam(t *testing.T) {
	ctx := context.Background()
	f := newTeamFixture(t, user.SessionModeJWT, false)
	acme := f.createTeam(t, "acme")
	switched, err := f.users.SwitchTeam(ctx, f.login.RefreshToken, acme.ID, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := f.users.Refresh(ctx, switched.RefreshToken, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	c, err := f.claims(t, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if c.TeamID != acme.ID {
		t.Fatalf("TeamID after Refresh = %q, want %q", c.TeamID, acme.ID)
	}

	// And switching to no team clears it.
	cleared, err := f.users.SwitchTeam(ctx, rotated.RefreshToken, "", "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := f.claims(t, cleared); err != nil || c.TeamID != "" {
		t.Fatalf("claims after switching to no team = %+v, %v", c, err)
	}
}

// TestSwitchTeamRequiresActiveMembership: a team the user is not in, or is
// deactivated in, is refused, and the session is left as it was.
func TestSwitchTeamRequiresActiveMembership(t *testing.T) {
	eachMode(t, func(t *testing.T, mode user.SessionMode) {
		ctx := context.Background()
		f := newTeamFixture(t, mode, false)
		other := newTeamFixture(t, mode, false)
		// A team that exists, in a store alice's service cannot see a
		// membership for.
		foreign := other.createTeam(t, "foreign")
		if _, err := f.users.SwitchTeam(ctx, f.session(f.login), foreign.ID, "ua", "ip"); !errors.Is(err, user.ErrNotTeamMember) {
			t.Fatalf("SwitchTeam to a team she is not in = %v, want ErrNotTeamMember", err)
		}

		acme := f.createTeam(t, "acme")
		owner, err := f.teams.GetMemberByUserAndTeam(ctx, f.userID, acme.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Make room to deactivate her: a second owner.
		if err := f.teams.SetMemberActive(ctx, owner.ID, false); !errors.Is(err, team.ErrLastOwner) {
			t.Fatalf("expected the last-owner guard, got %v", err)
		}
		bobID := "bob"
		bob := &store.Member{ID: "m-bob", TeamID: acme.ID, UserID: &bobID, Role: store.RoleOwner, IsActive: true}
		if err := f.members.CreateMember(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if err := f.teams.SetMemberActive(ctx, owner.ID, false); err != nil {
			t.Fatal(err)
		}
		if _, err := f.users.SwitchTeam(ctx, f.session(f.login), acme.ID, "ua", "ip"); !errors.Is(err, user.ErrNotTeamMember) {
			t.Fatalf("SwitchTeam while deactivated = %v, want ErrNotTeamMember", err)
		}
		// Refused, not spent: the original session still works.
		if _, err := f.users.SwitchTeam(ctx, f.session(f.login), "", "ua", "ip"); err != nil {
			t.Fatalf("the session a refused switch left behind: %v", err)
		}
	})
}

// TestLeavingTheTeamEndsItsSessions: deactivating or removing a membership
// ends the sessions acting in that team -- at once with team.Stores.Sessions
// wired, and at their next use without it.
func TestLeavingTheTeamEndsItsSessions(t *testing.T) {
	for _, revokeOnChange := range []bool{true, false} {
		name := "at their next use"
		if revokeOnChange {
			name = "at once"
		}
		t.Run(name, func(t *testing.T) {
			eachMode(t, func(t *testing.T, mode user.SessionMode) {
				for _, leave := range []string{"deactivate", "remove"} {
					t.Run(leave, func(t *testing.T) {
						ctx := context.Background()
						f := newTeamFixture(t, mode, revokeOnChange)
						acme := f.createTeam(t, "acme")
						home := f.createTeam(t, "home")
						inAcme, err := f.users.SwitchTeam(ctx, f.session(f.login), acme.ID, "ua", "ip")
						if err != nil {
							t.Fatal(err)
						}
						res, err := f.users.Authenticate(ctx, "alice@example.com", "correct-horse-battery-staple", "ua", "ip")
						if err != nil {
							t.Fatal(err)
						}
						inHome, err := f.users.SwitchTeam(ctx, f.session(*res.Tokens), home.ID, "ua", "ip")
						if err != nil {
							t.Fatal(err)
						}

						// A second owner, so alice may leave.
						bobID := "bob"
						bob := &store.Member{ID: "m-bob", TeamID: acme.ID, UserID: &bobID, Role: store.RoleOwner, IsActive: true}
						if err := f.members.CreateMember(ctx, bob); err != nil {
							t.Fatal(err)
						}
						m, err := f.teams.GetMemberByUserAndTeam(ctx, f.userID, acme.ID)
						if err != nil {
							t.Fatal(err)
						}
						if leave == "deactivate" {
							err = f.teams.SetMemberActive(ctx, m.ID, false)
						} else {
							err = f.teams.RemoveMember(ctx, m.ID)
						}
						if err != nil {
							t.Fatal(err)
						}

						if revokeOnChange {
							sessions, err := f.users.ListSessions(ctx, f.userID, "")
							if err != nil {
								t.Fatal(err)
							}
							if len(sessions) != 1 || sessions[0].TeamID != home.ID {
								t.Fatalf("sessions after leaving = %+v, want only the one in %s", sessions, home.ID)
							}
						}
						if mode == user.SessionModeOpaque {
							if _, err := f.users.ValidateSession(ctx, inAcme.AccessToken); !errors.Is(err, user.ErrInvalidToken) {
								t.Fatalf("ValidateSession in the team she left = %v, want ErrInvalidToken", err)
							}
						} else if _, err := f.users.Refresh(ctx, inAcme.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
							t.Fatalf("Refresh in the team she left = %v, want ErrInvalidToken", err)
						}
						// Her session in another team is untouched.
						if _, err := f.users.SwitchTeam(ctx, f.session(inHome), home.ID, "ua", "ip"); err != nil {
							t.Fatalf("the session in another team: %v", err)
						}
					})
				}
			})
		})
	}
}

// TestSwitchTeamNeedsMembers: without Stores.Members there is nothing to
// check a membership against, and SwitchTeam says so rather than trusting
// the caller.
func TestSwitchTeamNeedsMembers(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.SwitchTeam(context.Background(), "whatever", "team", "ua", "ip"); !errors.Is(err, user.ErrNoMemberStore) {
		t.Fatalf("SwitchTeam without Members = %v, want ErrNoMemberStore", err)
	}
}
