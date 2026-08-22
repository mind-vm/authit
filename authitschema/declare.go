package authitschema

import "github.com/jryannel/sqlb/schema"

// Tables is what Declare hands back: authit's table definitions, so a host can
// point its own foreign keys at them.
//
//	auth := authitschema.Declare(reg)
//	schema.Ref("user", auth.User).OnDelete(schema.Cascade)
//
// Only the tables a host is plausibly going to reference are worth reaching
// for — User, Team and Superuser are the identities; the rest are authit's
// internal bookkeeping and are exported for completeness rather than because
// pointing at a password reset token is a good idea.
type Tables struct {
	User                    *schema.TableDef
	RefreshToken            *schema.TableDef
	PasswordResetToken      *schema.TableDef
	EmailVerificationToken  *schema.TableDef
	TOTPSettings            *schema.TableDef
	PendingTwoFactorSession *schema.TableDef
	FailedLoginAttempt      *schema.TableDef
	AccountLock             *schema.TableDef

	Team           *schema.TableDef
	TeamMember     *schema.TableDef
	TeamInvitation *schema.TableDef

	Superuser                   *schema.TableDef
	SuperuserRefreshToken       *schema.TableDef
	SuperuserFailedLoginAttempt *schema.TableDef
	SuperuserAccountLock        *schema.TableDef

	PersonalAccessToken *schema.TableDef
	DeviceAuthorization *schema.TableDef
}

// All is every table Declare contributes, in dependency order.
func (t Tables) All() []*schema.TableDef {
	return []*schema.TableDef{
		t.User, t.RefreshToken, t.PasswordResetToken, t.EmailVerificationToken,
		t.TOTPSettings, t.PendingTwoFactorSession, t.FailedLoginAttempt, t.AccountLock,
		t.Team, t.TeamMember, t.TeamInvitation,
		t.Superuser, t.SuperuserRefreshToken, t.SuperuserFailedLoginAttempt, t.SuperuserAccountLock,
		t.PersonalAccessToken, t.DeviceAuthorization,
	}
}

// Declare contributes authit's tables to reg and returns them, so the host
// gets one registry, one migration sequence, and foreign keys that cross the
// boundary in both directions.
//
// # On names
//
// authit's tables keep authit's names — users, refresh_tokens, teams, and so
// on — even when reg is a module registry that prefixes its own. That is not
// an oversight. authit ships generated row structs whose TableName is fixed at
// authit's build time, so a name the host could vary would desynchronise the
// structs from the migration, and the failure would be a runtime "relation
// does not exist" rather than a compile error.
//
// The practical consequence is that authit owns `users`, and a host that
// already has a table by that name has a real collision to resolve rather than
// a prefix to set. Resolve it the way the design intends: authit's users row is
// a credential and nothing more, so the host's profile data becomes its own
// table joined by id. Declare panics on the collision rather than letting two
// declarations of `users` reach the migration diff.
//
// # On extension
//
// A host cannot add columns to these tables. Join your own table by user id
// instead. That is the same answer authit gave when it abstracted storage, and
// it is the reason declaring directly costs a host nothing it previously had:
// the Table[R, T] indirection was paying for a flexibility the design never
// wanted.
//
// # On versioning
//
// authit changing a declaration is a schema change for every host that has
// already migrated. It is therefore a breaking change and will be tagged as
// one; the host's own migration diff is what turns it into DDL, so the change
// arrives as a reviewable ALTER rather than as a surprise at boot.
func Declare(reg *schema.Registry) Tables {
	t := Tables{
		User:                    User,
		RefreshToken:            RefreshToken,
		PasswordResetToken:      PasswordResetToken,
		EmailVerificationToken:  EmailVerificationToken,
		TOTPSettings:            TOTPSettings,
		PendingTwoFactorSession: PendingTwoFactorSession,
		FailedLoginAttempt:      FailedLoginAttempt,
		AccountLock:             AccountLock,

		Team:           Team,
		TeamMember:     TeamMember,
		TeamInvitation: TeamInvitation,

		Superuser:                   Superuser,
		SuperuserRefreshToken:       SuperuserRefreshToken,
		SuperuserFailedLoginAttempt: SuperuserFailedLoginAttempt,
		SuperuserAccountLock:        SuperuserAccountLock,

		PersonalAccessToken: PersonalAccessToken,
		DeviceAuthorization: DeviceAuthorization,
	}
	// Add, not re-declare: the TableDefs are built once in this package's own
	// registry, so their names and their foreign keys to each other are already
	// settled. Copying the pointers is what keeps authit's names authit's
	// regardless of what kind of registry reg is.
	for _, table := range t.All() {
		reg.Add(table)
	}
	return t
}

// Registry is authit's own registry, holding exactly the tables Declare
// contributes. It is what authit's code generation and its own test migrations
// run against; a host wants Declare instead.
func Registry() *schema.Registry { return decls }
