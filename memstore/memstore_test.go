package memstore_test

import (
	"testing"

	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
)

// TestMemstoreConformance runs the shared store conformance suite against
// every in-memory implementation.
//
// memstore is the reference a host reads before writing its own adapter,
// and until this existed it had no tests at all — its correctness was
// asserted only indirectly, by the service packages that happen to use it.
func TestMemstoreConformance(t *testing.T) {
	storetest.RunAll(t, storetest.Stores{
		Users:              func(*testing.T) store.UserStore { return memstore.NewUserStore() },
		RefreshTokens:      func(*testing.T) store.RefreshTokenStore { return memstore.NewRefreshTokenStore() },
		PasswordResets:     func(*testing.T) store.PasswordResetStore { return memstore.NewPasswordResetStore() },
		EmailVerifications: func(*testing.T) store.EmailVerificationStore { return memstore.NewEmailVerificationStore() },
		TOTP:               func(*testing.T) store.TOTPStore { return memstore.NewTOTPStore() },
		PendingTwoFactor:   func(*testing.T) store.PendingTwoFactorStore { return memstore.NewPendingTwoFactorStore() },
		Lockouts:           func(*testing.T) store.LockoutStore { return memstore.NewLockoutStore() },
		Teams:              func(*testing.T) store.TeamStore { return memstore.NewTeamStore() },
		Members:            func(*testing.T) store.MemberStore { return memstore.NewMemberStore() },
		Invitations:        func(*testing.T) store.InvitationStore { return memstore.NewInvitationStore() },
		PATs: func(*testing.T) store.PersonalAccessTokenStore {
			return memstore.NewPersonalAccessTokenStore()
		},
		Devices: func(*testing.T) store.DeviceAuthorizationStore {
			return memstore.NewDeviceAuthorizationStore()
		},
		Superusers: func(*testing.T) store.SuperuserStore { return memstore.NewSuperuserStore() },
		SuperuserTokens: func(*testing.T) store.SuperuserRefreshTokenStore {
			return memstore.NewSuperuserRefreshTokenStore()
		},
		Accounts: func(*testing.T) store.AccountStore { return memstore.NewAccountStore() },
		WebAuthn: func(*testing.T) store.WebAuthnCredentialStore {
			return memstore.NewWebAuthnCredentialStore()
		},
		EmailLogins: func(*testing.T) store.EmailLoginStore { return memstore.NewEmailLoginStore() },
	})
}
