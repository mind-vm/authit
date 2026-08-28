package memstore

import "github.com/mind-vm/authit/store"

// Compile-time assertions that every store above satisfies its interface.
var (
	_ store.UserStore                  = (*UserStore)(nil)
	_ store.RefreshTokenStore          = (*RefreshTokenStore)(nil)
	_ store.PasswordResetStore         = (*PasswordResetStore)(nil)
	_ store.EmailVerificationStore     = (*EmailVerificationStore)(nil)
	_ store.TOTPStore                  = (*TOTPStore)(nil)
	_ store.PendingTwoFactorStore      = (*PendingTwoFactorStore)(nil)
	_ store.LockoutStore               = (*LockoutStore)(nil)
	_ store.TeamStore                  = (*TeamStore)(nil)
	_ store.MemberStore                = (*MemberStore)(nil)
	_ store.InvitationStore            = (*InvitationStore)(nil)
	_ store.SuperuserStore             = (*SuperuserStore)(nil)
	_ store.SuperuserRefreshTokenStore = (*SuperuserRefreshTokenStore)(nil)
	_ store.PersonalAccessTokenStore   = (*PersonalAccessTokenStore)(nil)
	_ store.DeviceAuthorizationStore   = (*DeviceAuthorizationStore)(nil)
	_ store.AccountStore               = (*AccountStore)(nil)
	_ store.WebAuthnCredentialStore    = (*WebAuthnCredentialStore)(nil)
	_ store.EmailLoginStore            = (*EmailLoginStore)(nil)
)
