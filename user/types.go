package user

import (
	"time"

	"github.com/mind-vm/authit/store"
)

// TokenPair is what a completed login/refresh returns to the caller.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AuthResult is the outcome of Authenticate. Exactly one of Tokens or
// PendingTwoFactorToken is set: if the account has 2FA enabled, the caller
// must call VerifyTwoFactorLogin with PendingTwoFactorToken to obtain
// Tokens.
type AuthResult struct {
	User                  store.User
	Tokens                *TokenPair
	RequiresTwoFactor     bool
	PendingTwoFactorToken string
}

// Session is a user-facing view of a RefreshToken, for session-management
// UIs (list active sessions, revoke one).
type Session struct {
	ID        string
	IsCurrent bool
	UserAgent string
	IPAddress string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TwoFactorSetup is returned by BeginTwoFactorSetup; the caller renders
// Secret/OTPAuthURL as a QR code for the user to scan.
type TwoFactorSetup struct {
	Secret     string
	OTPAuthURL string
}

// TwoFactorEnrollment is returned by ConfirmTwoFactorSetup: the plaintext
// backup codes, shown to the user exactly once.
type TwoFactorEnrollment struct {
	BackupCodes []string
}

// TwoFactorStatus reports a user's current 2FA state.
type TwoFactorStatus struct {
	Enabled              bool
	VerifiedAt           *time.Time
	RemainingBackupCodes int
}
