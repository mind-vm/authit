package authhandlers

import (
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
)

// userResponse never exposes store.User.PasswordHash — only the fields
// below are ever written out.
type userResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	EmailVerified   bool       `json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func newUserResponse(u store.User) userResponse {
	return userResponse{
		ID:              u.ID,
		Email:           u.Email,
		EmailVerified:   u.EmailVerified,
		EmailVerifiedAt: u.EmailVerifiedAt,
		CreatedAt:       u.CreatedAt,
	}
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func newTokenResponse(t user.TokenPair) tokenResponse {
	return tokenResponse{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, ExpiresAt: t.ExpiresAt}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	RequiresTwoFactor     bool           `json:"requires_two_factor"`
	PendingTwoFactorToken string         `json:"pending_two_factor_token,omitempty"`
	Tokens                *tokenResponse `json:"tokens,omitempty"`
}

func newLoginResponse(r user.AuthResult) loginResponse {
	resp := loginResponse{RequiresTwoFactor: r.RequiresTwoFactor, PendingTwoFactorToken: r.PendingTwoFactorToken}
	if r.Tokens != nil {
		tr := newTokenResponse(*r.Tokens)
		resp.Tokens = &tr
	}
	return resp
}

type twoFactorLoginRequest struct {
	PendingTwoFactorToken string `json:"pending_two_factor_token"`
	Code                  string `json:"code"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type passwordResetRequestRequest struct {
	Email string `json:"email"`
}

type passwordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type emailVerifyRequest struct {
	Token string `json:"token"`
}

type emailVerificationRequestByEmailRequest struct {
	Email string `json:"email"`
}

type sessionResponse struct {
	ID        string    `json:"id"`
	IsCurrent bool      `json:"is_current"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func newSessionResponse(s user.Session) sessionResponse {
	return sessionResponse{
		ID:        s.ID,
		IsCurrent: s.IsCurrent,
		UserAgent: s.UserAgent,
		IPAddress: s.IPAddress,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
	}
}

type revokeOtherSessionsRequest struct {
	CurrentRefreshToken string `json:"current_refresh_token"`
}

type twoFactorSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type twoFactorCodeRequest struct {
	Code string `json:"code"`
}

type twoFactorEnrollmentResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

type twoFactorStatusResponse struct {
	Enabled              bool       `json:"enabled"`
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
	RemainingBackupCodes int        `json:"remaining_backup_codes"`
}

func newTwoFactorStatusResponse(s user.TwoFactorStatus) twoFactorStatusResponse {
	return twoFactorStatusResponse{
		Enabled:              s.Enabled,
		VerifiedAt:           s.VerifiedAt,
		RemainingBackupCodes: s.RemainingBackupCodes,
	}
}
