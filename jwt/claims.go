// Package jwt provides authit's token signing/verification, kept
// deliberately free of any notion of users, sessions, or storage — it knows
// only how to turn claims into a signed string and back.
package jwt

import "github.com/golang-jwt/jwt/v5"

// Claims is the default access-token claim set for regular users. Subject
// carries the user ID. Host applications that need extra fields (e.g. a
// team ID) can define their own struct embedding jwtlib.RegisteredClaims
// and sign it directly through Signer.Sign/Verify instead of using this
// type.
type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
	// ActorID, when set, means this token was minted by an operator
	// impersonating this Subject rather than the user logging in directly
	// (see the superuser package's Impersonate). It carries no special
	// privilege on its own — it exists purely so downstream audit/log code
	// can record who was really acting.
	ActorID string `json:"actor_id,omitempty"`
}

// IsImpersonation reports whether these claims were minted by an operator
// impersonating the subject rather than by the subject logging in
// themselves.
func (c Claims) IsImpersonation() bool {
	return c.ActorID != ""
}
