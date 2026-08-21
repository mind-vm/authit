// Package superuser implements a system-operator identity plane that is
// structurally separate from the user package: its own table (via
// SuperuserStore), its own claims type, and — critically — its own JWT
// audience, so a perfectly valid user access token can never be accepted
// by superuser middleware, and vice versa, even though both planes may
// share the same underlying jwt.Signer/secret.
package superuser

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultAudience is the JWT audience claim that marks a token as
// belonging to the superuser plane.
const DefaultAudience = "authit-superuser"

// Claims is the admin-plane access token claim set. Subject carries the
// superuser ID. Impersonation does NOT use this type — Impersonate mints an
// ordinary jwt.Claims (user-plane) token instead, so it flows through
// existing user routes unchanged; see jwt.Claims.ActorID.
type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
}

// HasAudience reports whether aud is present in the claims' audience list.
func (c Claims) HasAudience(aud string) bool {
	return slices.Contains(c.Audience, aud)
}
