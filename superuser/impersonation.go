package superuser

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	authitjwt "github.com/jryannel/authit/jwt"
)

// Impersonate mints a short-lived, ordinary user-plane access token (no
// superuser audience) for targetUserID, stamped with ActorID=superuserID
// so it is distinguishable from a normal login (jwt.Claims.IsImpersonation).
// Because it carries the user-plane's normal shape, it flows through
// existing user routes/middleware unchanged.
//
// The token is not tracked server-side: it is valid until it naturally
// expires (Config.ImpersonationTTL, default 15 minutes) and cannot be
// revoked early. This bounds blast radius via a short TTL rather than a
// live revocation check on every request. A host application that needs an
// audit trail or early revocation should log this call itself (e.g. via
// its own audit/event system) — authit does not assume one exists.
func (s *Service) Impersonate(superuserID, targetUserID, targetUserEmail string) (string, error) {
	now := time.Now()
	claims := authitjwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   targetUserID,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.ImpersonationTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Email:   targetUserEmail,
		ActorID: superuserID,
	}
	return s.signer.Sign(&claims)
}
