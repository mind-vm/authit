package superuser

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mind-vm/authit/audit"
	authitjwt "github.com/mind-vm/authit/jwt"
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
// live revocation check on every request. The call is recorded through
// Config.AuditLogger if one is configured (see package audit) — early
// revocation is still on the host, but the trail is not.
func (s *Service) Impersonate(ctx context.Context, superuserID, targetUserID, targetUserEmail string) (string, error) {
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
	token, err := s.signer.Sign(&claims)
	if err != nil {
		return "", err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserImpersonated, Result: audit.ResultSuccess,
		ActorID: superuserID, TargetID: targetUserID, Email: targetUserEmail,
	})
	return token, nil
}
