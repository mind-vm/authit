package user

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	authitjwt "github.com/mind-vm/authit/jwt"
)

func newAccessClaims(userID, email string, expiresAt time.Time) authitjwt.Claims {
	return authitjwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email: email,
	}
}
