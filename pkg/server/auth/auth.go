package auth

import (
	"github.com/bloom42/stdx-go/uuid"
	"markdown.ninja/pkg/jwt"
)

type AccessToken struct {
	UserID  uuid.UUID `json:"sub"`
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	IsAdmin bool      `json:"is_admin"`
	jwt.RegisteredClaims
}
