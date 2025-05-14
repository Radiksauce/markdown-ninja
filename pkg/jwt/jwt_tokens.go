package jwt

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

type Algorithm string
type Type string
type Curve string

const (
	// algorithmNone Algorithm = "none"

	// AlgorithmHS256 Algorithm = "HS256"
	AlgorithmHS512 Algorithm = "HS512"
	// AlgorithmEdDsa Algorithm = "EdDSA"
)

const (
	TypeJWT Type = "JWT"
)

const (
	CurveEd25519 Curve = "Ed25519"
)

var (
	ErrTokenIsNotValid     = errors.New("the token is not valid")
	ErrSignatureIsNotValid = errors.New("signature is not valid")
	ErrTokenHasExpired     = errors.New("the token has expired")
	// ErrAlgorithmIsNotValid = fmt.Errorf("Algorithm is not valid. Valid algorithms values are: [%s, %s]", AlgorithmHS256, AlgorithmHS512)
	ErrKeyNotFound      = errors.New("JWT key not found")
	ErrIssuerIsNotValid = errors.New("issuer is not valud")
)

type header struct {
	Algorithm Algorithm `json:"alg"`
	Type      Type      `json:"typ"`
	KeyID     string    `json:"kid"`
}

// registered claim names from https://www.rfc-editor.org/rfc/rfc7519#section-4.1
type reservedClaims struct {
	JwtID          string `json:"jti,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	Issuer         string `json:"iss,omitempty"`
}

// registered claim names from https://www.rfc-editor.org/rfc/rfc7519#section-4.1
type RegisteredClaims struct {
	JwtID          string `json:"jti,omitempty"`
	ExpirationTime Time   `json:"exp,omitempty"`
	NotBefore      Time   `json:"nbf,omitempty"`
	Issuer         string `json:"iss,omitempty"`
}

func (claims *RegisteredClaims) RegisteredClaims() *RegisteredClaims {
	return claims
}

type Time time.Time

func (t Time) MarshalJSON() (ret []byte, err error) {
	return []byte(strconv.Itoa(int(time.Time(t).Unix()))), nil
}

func (t *Time) UnmarshalJSON(input []byte) error {
	unixTimestamp, err := strconv.ParseInt(string(input), 10, 64)
	if err != nil {
		return fmt.Errorf("error parsing time: %w", err)
	}

	*t = Time(time.Unix(unixTimestamp, 0))
	return nil
}

// type HmacKey struct {
// 	ID        string    `json:"kid" yaml:"kid"`
// 	Algorithm Algorithm `json:"alg" yaml:"alg"`
// 	Secret    string    `json:"secret" yaml:"secret"`
// }

type TokenOptions struct {
	ExpirationTime *time.Time
	NotBefore      *time.Time
}
