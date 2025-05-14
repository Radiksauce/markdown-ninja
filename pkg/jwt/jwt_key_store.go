package jwt

import (
	"context"
	"time"
)

type KeyStore interface {
	GetLatestKey(ctx context.Context) (jwtKey, error)
	GetKey(ctx context.Context, keyID string) (jwtKey, error)
	SetKey(ctx context.Context, key jwtKey) error
	DeleteKey(ctx context.Context, keyId string) error
	GetAllKeys(ctx context.Context) ([]jwtKey, error)
	DeleteOlderKeys(ctx context.Context, olderThan time.Time) error
}
