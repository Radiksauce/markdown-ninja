package kms

import (
	"context"
	"encoding/hex"
	"fmt"
)

type ConsoleKms struct {
}

func NewConsoleKms() *ConsoleKms {
	return &ConsoleKms{}
}

func (kms *ConsoleKms) EncryptDataKey(ctx context.Context, keyId string, plaintext []byte) ([]byte, error) {
	fmt.Printf("kms: encrypting data key (%s): %s\n", keyId, hex.EncodeToString(plaintext))
	return plaintext, nil
}

func (kms *ConsoleKms) DecryptDataKey(ctx context.Context, keyId string, ciphertext []byte) ([]byte, error) {
	fmt.Printf("kms: decrypting data key (%s): %s\n", keyId, hex.EncodeToString(ciphertext))
	return ciphertext, nil
}
