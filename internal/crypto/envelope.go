package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const envelopePrefix = "v1:"

var envelopeAAD = []byte("supergrok-api/envelope/v1")

func Encrypt(key [32]byte, plaintext []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, envelopeAAD)
	payload := append(nonce, sealed...)
	return envelopePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func Decrypt(key [32]byte, envelope string) ([]byte, error) {
	if !strings.HasPrefix(envelope, envelopePrefix) {
		return nil, errors.New("unsupported encryption envelope")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, envelopePrefix))
	if err != nil {
		return nil, errors.New("malformed encryption envelope")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("malformed encryption envelope")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], envelopeAAD)
	if err != nil {
		return nil, errors.New("decrypt encryption envelope")
	}
	return plaintext, nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm, nil
}
