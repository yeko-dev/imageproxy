package imageproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

const defaultTokenBytes = 24

// Token identifies a stored upstream image until ExpiresAt.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

func newToken(size int) (string, error) {
	if size <= 0 {
		size = defaultTokenBytes
	}

	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newTokenFromString(secret []byte, value string) (string, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func validateToken(token string, maxLen int) error {
	if token == "" || len(token) > maxLen {
		return ErrInvalidToken
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return ErrInvalidToken
	}

	return nil
}
