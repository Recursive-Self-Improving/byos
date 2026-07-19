package devin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
)

const (
	tokenExpirySkew     = 5 * time.Minute
	tokenFallbackExpiry = 365 * 24 * time.Hour
)

var (
	minimumJWTExpiry = time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	maximumJWTExpiry = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC).Unix()
)

// ExpiresAt derives local expiry metadata from an opaque Devin token. A JWT
// payload is decoded without verification and only an integer exp is observed.
// All malformed or unsupported forms receive the source-compatible one-year
// fallback. A valid exp remains authoritative even when its effective expiry
// is equal to or before now.
func ExpiresAt(opaqueToken string, now time.Time) time.Time {
	fallback := now.UTC().Add(tokenFallbackExpiry)
	parts := strings.Split(opaqueToken, ".")
	if len(parts) != 3 {
		return fallback
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return fallback
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fallback
	}

	number, ok := claims["exp"].(json.Number)
	if !ok {
		return fallback
	}
	seconds, err := number.Int64()
	if err != nil || seconds < minimumJWTExpiry || seconds > maximumJWTExpiry {
		return fallback
	}
	return time.Unix(seconds, 0).UTC().Add(-tokenExpirySkew)
}

// Usable reports whether an opaque token is still locally usable. Equality is
// expired so callers never use a credential at its effective expiry instant.
func Usable(expiresAt, now time.Time) bool {
	return now.Before(expiresAt)
}
