package devin

import (
	"byos/internal/provider"
	"byos/internal/store"
	"time"
)

const AccountLabel = "Devin"

// IdentityFingerprintInput returns the only durable identity available for a
// Devin login. The opaque token is provider-scoped by the store; unverified JWT
// claims must never be used as account identity.
func IdentityFingerprintInput(opaqueToken string) store.AccountIdentityFingerprintInput {
	return store.AccountIdentityFingerprintInput{
		Provider:    provider.Devin,
		OpaqueToken: opaqueToken,
	}
}

// Credentials returns the minimal encrypted credential payload for Devin and
// derives its local expiry. Devin has no refresh credential, token endpoint,
// or durable user JWT.
func Credentials(opaqueToken string, now time.Time) store.AccountCredentials {
	expiresAt := ExpiresAt(opaqueToken, now)
	return store.AccountCredentials{
		OpaqueToken:          opaqueToken,
		OpaqueTokenExpiresAt: &expiresAt,
	}
}
