package devin

import (
	"reflect"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

func TestIdentityFingerprintInputUsesProviderAndOpaqueTokenOnly(t *testing.T) {
	const sentinel = "DEVIN-TOKEN-SENTINEL-b7f8104c"
	got := IdentityFingerprintInput(sentinel)
	want := store.AccountIdentityFingerprintInput{Provider: provider.Devin, OpaqueToken: sentinel}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fingerprint input mismatch: provider=%q issuer=%q subject=%q", got.Provider, got.Issuer, got.Subject)
	}
}

func TestCredentialsContainOnlyOpaqueTokenAndExpiry(t *testing.T) {
	const tokenSentinel = "DEVIN-TOKEN-SENTINEL-b7f8104c"
	const userJWTSentinel = "eyJ.USER-JWT-SENTINEL-1e37f66a.sig"
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.FixedZone("offset", 3600))
	wantExpiry := now.UTC().Add(365 * 24 * time.Hour)

	got := Credentials(tokenSentinel, now)
	if got.OpaqueToken != tokenSentinel || got.OpaqueTokenExpiresAt == nil || !got.OpaqueTokenExpiresAt.Equal(wantExpiry) {
		t.Fatalf("opaque credential fields were not preserved")
	}
	if got.OpaqueTokenExpiresAt.Location() != time.UTC {
		t.Fatalf("expiry location = %v, want UTC", got.OpaqueTokenExpiresAt.Location())
	}
	if got.Issuer != "" || got.Subject != "" || got.Email != "" || got.AccessToken != "" || got.RefreshToken != "" || got.IDToken != "" || got.TokenEndpoint != "" || len(got.RawIdentity) != 0 {
		t.Fatal("Devin credentials contain xAI or refresh fields")
	}
	if got.OpaqueToken == userJWTSentinel {
		t.Fatal("user JWT was persisted as the opaque token")
	}
	if AccountLabel != "Devin" || AccountLabel == tokenSentinel || AccountLabel == userJWTSentinel {
		t.Fatal("account label is not the fixed provider-safe label")
	}
}
