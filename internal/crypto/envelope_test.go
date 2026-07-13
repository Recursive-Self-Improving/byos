package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEnvelopeRoundTripAndEmpty(t *testing.T) {
	keys, err := DeriveKeys(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{nil, []byte("secret fixture")} {
		envelope, err := Encrypt(keys.OAuth(), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(keys.OAuth(), envelope)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip = %q, want %q", got, plaintext)
		}
	}
}

func TestEnvelopeRejectsTamperWrongKeyAndMalformed(t *testing.T) {
	keys, _ := DeriveKeys(bytes.Repeat([]byte{2}, 32))
	other, _ := DeriveKeys(bytes.Repeat([]byte{3}, 32))
	envelope, _ := Encrypt(keys.OAuth(), []byte("secret"))
	if plaintext, err := Decrypt(other.OAuth(), envelope); err == nil || plaintext != nil {
		t.Fatal("wrong key returned plaintext")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, envelopePrefix))
	payload[len(payload)-1] ^= 1
	tampered := envelopePrefix + base64.RawURLEncoding.EncodeToString(payload)
	if plaintext, err := Decrypt(keys.OAuth(), tampered); err == nil || plaintext != nil {
		t.Fatal("tamper returned plaintext")
	}
	for _, malformed := range []string{"", "v2:abc", "v1:not base64", "v1:AA"} {
		if plaintext, err := Decrypt(keys.OAuth(), malformed); err == nil || plaintext != nil {
			t.Fatalf("malformed %q accepted", malformed)
		}
	}
}

func TestEnvelopeUsesUniqueNonces(t *testing.T) {
	keys, _ := DeriveKeys(bytes.Repeat([]byte{4}, 32))
	first, _ := Encrypt(keys.OAuth(), []byte("same"))
	second, _ := Encrypt(keys.OAuth(), []byte("same"))
	if first == second {
		t.Fatal("envelopes reused a nonce")
	}
}

func TestDerivedKeysAreSeparatedAndFingerprintStable(t *testing.T) {
	keys, err := DeriveKeys(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if keys.OAuth() == keys.Transcript() || keys.OAuth() == keys.Billing() || keys.OAuth() == keys.WebSession() {
		t.Fatal("derived keys are not separated")
	}
	first := keys.IdentityFingerprint("https://auth.x.ai", "subject")
	second := keys.IdentityFingerprint("https://auth.x.ai", "subject")
	if first != second {
		t.Fatal("fingerprint is not stable")
	}
	if first == keys.IdentityFingerprint("https://auth.x.ai", "other") {
		t.Fatal("fingerprint ignores subject")
	}
}
