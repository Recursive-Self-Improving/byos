package devin

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func jwtWithPayload(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestExpiresAtUsesUnverifiedIntegerExpWithSkew(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	token := jwtWithPayload(fmt.Sprintf(`{"exp":%d,"sub":"must-not-be-identity","email":"private@example.test"}`, exp.Unix()))

	if got, want := ExpiresAt(token, now), exp.Add(-5*time.Minute); !got.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got, want)
	}
}

func TestExpiresAtValidPastAndEqualityRemainExpired(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		exp  time.Time
		want time.Time
	}{
		{name: "equality", exp: now.Add(5 * time.Minute), want: now},
		{name: "past", exp: now.Add(-time.Hour), want: now.Add(-time.Hour - 5*time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, test.exp.Unix()))
			got := ExpiresAt(token, now)
			if !got.Equal(test.want) {
				t.Fatalf("expiry = %v, want %v", got, test.want)
			}
			if Usable(got, now) {
				t.Fatal("expired credential reported usable")
			}
		})
	}
}

func TestUsableExpiryBoundary(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	if !Usable(now.Add(time.Nanosecond), now) {
		t.Fatal("future expiry reported unusable")
	}
	if Usable(now, now) || Usable(now.Add(-time.Nanosecond), now) {
		t.Fatal("expiry equality or past reported usable")
	}
}

func TestExpiresAtMalformedTokensUseFixedOneYearFallback(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.FixedZone("offset", 7200))
	want := now.UTC().Add(365 * 24 * time.Hour)
	tests := map[string]string{
		"empty":                "",
		"one segment":          "opaque",
		"two segments":         "one.two",
		"four segments":        "one.two.three.four",
		"bad base64":           "one.%%%.three",
		"non object":           jwtWithPayload(`[]`),
		"missing exp":          jwtWithPayload(`{"sub":"private"}`),
		"string exp":           jwtWithPayload(`{"exp":"123"}`),
		"fraction exp":         jwtWithPayload(`{"exp":123.5}`),
		"null exp":             jwtWithPayload(`{"exp":null}`),
		"boolean exp":          jwtWithPayload(`{"exp":true}`),
		"overflow exp":         jwtWithPayload(`{"exp":9223372036854775808}`),
		"out of time range":    jwtWithPayload(`{"exp":253402300800}`),
		"malformed json":       jwtWithPayload(`{"exp":`),
		"multiple json values": jwtWithPayload(`{"exp":123} {"exp":456}`),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ExpiresAt(token, now); !got.Equal(want) {
				t.Fatalf("expiry = %v, want fallback %v", got, want)
			}
		})
	}
}

func TestExpiresAtDoesNotExposeTokenSentinel(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	const sentinel = "DEVIN-TOKEN-SENTINEL-b7f8104c"
	got := ExpiresAt(sentinel, now)
	if got.Format(time.RFC3339Nano) == sentinel {
		t.Fatal("token sentinel escaped through expiry metadata")
	}
}
