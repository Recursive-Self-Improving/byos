package devin

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeSessionToken(t *testing.T) {
	const bare = "opaque-secret"
	for _, test := range []struct {
		name, input, want string
	}{
		{"bare", bare, SessionTokenPrefix + bare},
		{"once", SessionTokenPrefix + bare, SessionTokenPrefix + bare},
		{"repeated", SessionTokenPrefix + SessionTokenPrefix + bare, SessionTokenPrefix + bare},
		{"whitespace", " \t" + SessionTokenPrefix + "  " + SessionTokenPrefix + bare + " \n", SessionTokenPrefix + bare},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeSessionToken(test.input)
			if err != nil || got != test.want {
				t.Fatalf("NormalizeSessionToken() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestNormalizeSessionTokenRejectsEmptyWithoutCredentialLeak(t *testing.T) {
	for _, input := range []string{"", " \t\n", SessionTokenPrefix, SessionTokenPrefix + " " + SessionTokenPrefix} {
		_, err := NormalizeSessionToken(input)
		if !errors.Is(err, ErrSessionTokenRequired) {
			t.Fatalf("input %q: got %v", input, err)
		}
		if strings.Contains(err.Error(), input) && input != "" {
			t.Fatalf("error leaked input %q: %v", input, err)
		}
	}
}

func TestSourceMetadataExactIdentity(t *testing.T) {
	metadata, err := SourceMetadata("secret")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.IDEName != WindsurfIDEName || metadata.IDEVersion != WindsurfIDEVersion || metadata.ExtensionName != WindsurfExtensionName || metadata.ExtensionVersion != WindsurfExtensionVersion || metadata.Locale != WindsurfLocale || metadata.APIKey != SessionTokenPrefix+"secret" || metadata.UserJWT != "" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}
