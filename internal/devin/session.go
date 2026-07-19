package devin

import (
	"errors"
	"strings"

	devinproto "byos/internal/devin/proto"
)

const (
	SessionTokenPrefix       = "devin-session-token$"
	WindsurfIDEName          = "windsurf"
	WindsurfIDEVersion       = "3.2.23"
	WindsurfExtensionName    = "windsurf"
	WindsurfExtensionVersion = "1.48.2"
	WindsurfLocale           = "en"
)

var ErrSessionTokenRequired = errors.New("devin session token is required")

// NormalizeSessionToken canonicalizes an opaque Devin credential without ever
// including credential material in an error.
func NormalizeSessionToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	for strings.HasPrefix(token, SessionTokenPrefix) {
		token = strings.TrimSpace(strings.TrimPrefix(token, SessionTokenPrefix))
	}
	if token == "" {
		return "", ErrSessionTokenRequired
	}
	return SessionTokenPrefix + token, nil
}

// SourceMetadata returns the fixed Windsurf identity expected by the Devin API.
// The API key is the normalized Devin session token, never a downstream or
// administrative credential.
func SourceMetadata(sessionToken string) (*devinproto.Metadata, error) {
	normalized, err := NormalizeSessionToken(sessionToken)
	if err != nil {
		return nil, err
	}
	return &devinproto.Metadata{
		IDEName:          WindsurfIDEName,
		IDEVersion:       WindsurfIDEVersion,
		ExtensionName:    WindsurfExtensionName,
		ExtensionVersion: WindsurfExtensionVersion,
		Locale:           WindsurfLocale,
		APIKey:           normalized,
	}, nil
}
