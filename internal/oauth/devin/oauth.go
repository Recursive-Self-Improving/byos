package devin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	AuthorizationEndpoint = "https://app.devin.ai/auth/cli/continue"
	ExchangeEndpoint      = "https://api.devin.ai/auth/cli/token"

	verifierBytes         = 96
	stateBytes            = 32
	maxCallbackURLBytes   = 16 << 10
	maxCallbackQueryBytes = 8 << 10
	maxCallbackValueBytes = 4 << 10
)

// OAuthConfig contains the deployment-specific callback address. The callback
// is always constructed from these values; request and proxy headers are not
// inputs to the OAuth protocol.
type OAuthConfig struct {
	CallbackOrigin string
	CallbackPath   string
}

// GeneratePKCE creates a 96-random-byte, unpadded base64url verifier and its
// RFC 7636 S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	return generatePKCE(rand.Reader)
}

func generatePKCE(random io.Reader) (verifier, challenge string, err error) {
	buf := make([]byte, verifierBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", "", fmt.Errorf("%w: verifier randomness", ErrRandomness)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	return verifier, ChallengeS256(verifier), nil
}

// ChallengeS256 computes the unpadded base64url SHA-256 PKCE challenge.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateState creates a 32-random-byte, unpadded base64url OAuth state.
func GenerateState() (string, error) { return generateState(rand.Reader) }

func generateState(random io.Reader) (string, error) {
	buf := make([]byte, stateBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("%w: state randomness", ErrRandomness)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CallbackURL constructs and validates the configured callback URL. Devin's
// CLI authorization endpoint accepts native-style HTTP loopback redirects;
// public HTTPS redirect URIs are rejected by the provider.
func CallbackURL(config OAuthConfig) (string, error) {
	originText := strings.TrimSuffix(config.CallbackOrigin, "/")
	origin, err := url.Parse(originText)
	if err != nil || !validCallbackOrigin(origin) || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", ErrInvalidCallback
	}
	path, err := url.Parse(config.CallbackPath)
	if err != nil || !strings.HasPrefix(config.CallbackPath, "/") || strings.HasPrefix(config.CallbackPath, "//") || path.IsAbs() || path.Host != "" || path.RawQuery != "" || path.Fragment != "" || path.Path != config.CallbackPath {
		return "", ErrInvalidCallback
	}
	origin.Path = config.CallbackPath
	return origin.String(), nil
}

func validCallbackOrigin(origin *url.URL) bool {
	if origin == nil || origin.Scheme != "http" || origin.Host == "" || origin.User != nil {
		return false
	}
	port, err := strconv.ParseUint(origin.Port(), 10, 16)
	if err != nil || port == 0 {
		return false
	}
	host := origin.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseCallbackURL validates a browser-copied Devin loopback callback against
// the exact redirect URI advertised when the flow started, then extracts the
// single-use state and authorization code. It never returns the input URL.
func ParseCallbackURL(value, expectedRedirectURI string) (state, code string, err error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCallbackURLBytes {
		return "", "", ErrInvalidCallback
	}
	candidate, err := url.Parse(value)
	if err != nil || candidate.Opaque != "" || candidate.User != nil || candidate.Fragment != "" || candidate.RawPath != "" || !validCallbackOrigin(candidate) {
		return "", "", ErrInvalidCallback
	}
	expected, err := url.Parse(expectedRedirectURI)
	if err != nil || expected.Opaque != "" || expected.User != nil || expected.RawQuery != "" || expected.Fragment != "" || expected.RawPath != "" || !validCallbackOrigin(expected) {
		return "", "", ErrInvalidCallback
	}
	if candidate.Scheme != expected.Scheme || candidate.Host != expected.Host || candidate.Path != expected.Path {
		return "", "", ErrInvalidCallback
	}
	return ParseCallbackQuery(candidate.RawQuery)
}

// ParseCallbackQuery accepts only the exact successful Devin callback shape.
// Bounding RawQuery before url.ParseQuery prevents unauthenticated callbacks
// from turning oversized attacker input into unbounded parsing work.
func ParseCallbackQuery(rawQuery string) (state, code string, err error) {
	if rawQuery == "" || len(rawQuery) > maxCallbackQueryBytes {
		return "", "", ErrInvalidCallback
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", ErrInvalidCallback
	}
	if _, present := query["error"]; present {
		return "", "", ErrInvalidAuthorization
	}
	if _, present := query["error_description"]; present {
		return "", "", ErrInvalidAuthorization
	}
	if len(query) != 2 {
		return "", "", ErrInvalidCallback
	}
	states, stateOK := query["state"]
	codes, codeOK := query["code"]
	if !stateOK || !codeOK || len(states) != 1 || len(codes) != 1 || states[0] == "" || codes[0] == "" || len(states[0]) > maxCallbackValueBytes || len(codes[0]) > maxCallbackValueBytes {
		return "", "", ErrInvalidCallback
	}
	return states[0], codes[0], nil
}

// AuthorizationURL builds the exact Devin browser authorization request.
func AuthorizationURL(callbackURL, state, challenge string) (string, error) {
	callback, err := url.Parse(callbackURL)
	if err != nil || !validCallbackOrigin(callback) || callback.Fragment != "" {
		return "", ErrInvalidCallback
	}
	if state == "" || challenge == "" {
		return "", ErrInvalidAuthorization
	}
	endpoint, _ := url.Parse(AuthorizationEndpoint)
	query := endpoint.Query()
	query.Set("redirect_uri", callback.String())
	query.Set("state", state)
	query.Set("prompt", "select_account")
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// BuildAuthorization generates state and PKCE material and returns the exact
// authorization URL. The verifier is returned for encrypted pending storage by
// the lifecycle layer; this package does not persist it.
func BuildAuthorization(config OAuthConfig) (authorizationURL, state, verifier string, err error) {
	callback, err := CallbackURL(config)
	if err != nil {
		return "", "", "", err
	}
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return "", "", "", err
	}
	state, err = GenerateState()
	if err != nil {
		return "", "", "", err
	}
	authorizationURL, err = AuthorizationURL(callback, state, challenge)
	if err != nil {
		return "", "", "", err
	}
	return authorizationURL, state, verifier, nil
}
