package devin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	AuthorizationEndpoint = "https://app.devin.ai/auth/cli/continue"
	ExchangeEndpoint      = "https://api.devin.ai/auth/cli/token"

	verifierBytes = 96
	stateBytes    = 32
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

// CallbackURL constructs and validates the configured HTTPS callback URL.
func CallbackURL(config OAuthConfig) (string, error) {
	originText := strings.TrimSuffix(config.CallbackOrigin, "/")
	origin, err := url.Parse(originText)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", ErrInvalidCallback
	}
	path, err := url.Parse(config.CallbackPath)
	if err != nil || !strings.HasPrefix(config.CallbackPath, "/") || strings.HasPrefix(config.CallbackPath, "//") || path.IsAbs() || path.Host != "" || path.RawQuery != "" || path.Fragment != "" || path.Path != config.CallbackPath {
		return "", ErrInvalidCallback
	}
	origin.Path = config.CallbackPath
	return origin.String(), nil
}

// AuthorizationURL builds the exact Devin browser authorization request.
func AuthorizationURL(callbackURL, state, challenge string) (string, error) {
	callback, err := url.Parse(callbackURL)
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil || callback.Fragment != "" {
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
