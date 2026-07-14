package xai

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Identity struct {
	Issuer, Subject, Email string
	Claims                 map[string]any
}
type IdentityVerifier struct {
	verifier *oidc.IDTokenVerifier
	issuer   string
}

func NewIdentityVerifier(ctx context.Context, issuer, jwksURI, clientID string, signingAlgs []string) *IdentityVerifier {
	keys := oidc.NewRemoteKeySet(ctx, jwksURI)
	config := &oidc.Config{ClientID: clientID, SupportedSigningAlgs: append([]string(nil), signingAlgs...)}
	return &IdentityVerifier{verifier: oidc.NewVerifier(issuer, keys, config), issuer: issuer}
}
func (v *IdentityVerifier) Verify(ctx context.Context, raw string) (Identity, error) {
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, errors.New("invalid xAI ID token")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Identity{}, errors.New("invalid xAI ID token claims")
	}
	subject := strings.TrimSpace(token.Subject)
	if subject == "" {
		return Identity{}, errors.New("xAI ID token missing subject")
	}
	email, _ := claims["email"].(string)
	return Identity{Issuer: v.issuer, Subject: subject, Email: email, Claims: claims}, nil
}
