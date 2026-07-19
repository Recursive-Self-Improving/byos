package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

var (
	ErrInvalidClientConfig = errors.New("invalid Devin client configuration")
	ErrUnsafeTLSDialHooks  = errors.New("Devin HTTP transport TLS dial hooks are not allowed")
	ErrUnsafeTLSNextProto  = errors.New("Devin HTTP transport TLS protocol hooks are not allowed")
	ErrRedirect            = errors.New("Devin API redirects are not allowed")
	ErrResponseTooLarge    = errors.New("Devin API response exceeds configured limit")
	ErrMalformedResponse   = errors.New("malformed Devin API response")
	ErrEmptyUserJWT        = errors.New("Devin API returned an empty user JWT")
)

type HTTPStatusError struct{ StatusCode int }

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("Devin API returned HTTP %d", e.StatusCode)
}

type ClientConfig struct {
	HTTPClient           *http.Client
	Resolver             Resolver
	Dialer               *net.Dialer
	AllowedChatHosts     []string
	UnaryTimeout         time.Duration
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
}

type Client struct {
	httpClient           *http.Client
	resolver             Resolver
	allowedHosts         []string
	timeout              time.Duration
	maxCompressedBytes   int64
	maxDecompressedBytes int64
}

type AuthSession struct {
	UserJWT      string
	APIBaseURL   string
	SessionToken string
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.UnaryTimeout <= 0 || config.MaxCompressedBytes <= 0 || config.MaxDecompressedBytes <= 0 || len(config.AllowedChatHosts) == 0 {
		return nil, ErrInvalidClientConfig
	}
	allowed := append([]string(nil), config.AllowedChatHosts...)
	for _, host := range allowed {
		if host == "" || host != strings.TrimSpace(host) || strings.ToLower(host) != host || net.ParseIP(host) != nil || strings.Contains(host, ":") {
			return nil, ErrInvalidClientConfig
		}
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = publicResolver{resolver: net.DefaultResolver}
	}
	dialer := config.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	var transport *http.Transport
	base := config.HTTPClient
	if base == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		base = &http.Client{}
	} else {
		supplied, ok := base.Transport.(*http.Transport)
		if !ok && base.Transport != nil {
			return nil, ErrInvalidClientConfig
		}
		if supplied != nil && (supplied.DialTLSContext != nil || supplied.DialTLS != nil) {
			return nil, ErrUnsafeTLSDialHooks
		}
		if supplied != nil && supplied.TLSNextProto != nil {
			return nil, ErrUnsafeTLSNextProto
		}
		if supplied == nil {
			supplied = http.DefaultTransport.(*http.Transport)
		}
		transport = supplied.Clone()
	}
	var rootCAs *x509.CertPool
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.RootCAs != nil {
		rootCAs = transport.TLSClientConfig.RootCAs.Clone()
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}
	transport.Proxy = nil
	transport.DialContext = trustedDialer(resolver, dialer)
	transport.ForceAttemptHTTP2 = true
	transport.ResponseHeaderTimeout = config.UnaryTimeout
	copyClient := *base
	copyClient.Transport = transport
	copyClient.Timeout = 0
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	return &Client{httpClient: &copyClient, resolver: resolver, allowedHosts: allowed, timeout: config.UnaryTimeout, maxCompressedBytes: config.MaxCompressedBytes, maxDecompressedBytes: config.MaxDecompressedBytes}, nil
}

// GetUserJWT performs a fresh bootstrap on every call. The result is never
// cached or persisted by Client.
func (c *Client) GetUserJWT(ctx context.Context, sessionToken string) (AuthSession, error) {
	if c == nil || c.httpClient == nil {
		return AuthSession{}, ErrInvalidClientConfig
	}
	metadata, err := SourceMetadata(sessionToken)
	if err != nil {
		return AuthSession{}, err
	}
	normalized := metadata.APIKey
	requestBody, err := (&devinproto.GetUserJWTRequest{Metadata: metadata}).Marshal()
	if err != nil || int64(len(requestBody)) > c.maxCompressedBytes {
		return AuthSession{}, ErrResponseTooLarge
	}
	base, err := ValidateAuthOrigin()
	if err != nil {
		return AuthSession{}, err
	}
	body, err := c.postUnaryProto(ctx, base.String()+devinproto.AuthServiceGetUserJWTPath, requestBody)
	if err != nil {
		return AuthSession{}, err
	}
	var response devinproto.GetUserJWTResponse
	if err := response.Unmarshal(body); err != nil {
		return AuthSession{}, ErrMalformedResponse
	}
	if strings.TrimSpace(response.UserJWT) == "" {
		return AuthSession{}, ErrEmptyUserJWT
	}
	apiBase, err := ValidateAPIOrigin(response.CustomAPIServerURL, c.allowedHosts)
	if err != nil {
		return AuthSession{}, err
	}
	return AuthSession{UserJWT: response.UserJWT, APIBaseURL: apiBase.String(), SessionToken: normalized}, nil
}

// PrepareChatRequest performs the complete per-chat credential composition.
// It bootstraps a fresh user JWT for every invocation, validates the selected
// chat origin, and keeps the ephemeral JWT only in the returned wire request.
func (c *Client) PrepareChatRequest(ctx context.Context, sessionToken string, canonical provider.CanonicalRequest) (*devinproto.GetChatMessageRequest, *url.URL, error) {
	auth, err := c.GetUserJWT(ctx, sessionToken)
	if err != nil {
		return nil, nil, err
	}
	origin, err := ValidateAPIOrigin(auth.APIBaseURL, c.allowedHosts)
	if err != nil {
		return nil, nil, err
	}
	request, err := BuildChatRequest(canonical, auth.SessionToken, auth.UserJWT)
	if err != nil {
		return nil, nil, err
	}
	return request, origin, nil
}

func (c *Client) postUnaryProto(ctx context.Context, endpoint string, payload []byte) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, ErrMalformedResponse
	}
	request.Header.Set("Content-Type", "application/proto")
	request.Header.Set("Connect-Protocol-Version", "1")
	request.Header.Set("Accept", "*/*")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return nil, ErrRedirect
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("Devin API transport: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, classifyStatus(response.StatusCode)
	}
	compressed, err := readBounded(response.Body, c.maxCompressedBytes)
	if err != nil {
		return nil, err
	}
	return decodeUnaryBody(compressed, response.Header.Get("Content-Encoding"), c.maxDecompressedBytes)
}

func classifyStatus(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return &provider.UpstreamError{Provider: provider.Devin, Status: status, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, ReloginRequired: true, DisableAccount: true, PublicStatus: http.StatusUnauthorized, PublicCode: "authentication_required", PublicMessage: "provider authentication is required"}}
	}
	return &HTTPStatusError{StatusCode: status}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, ErrMalformedResponse
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func decodeUnaryBody(body []byte, encoding string, limit int64) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	gzipped := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		return nil, ErrMalformedResponse
	}
	if encoding != "gzip" && !gzipped {
		if int64(len(body)) > limit {
			return nil, ErrResponseTooLarge
		}
		return body, nil
	}
	source := bytes.NewReader(body)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, ErrMalformedResponse
	}
	reader.Multistream(false)
	decoded, readErr := readBounded(reader, limit)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil || source.Len() != 0 {
		return nil, ErrMalformedResponse
	}
	return decoded, nil
}
