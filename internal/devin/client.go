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
	"strconv"
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
	HTTPClient                *http.Client
	Resolver                  Resolver
	Dialer                    *net.Dialer
	AllowedChatHosts          []string
	UnaryTimeout              time.Duration
	MaxCompressedBytes        int64
	MaxDecompressedBytes      int64
	StreamIdleTimeout         time.Duration
	StreamDeadline            time.Duration
	MaxFrameCompressedBytes   int64
	MaxFrameDecompressedBytes int64
	MaxStreamBytes            int64
	MaxToolArgumentBytes      int64
	MaxNonStreamBytes         int64
}

type Client struct {
	httpClient                *http.Client
	resolver                  Resolver
	allowedHosts              []string
	timeout                   time.Duration
	maxCompressedBytes        int64
	maxDecompressedBytes      int64
	streamIdleTimeout         time.Duration
	streamDeadline            time.Duration
	maxFrameCompressedBytes   int64
	maxFrameDecompressedBytes int64
	maxStreamBytes            int64
	maxToolArgumentBytes      int64
	maxNonStreamBytes         int64
}

type AuthSession struct {
	UserJWT      string
	APIBaseURL   string
	SessionToken string
}

const (
	minUnaryTimeout                 = time.Second
	maxUnaryTimeout                 = time.Minute
	minStreamIdleTimeout            = 5 * time.Second
	maxStreamIdleTimeout            = 5 * time.Minute
	minStreamDeadline               = 30 * time.Second
	maxStreamDeadline               = 30 * time.Minute
	minUnaryCompressedBytes   int64 = 1 << 10
	maxUnaryCompressedBytes   int64 = 8 << 20
	minUnaryDecompressedBytes int64 = 1 << 10
	maxUnaryDecompressedBytes int64 = 32 << 20
	minFrameCompressedBytes   int64 = 1 << 10
	maxFrameCompressedBytes   int64 = 16 << 20
	minFrameDecompressedBytes int64 = 1 << 10
	maxFrameDecompressedBytes int64 = 64 << 20
	minStreamBytes            int64 = 1 << 20
	maxStreamBytes            int64 = 256 << 20
	minToolArgumentBytes      int64 = 1 << 10
	maxToolArgumentBytes      int64 = 16 << 20
	minNonStreamBytes         int64 = 1 << 20
	maxNonStreamBytes         int64 = 128 << 20
)

func validClientConfig(config ClientConfig) bool {
	return config.UnaryTimeout >= minUnaryTimeout && config.UnaryTimeout <= maxUnaryTimeout &&
		config.MaxCompressedBytes >= minUnaryCompressedBytes && config.MaxCompressedBytes <= maxUnaryCompressedBytes &&
		config.MaxDecompressedBytes >= minUnaryDecompressedBytes && config.MaxDecompressedBytes <= maxUnaryDecompressedBytes &&
		config.StreamIdleTimeout >= minStreamIdleTimeout && config.StreamIdleTimeout <= maxStreamIdleTimeout &&
		(config.StreamDeadline == 0 || config.StreamDeadline >= minStreamDeadline && config.StreamDeadline <= maxStreamDeadline) &&
		config.MaxFrameCompressedBytes >= minFrameCompressedBytes && config.MaxFrameCompressedBytes <= maxFrameCompressedBytes &&
		config.MaxFrameDecompressedBytes >= minFrameDecompressedBytes && config.MaxFrameDecompressedBytes <= maxFrameDecompressedBytes &&
		config.MaxStreamBytes >= minStreamBytes && config.MaxStreamBytes <= maxStreamBytes &&
		config.MaxToolArgumentBytes >= minToolArgumentBytes && config.MaxToolArgumentBytes <= maxToolArgumentBytes &&
		config.MaxNonStreamBytes >= minNonStreamBytes && config.MaxNonStreamBytes <= maxNonStreamBytes
}

func NewClient(config ClientConfig) (*Client, error) {
	if !validClientConfig(config) || len(config.AllowedChatHosts) == 0 {
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
	// Rebuild the TLS config from scratch so only safe fields survive.
	// Verification-bypass hooks/flags (InsecureSkipVerify, VerifyPeerCertificate,
	// VerifyConnection, ServerName overrides, client certs, KeyLogWriter, etc.)
	// from the injected transport are dropped unconditionally. Only the cloned
	// RootCAs are preserved so custom trust roots remain usable for TLS test
	// fixtures and production private CAs. MinVersion is pinned to TLS 1.2.
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		InsecureSkipVerify: false,
	}
	transport.Proxy = nil
	transport.DialContext = trustedDialer(resolver, dialer)
	transport.ForceAttemptHTTP2 = true
	transport.ResponseHeaderTimeout = config.UnaryTimeout
	copyClient := *base
	copyClient.Transport = transport
	copyClient.Timeout = 0
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	return &Client{httpClient: &copyClient, resolver: resolver, allowedHosts: allowed, timeout: config.UnaryTimeout, maxCompressedBytes: config.MaxCompressedBytes, maxDecompressedBytes: config.MaxDecompressedBytes, streamIdleTimeout: config.StreamIdleTimeout, streamDeadline: config.StreamDeadline, maxFrameCompressedBytes: config.MaxFrameCompressedBytes, maxFrameDecompressedBytes: config.MaxFrameDecompressedBytes, maxStreamBytes: config.MaxStreamBytes, maxToolArgumentBytes: config.MaxToolArgumentBytes, maxNonStreamBytes: config.MaxNonStreamBytes}, nil
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
		return nil, classifyStatus(response.StatusCode, response.Header, time.Now())
	}
	compressed, err := readBounded(response.Body, c.maxCompressedBytes)
	if err != nil {
		return nil, err
	}
	return decodeUnaryBody(compressed, response.Header.Get("Content-Encoding"), c.maxDecompressedBytes)
}

func classifyStatus(status int, headers http.Header, now time.Time) error {
	classification := provider.ErrorClassification{Class: provider.ClassUpstream, PublicStatus: http.StatusBadGateway, PublicCode: "provider_error", PublicMessage: "upstream provider error"}
	switch status {
	case http.StatusBadRequest, http.StatusNotFound:
		classification.Class = provider.ClassValidation
		classification.PublicStatus = http.StatusBadRequest
		classification.PublicCode = "invalid_request_error"
		classification.PublicMessage = "invalid model or request payload"
	case http.StatusUnauthorized, http.StatusForbidden:
		classification.Class = provider.ClassUnauthorized
		classification.RetryNext = true
		classification.RefreshSame = true
		classification.DisableAccount = true
		classification.ReloginRequired = true
		classification.CooldownScope = provider.CooldownAccount
		classification.PublicStatus = http.StatusUnauthorized
		classification.PublicCode = "provider_authentication_error"
		classification.PublicMessage = "provider authentication is required"
	case http.StatusTooManyRequests:
		classification.Class = provider.ClassRateLimit
		classification.RetryNext = true
		classification.CooldownScope = provider.CooldownModel
		classification.PublicStatus = http.StatusTooManyRequests
		classification.PublicCode = "rate_limit_exceeded"
		classification.PublicMessage = "all available accounts are rate limited"
		if retryAt, ok := parseRetryAfter(headers.Get("Retry-After"), now); ok {
			classification.ExplicitRetryAfter = true
			classification.RetryAfter = retryAt
			classification.Cooldown = retryAt.Sub(now)
		}
	case http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		classification.Class = provider.ClassTransient
		classification.RetryNext = true
		classification.CooldownScope = provider.CooldownModel
		classification.Cooldown = time.Minute
		classification.PublicStatus = http.StatusServiceUnavailable
		classification.PublicCode = "provider_unavailable"
	}
	return &provider.UpstreamError{Provider: provider.Devin, Status: status, Classification: classification}
}

func parseRetryAfter(value string, now time.Time) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	parsed, err := http.ParseTime(value)
	if err != nil {
		return time.Time{}, false
	}
	if parsed.Before(now) {
		parsed = now
	}
	return parsed, true
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
