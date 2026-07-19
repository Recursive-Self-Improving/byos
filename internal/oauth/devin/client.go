package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultExchangeTimeout              = 15 * time.Second
	DefaultMaxExchangeCompressedBytes   = int64(2 << 20)
	DefaultMaxExchangeDecompressedBytes = int64(8 << 20)
)

type ClientConfig struct {
	HTTPClient           *http.Client
	Timeout              time.Duration
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
}

type Client struct {
	httpClient           *http.Client
	endpoint             string
	timeout              time.Duration
	maxCompressedBytes   int64
	maxDecompressedBytes int64
}

// NewClient creates a Devin token exchange client fixed to the production HTTPS
// endpoint. A supplied HTTP transport is useful for interception in tests, but
// cannot change the destination or enable redirects.
func NewClient(config ClientConfig) (*Client, error) {
	return newClient(config, ExchangeEndpoint, false)
}

func newClient(config ClientConfig, endpoint string, allowTestEndpoint bool) (*Client, error) {
	if config.Timeout == 0 {
		config.Timeout = DefaultExchangeTimeout
	}
	if config.MaxCompressedBytes == 0 {
		config.MaxCompressedBytes = DefaultMaxExchangeCompressedBytes
	}
	if config.MaxDecompressedBytes == 0 {
		config.MaxDecompressedBytes = DefaultMaxExchangeDecompressedBytes
	}
	if config.Timeout <= 0 || config.MaxCompressedBytes <= 0 || config.MaxDecompressedBytes <= 0 || !validExchangeEndpoint(endpoint, allowTestEndpoint) {
		return nil, ErrInvalidClientConfig
	}
	base := config.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	copyClient := *base
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return ErrExchangeRedirect }
	// Timeout is applied through the request context so an earlier caller
	// deadline remains authoritative and errors.Is retains its category.
	copyClient.Timeout = 0
	return &Client{httpClient: &copyClient, endpoint: endpoint, timeout: config.Timeout, maxCompressedBytes: config.MaxCompressedBytes, maxDecompressedBytes: config.MaxDecompressedBytes}, nil
}

func validExchangeEndpoint(raw string, allowTestEndpoint bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if allowTestEndpoint {
		return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.Path != ""
	}
	return parsed.Scheme == "https" && parsed.Host == "api.devin.ai" && parsed.Port() == "" && parsed.Path == "/auth/cli/token"
}

type exchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type exchangeResponse struct {
	Token json.RawMessage `json:"token"`
}

// Exchange posts a callback code and PKCE verifier and returns the opaque Devin
// token. Errors are sanitized and never include request or response secrets.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (string, error) {
	if c == nil || c.httpClient == nil || strings.TrimSpace(code) == "" || strings.TrimSpace(verifier) == "" {
		return "", protocolError(ErrExchangeProtocol)
	}
	body, err := json.Marshal(exchangeRequest{Code: code, CodeVerifier: verifier})
	if err != nil {
		return "", protocolError(ErrExchangeProtocol)
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", protocolError(ErrExchangeProtocol)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrExchangeRedirect) {
			return "", protocolError(ErrExchangeRedirect)
		}
		return "", transportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", statusError(response.StatusCode)
	}

	compressed, err := readBounded(response.Body, c.maxCompressedBytes)
	if err != nil {
		return "", err
	}
	decoded, err := decodeExchangeBody(compressed, response.Header.Get("Content-Encoding"), c.maxDecompressedBytes)
	if err != nil {
		return "", err
	}
	return parseExchangeToken(decoded)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, protocolError(ErrExchangeProtocol)
	}
	if int64(len(content)) > limit {
		return nil, protocolError(ErrExchangeTooLarge)
	}
	return content, nil
}

func decodeExchangeBody(compressed []byte, encoding string, limit int64) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		if int64(len(compressed)) > limit {
			return nil, protocolError(ErrExchangeTooLarge)
		}
		return compressed, nil
	case "gzip":
		source := bytes.NewReader(compressed)
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, protocolError(ErrExchangeEncoding)
		}
		reader.Multistream(false)
		decoded, readErr := readBounded(reader, limit)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, protocolError(ErrExchangeEncoding)
		}
		if source.Len() != 0 {
			return nil, protocolError(ErrExchangeEncoding)
		}
		return decoded, nil
	default:
		return nil, protocolError(ErrExchangeEncoding)
	}
}

func parseExchangeToken(body []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var response exchangeResponse
	if err := decoder.Decode(&response); err != nil {
		return "", protocolError(ErrExchangeProtocol)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", protocolError(ErrExchangeProtocol)
	}
	if len(response.Token) == 0 {
		return "", protocolError(ErrExchangeTokenRequired)
	}
	var token string
	if err := json.Unmarshal(response.Token, &token); err != nil || strings.TrimSpace(token) == "" {
		return "", protocolError(ErrExchangeTokenRequired)
	}
	return token, nil
}
