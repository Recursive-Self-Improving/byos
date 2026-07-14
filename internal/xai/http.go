// Portions adapted from CLIProxyAPI/v7 internal/runtime/executor/xai_executor.go (MIT): proxy-aware xAI transport defaults.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/runtime/executor/xai_executor.go

package xai

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

type HTTPConfig struct {
	BaseURL, ClientVersion, UserAgent string
	RequestTimeout, SSEIdleTimeout    time.Duration
}
type Client struct {
	config HTTPConfig
	http   *http.Client
}

func NewClient(config HTTPConfig) *Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: config.RequestTimeout}
	return &Client{config: config, http: &http.Client{Transport: transport}}
}

// Do sends an authenticated request through the shared xAI transport and header profile.
// The caller owns the returned response body.
func (c *Client) Do(ctx context.Context, method, endpoint, token, model, accept string, body io.Reader) (*http.Response, error) {
	requestCtx := ctx
	cancel := func() {}
	if c.config.RequestTimeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, c.config.RequestTimeout)
	}
	request, err := c.newRequest(requestCtx, method, endpoint, token, model, body)
	if err != nil {
		cancel()
		return nil, err
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	response, err := c.http.Do(request)
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnClose) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}
