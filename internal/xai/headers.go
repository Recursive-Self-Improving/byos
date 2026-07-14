// Portions adapted from CLIProxyAPI/v7 internal/runtime/executor/xai_executor.go (MIT): xAI request headers and endpoint construction.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/runtime/executor/xai_executor.go

package xai

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (c *Client) newRequest(ctx context.Context, method, endpoint, token, model string, body io.Reader) (*http.Request, error) {
	base, err := url.Parse(strings.TrimRight(c.config.BaseURL, "/"))
	if err != nil {
		return nil, err
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	joined := path.Join(base.Path, parsedEndpoint.Path)
	base.Path = joined
	base.RawQuery = parsedEndpoint.RawQuery
	request, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	request.Header.Set("x-grok-client-version", c.config.ClientVersion)
	if model != "" {
		request.Header.Set("x-grok-model-override", model)
	}
	request.Header.Set("User-Agent", c.config.UserAgent)
	return request, nil
}
