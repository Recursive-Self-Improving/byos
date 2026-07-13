package xai

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (c *Client) newRequest(method, endpoint, token, model string, body io.Reader) (*http.Request, error) {
	base, err := url.Parse(strings.TrimRight(c.config.BaseURL, "/"))
	if err != nil {
		return nil, err
	}
	base.Path = path.Join(base.Path, endpoint)
	request, err := http.NewRequest(method, base.String(), body)
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
