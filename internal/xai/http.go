package xai

import (
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
