package devin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

const (
	DefaultBaseURL  = "https://server.codeium.com"
	defaultBaseHost = "server.codeium.com"
)

var ErrUntrustedOrigin = errors.New("devin API origin is not trusted")

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type publicResolver struct{ resolver *net.Resolver }

func (r publicResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.resolver.LookupNetIP(ctx, network, host)
}

// ValidateAuthOrigin returns the fixed production bootstrap origin. Bootstrap
// credentials are never routed through the configurable chat-host allowlist.
func ValidateAuthOrigin() (*url.URL, error) {
	return validateHTTPSOrigin(DefaultBaseURL, nil)
}

// ValidateAPIOrigin accepts the pinned production origin or a configured
// custom HTTPS DNS origin. Empty input selects the pinned production origin.
// It performs no network I/O.
func ValidateAPIOrigin(raw string, allowedHosts []string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = DefaultBaseURL
	}
	return validateHTTPSOrigin(raw, allowedHosts)
}

func validateHTTPSOrigin(raw string, allowedHosts []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, ErrUntrustedOrigin
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil || u.Port() != "" || host != defaultBaseHost && !slices.Contains(allowedHosts, host) {
		return nil, ErrUntrustedOrigin
	}
	u.Path = ""
	return u, nil
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:2::/48"),
}

func isPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func publicAddresses(ctx context.Context, resolver Resolver, host string) ([]netip.Addr, error) {
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrUntrustedOrigin
	}
	for _, address := range addresses {
		if !isPublicAddress(address) {
			return nil, ErrUntrustedOrigin
		}
	}
	return addresses, nil
}

// trustedDialer resolves on every connection and dials only an address from
// that result, preventing the transport from performing a second, unvalidated
// DNS lookup.
func trustedDialer(resolver Resolver, dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrUntrustedOrigin
		}
		addresses, err := publicAddresses(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range addresses {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			last = dialErr
		}
		return nil, fmt.Errorf("devin trusted dial failed: %w", last)
	}
}
