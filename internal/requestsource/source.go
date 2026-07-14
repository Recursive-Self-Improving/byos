package requestsource

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	maxForwardedForBytes = 4096
	maxForwardedForHops  = 32
)

// TrustedProxies is an allowlist of network peers permitted to assert transport
// security and the original client address.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

func ParseTrustedProxies(values []string) (TrustedProxies, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return TrustedProxies{}, errors.New("trusted proxy entry cannot be blank")
		}
		if address, err := netip.ParseAddr(value); err == nil {
			address = address.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q", value)
		}
		address := prefix.Addr().Unmap()
		bits := prefix.Bits()
		if address.Is4() && bits > 32 {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q", value)
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, bits).Masked())
	}
	return TrustedProxies{prefixes: prefixes}, nil
}

func (p TrustedProxies) RequestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, ok := remoteAddress(r.RemoteAddr)
	if !ok || !p.contains(peer) {
		return false
	}
	values := r.Header.Values("X-Forwarded-Proto")
	if len(values) == 0 {
		return false
	}
	parts := strings.Split(values[len(values)-1], ",")
	return strings.EqualFold(strings.TrimSpace(parts[len(parts)-1]), "https")
}

// ClientIP returns the canonical client address. Forwarded addresses are used
// only when the immediate peer is trusted, and malformed trusted chains fail
// closed instead of collapsing all clients into the proxy's bucket.
func (p TrustedProxies) ClientIP(r *http.Request) (netip.Addr, error) {
	peer, ok := remoteAddress(r.RemoteAddr)
	if !ok {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	if !p.contains(peer) {
		return peer, nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer, nil
	}
	bytes := 0
	chain := make([]netip.Addr, 0, len(values)+1)
	for _, value := range values {
		bytes += len(value)
		if bytes > maxForwardedForBytes {
			return netip.Addr{}, errors.New("forwarded client chain is too large")
		}
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || len(chain) >= maxForwardedForHops {
				return netip.Addr{}, errors.New("invalid forwarded client chain")
			}
			address, err := netip.ParseAddr(part)
			if err != nil || address.Zone() != "" {
				return netip.Addr{}, errors.New("invalid forwarded client address")
			}
			chain = append(chain, address.Unmap())
		}
	}
	chain = append(chain, peer)
	for i := len(chain) - 1; i >= 0; i-- {
		if !p.contains(chain[i]) {
			return chain[i], nil
		}
	}
	return chain[0], nil
}

func (p TrustedProxies) contains(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range p.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func remoteAddress(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = strings.Trim(value, "[]")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}
