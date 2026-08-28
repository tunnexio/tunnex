package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var blockedOAuthPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func newOAuthHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = oauthDialContext
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if !validOAuthRequestURL(req.URL) {
				return ErrMetadata
			}
			return nil
		},
	}
}

func oauthDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid OAuth peer address: %w", err)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve OAuth peer: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("OAuth peer resolved no addresses")
	}
	for _, candidate := range addresses {
		if !allowedOAuthAddress(candidate) {
			return nil, fmt.Errorf("OAuth peer resolved a non-public address: %s", candidate)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, candidate := range addresses {
		if network == "tcp4" && !candidate.Is4() || network == "tcp6" && !candidate.Is6() {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("OAuth peer has no address for requested network")
	}
	return nil, lastErr
}

func allowedOAuthAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedOAuthPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validOAuthRequestURL(u *url.URL) bool {
	if u == nil || !validURL(u.String()) {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil && !allowedOAuthAddress(address) {
		return false
	}
	return true
}

func sameOrigin(left, right string) bool {
	a, errA := url.Parse(left)
	b, errB := url.Parse(right)
	return errA == nil && errB == nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (s *Service) doOAuthRequest(req *http.Request) (*http.Response, error) {
	if s == nil || s.http == nil || req == nil || !validURL(req.URL.String()) {
		return nil, ErrMetadata
	}
	// The production client disables proxies and validates every resolved address before dialing it.
	// Tests may inject a loopback-only client for deterministic protocol coverage.
	// codeql[go/request-forgery]
	return s.http.Do(req)
}
