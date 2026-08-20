// Package safedial constructs the only HTTP client F11 may use for an
// operator-configured destination. It resolves before dialing, then dials the
// verified IP literal so a DNS rebind cannot replace the checked address.
package safedial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultTimeout   = 10 * time.Second
	DefaultBodyLimit = 64 << 10
)

var (
	ErrUnsafeDestination = errors.New("unsafe alert destination")
	ErrDestinationDNS    = errors.New("alert destination DNS failure")
	ErrResponseTooLarge  = errors.New("alert destination response exceeds limit")
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type DialContext func(context.Context, string, string) (net.Conn, error)

type Options struct {
	AllowPrivate bool
	Resolver     Resolver
	DialContext  DialContext
	Timeout      time.Duration
}

// NewClient returns a client with no redirect path. A redirect is a second
// untrusted URL; following it would bypass the endpoint that was validated.
func NewClient(options Options) *http.Client {
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := options.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // proxy environment variables must not route control-plane alerts.
	transport.DialContext = resolvingDialer(resolver, dial, options.AllowPrivate)
	return &http.Client{
		Transport: safeTransport{base: transport, allowPrivate: options.AllowPrivate},
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirects are not permitted", ErrUnsafeDestination)
		},
	}
}

type safeTransport struct {
	base         http.RoundTripper
	allowPrivate bool
}

func (t safeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, fmt.Errorf("%w: invalid request", ErrUnsafeDestination)
	}
	if _, err := ValidateURL(request.URL.String(), t.allowPrivate); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(request)
}

// ValidateURL rejects a scheme downgrade before a caller can construct a
// request. Private targets are allowed only by the explicit owner-controlled
// escape hatch, which is also the only mode allowing plain HTTP for an
// on-premises receiver.
func ValidateURL(raw string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid URL", ErrUnsafeDestination)
	}
	if u.Scheme != "https" && !(allowPrivate && u.Scheme == "http") {
		return nil, fmt.Errorf("%w: HTTPS is required", ErrUnsafeDestination)
	}
	if u.Port() != "" {
		if _, err := net.LookupPort("tcp", u.Port()); err != nil {
			return nil, fmt.Errorf("%w: invalid port", ErrUnsafeDestination)
		}
	}
	return u, nil
}

// ReadBody caps diagnostic bodies. A provider cannot make a failed test-send
// retain an unbounded response in memory or in its delivery history.
func ReadBody(response *http.Response, limit int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = DefaultBodyLimit
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return body[:limit], ErrResponseTooLarge
	}
	return body, nil
}

func resolvingDialer(resolver Resolver, dial DialContext, allowPrivate bool) DialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid dial address", ErrUnsafeDestination)
		}
		addrs, err := resolve(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if !allowPrivate && blocked(addr) {
				return nil, fmt.Errorf("%w: %s is not an allowed target", ErrUnsafeDestination, addr)
			}
		}
		// Dial the checked literal, never the source hostname. This is the DNS
		// rebinding guard; TLS still receives the original request hostname as SNI.
		return dial(ctx, network, net.JoinHostPort(addrs[0].String(), port))
	}
}

func resolve(ctx context.Context, resolver Resolver, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{literal.Unmap()}, nil
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			return nil, fmt.Errorf("%w: resolve destination: %w", ErrDestinationDNS, err)
		}
		return nil, fmt.Errorf("%w: resolve destination", ErrDestinationDNS)
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

func blocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsPrivate() {
		return true
	}
	// CGNAT is not considered private by netip but is never an internet webhook target.
	return addr.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

// Host returns a normalized display-only hostname. It is never an authority to
// dial; the dialer independently resolves and validates it for every request.
func Host(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Hostname() == "" {
		return "", fmt.Errorf("%w: invalid URL", ErrUnsafeDestination)
	}
	return strings.ToLower(u.Hostname()), nil
}
