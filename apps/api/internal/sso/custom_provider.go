package sso

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func ValidateCustomIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("issuer must be a public HTTPS URL without credentials, query, fragment or custom port")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return errors.New("private issuer hosts are not supported")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !publicOIDCAddress(ip) {
		return errors.New("private issuer addresses are not supported")
	}
	return nil
}
func publicOIDCAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve and pin every dial to a checked public IP. No proxies or redirects can
// route discovery, token exchange or JWKS retrieval around this boundary.
func customHTTPClient() *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" {
			return nil, errors.New("OIDC endpoint requires HTTPS port 443")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("issuer has no addresses")
		}
		for _, ip := range ips {
			if !publicOIDCAddress(ip) {
				return nil, errors.New("OIDC endpoint resolves to a non-public address")
			}
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &http.Client{Transport: httpsOnlyTransport{transport}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects are not supported") }}
}

type httpsOnlyTransport struct{ base http.RoundTripper }

func (t httpsOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errors.New("OIDC endpoints require HTTPS")
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedOIDCBody{Reader: io.LimitReader(resp.Body, 1<<20), Closer: resp.Body}
	return resp, nil
}
func customNormalizer(r RawClaims) (Identity, error) {
	if strings.TrimSpace(r.Sub) == "" || len(r.Sub) > 255 || strings.TrimSpace(r.Email) == "" || !r.EmailVerified {
		return Identity{}, errors.New("custom OIDC requires subject and verified email")
	}
	return Identity{Subject: r.Sub, Email: r.Email, EmailVerified: true, Name: r.Name}, nil
}
func NewCustomProvider(ctx context.Context, issuer, clientID, secret, callback string) (Provider, error) {
	if err := ValidateCustomIssuer(issuer); err != nil {
		return nil, err
	}
	return newCustomProviderWithClient(ctx, issuer, clientID, secret, callback, customHTTPClient())
}

// Client injection is an internal test seam, never an environment configuration.
func newCustomProviderWithClient(ctx context.Context, issuer, clientID, secret, callback string, client *http.Client) (Provider, error) {
	ctx = oidc.ClientContext(ctx, client)
	p, err := NewOIDCProvider(ctx, "oidc", issuer, clientID, secret, callback, []string{"openid", "email", "profile"}, customNormalizer)
	if err != nil {
		return nil, err
	}
	// Validate the browser-facing authorization endpoint as well. Query parameters
	// added by AuthCodeURL are not part of the endpoint validation.
	if u, e := url.Parse(p.AuthCodeURL("", "", "")); e != nil {
		return nil, e
	} else if client != nil && issuerHasHTTPS(issuer) {
		u.RawQuery = ""
		if e = ValidateCustomIssuer(u.String()); e != nil {
			return nil, e
		}
	}
	// Retain the restricted HTTP client for code exchange, not only discovery.
	return &customProvider{Provider: p, client: client}, nil
}

type customProvider struct {
	Provider
	client *http.Client
}

func (p *customProvider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	return p.Provider.Exchange(oidc.ClientContext(ctx, p.client), code, verifier, nonce)
}

type boundedOIDCBody struct {
	io.Reader
	io.Closer
}

func issuerHasHTTPS(issuer string) bool { return strings.HasPrefix(issuer, "https://") }
