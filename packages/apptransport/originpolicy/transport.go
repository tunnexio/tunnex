package originpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Transport forwards streaming requests only to one registered root origin.
// Resolution is repeated per request and every answer is checked before dialing.
// Request paths and Host never grant destination authority.
type Transport struct {
	Checker Checker
	Origin  string
	Policy  Policy
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	refused := errors.New("application origin refused")
	p, err := Normalize(t.Policy.AllowedDestinationCIDRs, t.Policy.OriginCAPEM)
	if err != nil || p.OriginCADigest != t.Policy.OriginCADigest {
		return nil, refused
	}
	u, err := url.Parse(t.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(t.Origin, "#") || strings.Contains(u.Hostname(), "%") {
		return nil, refused
	}
	for _, h := range t.Checker.ControlHosts {
		if strings.EqualFold(strings.TrimSuffix(h, "."), strings.TrimSuffix(u.Hostname(), ".")) {
			return nil, refused
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, refused
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		ips = []netip.Addr{ip}
	} else {
		lookup := t.Checker.Lookup
		if lookup == nil {
			resolver := t.Checker.Resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			lookup = func(c context.Context, h string) ([]netip.Addr, error) { return resolver.LookupNetIP(c, "ip", h) }
		}
		ips, err = lookup(ctx, u.Hostname())
	}
	cancel()
	if err != nil || len(ips) == 0 || len(ips) > 64 {
		return nil, refused
	}
	controls := append([]netip.Addr(nil), t.Checker.ControlAddresses...)
	controlCtx, controlCancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer controlCancel()
	for _, host := range t.Checker.ControlHosts {
		if ip, e := netip.ParseAddr(host); e == nil {
			controls = append(controls, ip)
			continue
		}
		lookup := t.Checker.Lookup
		if lookup == nil {
			resolver := t.Checker.Resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			lookup = func(c context.Context, h string) ([]netip.Addr, error) { return resolver.LookupNetIP(c, "ip", h) }
		}
		addresses, e := lookup(controlCtx, host)
		if e != nil || len(addresses) == 0 || len(addresses) > 64 {
			return nil, refused
		}
		controls = append(controls, addresses...)
	}
	for _, ip := range ips {
		if p.Validate(ip, controls) != nil {
			return nil, refused
		}
	}
	var roots *x509.CertPool
	if p.OriginCAPEM != "" {
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(p.OriginCAPEM)) {
			return nil, refused
		}
	}
	dial := t.Checker.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}}
	tr.DialContext = func(c context.Context, _, _ string) (net.Conn, error) {
		c, stop := context.WithTimeout(c, 5*time.Second)
		defer stop()
		var last error
		for _, ip := range ips {
			conn, e := dial(c, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
			if c.Err() != nil {
				break
			}
		}
		return nil, last
	}
	outbound := request.Clone(request.Context())
	// Only the registered origin grants destination authority. Copy the browser's
	// path/query explicitly, never its URL authority, userinfo or opaque form.
	outbound.URL = &url.URL{
		Scheme: u.Scheme, Host: u.Host,
		Path: request.URL.Path, RawPath: request.URL.RawPath,
		RawQuery: request.URL.RawQuery, ForceQuery: request.URL.ForceQuery,
	}
	outbound.Host = u.Host
	outbound.RequestURI = ""
	response, err := tr.RoundTrip(outbound)
	// Keep-alive is disabled; streaming and upgraded bodies own their connection.
	tr.CloseIdleConnections()
	return response, err
}
