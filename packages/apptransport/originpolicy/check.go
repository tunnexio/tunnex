package originpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Result intentionally contains no body, headers, cookies, destination addresses
// or underlying error strings. Status is suitable for bounded control reports.
type Result struct {
	Status     string    `json:"status"`
	DNS        string    `json:"dns"`
	Connect    string    `json:"connect"`
	TLS        string    `json:"tls"`
	HTTPStatus int       `json:"http_status,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
type Checker struct {
	// Resolver observes the gateway's local DNS context; nil uses net.DefaultResolver.
	Resolver         *net.Resolver
	ControlAddresses []netip.Addr
	ControlHosts     []string
	// Test seams never change destination validation or TLS verification.
	Lookup func(context.Context, string) ([]netip.Addr, error)
	Dial   func(context.Context, string, string) (net.Conn, error)
}

func (c Checker) Check(ctx context.Context, origin string, policy Policy) Result {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := Result{Status: "origin_refused", DNS: "not_checked", Connect: "not_checked", TLS: "not_checked", ObservedAt: time.Now().UTC()}
	canonical, e := Normalize(policy.AllowedDestinationCIDRs, policy.OriginCAPEM)
	if e != nil || canonical.OriginCADigest != policy.OriginCADigest {
		return out
	}
	u, e := url.Parse(origin)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || strings.Contains(origin, "#") || u.Fragment != "" || strings.Contains(u.Hostname(), "%") {
		return out
	}
	for _, host := range c.ControlHosts {
		if strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(host, ".")) {
			return out
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
		return out
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		ips = []netip.Addr{ip}
	} else {
		lookup := c.Lookup
		if lookup == nil {
			resolver := c.Resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return resolver.LookupNetIP(ctx, "ip", host)
			}
		}
		ips, e = lookup(ctx, u.Hostname())
		if e != nil {
			out.Status = "dns_refused"
			out.DNS = "failed"
			return cancelledResult(ctx, out)
		}
	}
	if len(ips) == 0 || len(ips) > 64 {
		out.Status = "dns_refused"
		out.DNS = "failed"
		return out
	}
	for _, ip := range ips {
		if canonical.Validate(ip, c.ControlAddresses) != nil {
			out.Status = "dns_refused"
			out.DNS = "refused"
			return out
		}
	}
	out.DNS = "ready"
	out.Status = "unreachable"
	var roots *x509.CertPool
	if canonical.OriginCAPEM != "" {
		roots, e = x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(canonical.OriginCAPEM)) {
			return out
		}
	}
	dial := c.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		dial = dialer.DialContext
	}
	var connectStage, tlsStage atomic.Int32
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots}}
	tr.DialContext = func(dctx context.Context, network, address string) (net.Conn, error) {
		var last error
		for _, ip := range ips {
			conn, err := dial(dctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				connectStage.Store(1)
				return conn, nil
			}
			last = err
			if dctx.Err() != nil {
				break
			}
		}
		connectStage.Store(2)
		return nil, last
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return out
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
		if err != nil {
			tlsStage.Store(2)
		} else {
			tlsStage.Store(1)
		}
	}}))
	resp, e := client.Do(req)
	if connectStage.Load() == 1 {
		out.Connect = "ready"
	} else if connectStage.Load() == 2 {
		out.Connect = "failed"
	}
	if tlsStage.Load() == 1 {
		out.TLS = "ready"
	} else if tlsStage.Load() == 2 {
		out.TLS = "failed"
	}
	if e != nil {
		if u.Scheme == "https" && out.TLS == "failed" {
			out.Status = "tls_refused"
			out.TLS = "failed"
		}
		if out.Connect == "ready" && out.TLS != "failed" {
			out.Status = "http_failed"
		}
		return cancelledResult(ctx, out)
	}
	defer resp.Body.Close()
	if u.Scheme == "https" {
		out.TLS = "ready"
	} else {
		out.TLS = "not_required"
	}
	out.HTTPStatus = resp.StatusCode
	// Never buffer the body. Stop after 64KiB even if the origin keeps streaming.
	_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if e != nil {
		out.Status = "http_failed"
		return cancelledResult(ctx, out)
	}
	out.Status = "ready"
	return out
}
func cancelledResult(ctx context.Context, r Result) Result {
	if ctx.Err() == context.DeadlineExceeded {
		r.Status = "timeout"
	} else if ctx.Err() != nil {
		r.Status = "cancelled"
	}
	return r
}
