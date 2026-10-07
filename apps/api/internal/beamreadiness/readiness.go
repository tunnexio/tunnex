// Package beamreadiness measures deployment endpoints without changing authority.
package beamreadiness

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

type Config struct {
	BaseDomain, ProxyURL, PortalURL string
	Asserted                        bool
	ConnectorCA                     []byte
	ProbeFingerprint                string
}
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}
type View struct {
	SettingsVersion      int64      `json:"settings_version"`
	BaseDomain           string     `json:"base_domain"`
	ProxyURL             string     `json:"proxy_url"`
	PortalURL            string     `json:"portal_url"`
	ConfigurationVersion string     `json:"configuration_version"`
	OperatorAsserted     bool       `json:"operator_asserted"`
	CheckedAt            *time.Time `json:"checked_at"`
	ExpiresAt            *time.Time `json:"expires_at"`
	Passed               bool       `json:"passed"`
	Checks               []Check    `json:"checks"`
}

func Version(c Config) string {
	h := sha256.Sum256([]byte(c.BaseDomain + "\x00" + c.ProxyURL + "\x00" + c.PortalURL + "\x00" + strconv.FormatBool(c.Asserted) + "\x00" + string(c.ConnectorCA) + "\x00" + c.ProbeFingerprint))
	return hex.EncodeToString(h[:])
}
func Snapshot(c Config) View {
	base := c.BaseDomain
	if base != "" && !appdomains.Host(base) {
		base = "Invalid serving domain"
	}
	return View{BaseDomain: base, ProxyURL: safeEndpoint(c.ProxyURL), PortalURL: safeEndpoint(c.PortalURL), ConfigurationVersion: Version(c), OperatorAsserted: c.Asserted, Checks: []Check{}}
}
func safeEndpoint(raw string) string {
	if raw == "" {
		return ""
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, "\\\r\n\t ") {
		return "Invalid HTTPS endpoint (details withheld)"
	}
	return raw
}

// Inspector serializes network work and only probes the server's configuration.
// No URL, host, port or trust anchor can be supplied by an API caller.
type Inspector struct {
	mu            sync.Mutex
	last          View
	running       bool
	lookup        func(context.Context, string) ([]net.IPAddr, error)
	roots         *x509.CertPool
	dial          func(context.Context, string, string) (net.Conn, error)
	allowLoopback bool
	fingerprint   string
}

func New() *Inspector {
	return &Inspector{lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
}

// NewConfigured is only for an explicitly enabled development fixture. TLS chain,
// hostname, expiry and purpose verification remain mandatory. No API input can
// select this mode or change its fixed trust roots.
func NewConfigured(allowDevelopmentLoopback bool, fixedPublicCAPEM []byte) (*Inspector, error) {
	p := New()
	p.allowLoopback = allowDevelopmentLoopback
	if len(fixedPublicCAPEM) > 0 {
		if !allowDevelopmentLoopback || len(fixedPublicCAPEM) > 65536 {
			return nil, errors.New("development public trust requires explicit development loopback mode and bounded CA PEM")
		}
		roots, e := x509.SystemCertPool()
		if e != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		rest := fixedPublicCAPEM
		count := 0
		for len(strings.TrimSpace(string(rest))) > 0 {
			block, left := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("development public trust must contain only PEM CA certificates")
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil || !cert.IsCA || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
				return nil, errors.New("development public trust must contain currently valid CA certificates")
			}
			roots.AddCert(cert)
			rest = left
			count++
		}
		if count == 0 {
			return nil, errors.New("development public trust is empty")
		}
		p.roots = roots
	}
	h := sha256.Sum256(append([]byte(strconv.FormatBool(allowDevelopmentLoopback)+"\x00"), fixedPublicCAPEM...))
	p.fingerprint = hex.EncodeToString(h[:])
	return p, nil
}
func (p *Inspector) ProbeFingerprint() string { return p.fingerprint }
func (p *Inspector) Get(c Config) View {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last.ConfigurationVersion == Version(c) {
		v := p.last
		v.Checks = append([]Check{}, v.Checks...)
		if v.ExpiresAt != nil && !v.ExpiresAt.After(time.Now()) {
			v.Passed = false
		}
		return v
	}
	return Snapshot(c)
}

// Check returns cached evidence during a 20 second cooldown and rejects overlap.
func (p *Inspector) Check(ctx context.Context, c Config, expected string) (View, string) {
	if expected != Version(c) {
		return Snapshot(c), "stale"
	}
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return Snapshot(c), "busy"
	}
	if p.last.ConfigurationVersion == expected && p.last.CheckedAt != nil && time.Since(*p.last.CheckedAt) < 20*time.Second {
		v := p.last
		p.mu.Unlock()
		return v, ""
	}
	p.running = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.running = false; p.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	v := p.probe(ctx, c)
	p.mu.Lock()
	p.last = v
	p.mu.Unlock()
	return v, ""
}
func (p *Inspector) probe(ctx context.Context, c Config) View {
	v := Snapshot(c)
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	v.CheckedAt = &now
	v.ExpiresAt = &until
	add := func(name string, passed bool, detail string) {
		v.Checks = append(v.Checks, Check{name, passed, detail})
	}
	u, e := url.Parse(c.ProxyURL)
	_, boundary := appdomains.Normalize(appdomains.Config{PortalURL: c.PortalURL, AppBaseDomain: c.BaseDomain})
	valid := e == nil && boundary == nil && len(c.BaseDomain) <= 218 && u.Scheme == "https" && u.User == nil && u.Host != "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && (u.Path == "" || u.Path == "/") && !strings.ContainsAny(c.ProxyURL, "\\\r\n\t ")
	if valid {
		h := u.Hostname()
		valid = appdomains.Host(h) || net.ParseIP(h) != nil
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			valid = valid && err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port
		}
	}
	add("configuration", valid, "Use a valid dedicated serving domain, HTTPS portal and connector URL; unsafe sibling console domains are prohibited.")
	if !valid {
		return v
	}
	// Two unpredictable names distinguish wildcard DNS from an existing single record.
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		add("wildcard_dns", false, "Could not generate independent DNS samples.")
		return v
	}
	a := "p-" + hex.EncodeToString(random[:16]) + "." + c.BaseDomain
	b := "p-" + hex.EncodeToString(random[16:]) + "." + c.BaseDomain
	ipsA, errA := p.resolve(ctx, a)
	ipsB, errB := p.resolve(ctx, b)
	dns := errA == nil && errB == nil && len(ipsA) > 0 && len(ipsB) > 0
	add("wildcard_dns", dns, "Both independent random serving hostnames must resolve to safe routable addresses.")
	if dns {
		// Pin the verified DNS result, preserving exact SNI and Host. Never follow redirects.
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return p.dial(ctx, network, net.JoinHostPort(ipsA[0], "443"))
		}, ResponseHeaderTimeout: 2 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 16384}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+a+"/", nil)
		response, err := client.Do(req)
		coverage := false
		if response != nil && response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
			for _, chain := range response.TLS.VerifiedChains {
				for _, cert := range chain {
					if cert.NotAfter.Before(until) {
						until = cert.NotAfter
						v.ExpiresAt = &until
					}
				}
			}
			for _, name := range response.TLS.PeerCertificates[0].DNSNames {
				coverage = coverage || name == "*."+c.BaseDomain
			}
		}
		add("wildcard_tls", err == nil && coverage, "The serving edge must present a currently valid trusted certificate covering the configured wildcard domain.")
		denied := false
		if response != nil {
			denied = (response.StatusCode == 403 || response.StatusCode == 404 || response.StatusCode == 421) && response.Header.Get("Location") == "" && len(response.Header.Values("Set-Cookie")) == 0
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		add("unknown_host_denied", err == nil && denied, "An unallocated serving hostname must return 403, 404 or 421 without redirects, cookies or app content.")
	} else {
		add("wildcard_tls", false, "Fix wildcard DNS before HTTPS can be checked.")
		add("unknown_host_denied", false, "Fix wildcard DNS before exact-host denial can be checked.")
	}
	ips, err := p.resolve(ctx, u.Hostname())
	connector := false
	roots := x509.NewCertPool()
	trust := len(c.ConnectorCA) > 0 && roots.AppendCertsFromPEM(c.ConnectorCA)
	if err == nil && len(ips) > 0 && trust {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		conn, e := p.dial(ctx, "tcp", net.JoinHostPort(ips[0], port))
		if e == nil {
			tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "tunnex-beam-proxy"})
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			connector = tlsConn.HandshakeContext(bounded) == nil
			if connector {
				for _, chain := range tlsConn.ConnectionState().VerifiedChains {
					for _, cert := range chain {
						if cert.NotAfter.Before(until) {
							until = cert.NotAfter
							v.ExpiresAt = &until
						}
					}
				}
			}
			cancel()
			tlsConn.Close()
		}
	}
	add("connector_tls", connector, "The connector must be reachable and present a valid TLS 1.3 tunnex-beam-proxy purpose certificate trusted by the installation connector CA. No connector client credential is sent.")
	v.Passed = true
	for _, check := range v.Checks {
		v.Passed = v.Passed && check.Passed
	}
	return v
}
func (p *Inspector) resolve(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	ips, err := p.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	out := []string{}
	seen := map[string]bool{}
	for _, entry := range ips {
		ip := entry.IP
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || (!p.allowLoopback && ip.IsLoopback()) {
			continue
		}
		s := ip.String()
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
		if len(out) >= 8 {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}
