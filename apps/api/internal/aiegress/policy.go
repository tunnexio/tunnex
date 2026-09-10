// Package aiegress confines custom-provider CONNECT tunnels to operator-approved destinations.
package aiegress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrDenied = errors.New("custom endpoint denied")

type Endpoint struct {
	Provider     string   `json:"provider,omitempty"`
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
}
type Policy struct {
	PublicHTTPS    bool       `json:"public_https"`
	Endpoints      []Endpoint `json:"endpoints"`
	ProtectedHosts []string   `json:"protected_hosts"`
	DeniedCIDRs    []string   `json:"denied_cidrs"`
	rules          map[string][]netip.Prefix
	denied         []netip.Prefix
}

func NormalizeEndpoint(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(raw, "%\\\r\n\t ") {
		return "", ErrDenied
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "/@") {
		return "", ErrDenied
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", ErrDenied
		}
	}
	path := strings.TrimRight(u.Path, "/")
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." || part == "v1" {
			return "", ErrDenied
		}
	}
	if strings.Contains(path, "//") {
		return "", ErrDenied
	}
	u.Path = path
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u.String(), nil
}

// FoundryEndpoint recognizes the Azure OpenAI v1 and Anthropic Messages surfaces. The
// common endpoint normalizer stores the base without the transport's /v1 suffix.
func FoundryEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") || (u.Path != "/openai" && u.Path != "/anthropic") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	host := u.Hostname()
	for _, suffix := range []string{".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com"} {
		if strings.HasSuffix(host, suffix) {
			resource := strings.TrimSuffix(host, suffix)
			if len(resource) < 1 || len(resource) > 63 || resource[0] == '-' || resource[len(resource)-1] == '-' {
				return false
			}
			for _, c := range resource {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
			return true
		}
	}
	return false
}
func target(raw string) string {
	u, _ := url.Parse(raw)
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
func LoadPolicy(path string) (*Policy, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	var p Policy
	if d.Decode(&p) != nil {
		return nil, ErrDenied
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrDenied
	}
	if e = p.validate(); e != nil {
		return nil, e
	}
	return &p, nil
}
func (p *Policy) validate() error {
	p.rules = nil
	p.denied = nil
	if (len(p.Endpoints) == 0 && !p.PublicHTTPS) || len(p.Endpoints) > 64 || len(p.ProtectedHosts) == 0 || len(p.ProtectedHosts) > 128 || len(p.DeniedCIDRs) > 128 {
		return ErrDenied
	}
	rules := map[string][]netip.Prefix{}
	seen := map[string]bool{}
	authorityCIDRs := map[string][]string{}
	parse := func(raw string) (netip.Prefix, error) {
		v, e := netip.ParsePrefix(raw)
		if e != nil || v != v.Masked() || v.Addr().Is4In6() {
			return netip.Prefix{}, ErrDenied
		}
		return v, nil
	}
	for _, raw := range p.DeniedCIDRs {
		v, e := parse(raw)
		if e != nil {
			return e
		}
		p.denied = append(p.denied, v)
	}
	for i := range p.Endpoints {
		ep := &p.Endpoints[i]
		if ep.Provider == "" {
			ep.Provider = "custom"
		}
		if ep.Provider != "custom" && ep.Provider != "sagemaker" && ep.Provider != "azure_foundry" {
			return ErrDenied
		}
		u, e := NormalizeEndpoint(ep.URL)
		if e != nil || (ep.Provider == "azure_foundry" && !FoundryEndpoint(u)) || ep.Name == "" || len(ep.Name) > 100 || seen[u] || len(ep.AllowedCIDRs) == 0 || len(ep.AllowedCIDRs) > 64 {
			return ErrDenied
		}
		ep.URL = u
		seen[u] = true
		authority := target(u)
		sorted := slices.Clone(ep.AllowedCIDRs)
		slices.Sort(sorted)
		if previous, exists := authorityCIDRs[authority]; exists && !slices.Equal(previous, sorted) {
			return ErrDenied
		}
		authorityCIDRs[authority] = sorted
		for _, raw := range ep.AllowedCIDRs {
			v, e := parse(raw)
			if e != nil {
				return e
			}
			rules[authority] = append(rules[authority], v)
		}
	}
	for _, host := range p.ProtectedHosts {
		if host == "" || strings.ContainsAny(host, "/ @\r\n\t") {
			return ErrDenied
		}
	}
	p.rules = rules
	return nil
}
func (p *Policy) AllowsEndpoint(raw string) bool {
	if p == nil || p.rules == nil {
		return false
	}
	normalized, e := NormalizeEndpoint(raw)
	if e != nil {
		return false
	}
	for _, ep := range p.Endpoints {
		if ep.URL == normalized {
			return true
		}
	}
	return p.AllowsPublicEndpoint(normalized)
}

// AllowsPublicEndpoint permits only validated public HTTPS policy fallback.
// Any explicit authority reserves all its paths for exact endpoint rules.
// DNS and local/protected address checks are repeated by the proxy before dial.
func (p *Policy) AllowsPublicEndpoint(raw string) bool {
	if !p.PublicEndpointsEnabled() {
		return false
	}
	normalized, err := NormalizeEndpoint(raw)
	if err != nil {
		return false
	}
	u, _ := url.Parse(normalized)
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	if _, explicit := p.rules[target(normalized)]; explicit {
		return false
	}
	return p.publicHost(u.Hostname())
}

// PublicEndpointsEnabled reports successfully validated opt-in public egress.
func (p *Policy) PublicEndpointsEnabled() bool {
	return p != nil && p.PublicHTTPS && p.rules != nil
}

func (p *Policy) publicHost(host string) bool {
	for _, protected := range p.ProtectedHosts {
		if strings.EqualFold(host, protected) {
			return false
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return publicAddress(ip)
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	host = strings.ToLower(host)
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Conservative public unicast scope excludes special-use, documentation,
// benchmarking and transition ranges in addition to metadata/local addresses.
var nonpublicRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
}

func publicAddress(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if blocked(ip) || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range nonpublicRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.Is4() {
		a := ip.As4()
		return a[0] == 0 || a[0] >= 240 || a == [4]byte{168, 63, 129, 16} || a == [4]byte{100, 100, 100, 200}
	}
	if ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("fd20:ce::254") {
		return true
	}
	b := ip.As16()
	return b[0] == 0x20 && b[1] == 0x02 || b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b
}

// Resolve once, reject the complete mixed answer before dialing any address.
func (p *Policy) addresses(ctx context.Context, authority string, lookup func(context.Context, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	if p == nil || p.rules == nil {
		return nil, ErrDenied
	}
	host, port, e := net.SplitHostPort(authority)
	canonical := net.JoinHostPort(strings.ToLower(host), port)
	rules, explicit := p.rules[canonical]
	if e != nil || (!explicit && (!p.PublicHTTPS || port != "443" || !p.publicHost(host))) {
		return nil, ErrDenied
	}
	protected := map[netip.Addr]bool{}
	interfaces, e := net.InterfaceAddrs()
	if e != nil {
		return nil, ErrDenied
	}
	for _, v := range interfaces {
		prefix, e := netip.ParsePrefix(v.String())
		if e == nil {
			protected[prefix.Addr().Unmap()] = true
		}
	}
	for _, name := range p.ProtectedHosts {
		if strings.EqualFold(host, name) {
			return nil, ErrDenied
		}
		ips, e := lookup(ctx, name)
		if e != nil || len(ips) == 0 {
			return nil, ErrDenied
		}
		for _, ip := range ips {
			protected[ip.Unmap()] = true
		}
	}
	ips, e := lookup(ctx, host)
	if e != nil || len(ips) == 0 || len(ips) > 64 {
		return nil, ErrDenied
	}
	for _, v := range ips {
		ip := v.Unmap()
		if blocked(ip) || protected[ip] || (!explicit && !publicAddress(ip)) {
			return nil, ErrDenied
		}
		for _, deny := range p.denied {
			if deny.Contains(ip) {
				return nil, ErrDenied
			}
		}
		allowed := !explicit
		for _, rule := range rules {
			if rule.Contains(ip) {
				allowed = true
			}
		}
		if !allowed {
			return nil, ErrDenied
		}
	}
	return ips, nil
}
func (p *Policy) dial(ctx context.Context, authority string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	return p.dialResolved(ctx, authority, lookup, (&net.Dialer{}).DialContext)
}

func (p *Policy) dialResolved(ctx context.Context, authority string, lookup func(context.Context, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	ips, e := p.addresses(ctx, authority, lookup)
	if e != nil {
		return nil, ErrDenied
	}
	_, port, _ := net.SplitHostPort(authority)
	for _, ip := range ips {
		c, e := dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
	}
	return nil, ErrDenied
}

// FoundryAnthropicEndpoint selects the protocol from an explicit, validated URL,
// never from a deployment name (which may be an arbitrary alias).
func FoundryAnthropicEndpoint(raw string) bool {
	return FoundryEndpoint(raw) && strings.HasSuffix(raw, "/anthropic")
}
