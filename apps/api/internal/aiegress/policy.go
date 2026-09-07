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
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
}
type Policy struct {
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
	if len(p.Endpoints) == 0 || len(p.Endpoints) > 64 || len(p.ProtectedHosts) == 0 || len(p.ProtectedHosts) > 128 || len(p.DeniedCIDRs) > 128 {
		return ErrDenied
	}
	p.rules = map[string][]netip.Prefix{}
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
		u, e := NormalizeEndpoint(ep.URL)
		if e != nil || ep.Name == "" || len(ep.Name) > 100 || seen[u] || len(ep.AllowedCIDRs) == 0 || len(ep.AllowedCIDRs) > 64 {
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
			p.rules[authority] = append(p.rules[authority], v)
		}
	}
	for _, host := range p.ProtectedHosts {
		if host == "" || strings.ContainsAny(host, "/ @\r\n\t") {
			return ErrDenied
		}
	}
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
	return false
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
	host, _, e := net.SplitHostPort(authority)
	rules, ok := p.rules[authority]
	if e != nil || !ok {
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
		if blocked(ip) || protected[ip] {
			return nil, ErrDenied
		}
		for _, deny := range p.denied {
			if deny.Contains(ip) {
				return nil, ErrDenied
			}
		}
		allowed := false
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
	ips, e := p.addresses(ctx, authority, lookup)
	if e != nil {
		return nil, ErrDenied
	}
	_, port, _ := net.SplitHostPort(authority)
	for _, ip := range ips {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
	}
	return nil, ErrDenied
}
