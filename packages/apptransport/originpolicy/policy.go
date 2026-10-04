// Package originpolicy canonicalizes reviewed origin constraints. It never grants
// authority to a browser-supplied destination.
package originpolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"sort"
	"strings"
)

type Policy struct {
	AllowedDestinationCIDRs []string
	OriginCAPEM             string
	OriginCADigest          string
}

var ErrPolicy = errors.New("invalid origin destination or CA policy")
var ErrDestination = errors.New("origin destination refused")
var private = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
var forbidden = prefixes("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "168.63.129.16/32", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "3fff::/20", "2001:db8::/32", "2002::/16", "fd00:ec2::254/128", "fe80::/10", "ff00::/8")

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, v := range values {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}
func overlap(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}
func Normalize(allowed []string, caPEM string) (Policy, error) {
	out := Policy{AllowedDestinationCIDRs: []string{}}
	if len(allowed) > 32 || len(caPEM) > 32<<10 {
		return out, ErrPolicy
	}
	seen := map[string]bool{}
	for _, raw := range allowed {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Bits() == 0 || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return out, ErrPolicy
		}
		p = p.Masked()
		for _, blocked := range forbidden {
			if overlap(p, blocked) {
				return out, ErrPolicy
			}
		}
		for _, r := range private {
			if overlap(p, r) && (p.Bits() < r.Bits() || !r.Contains(p.Addr())) {
				return out, ErrPolicy
			}
		}
		if !seen[p.String()] {
			out.AllowedDestinationCIDRs = append(out.AllowedDestinationCIDRs, p.String())
			seen[p.String()] = true
		}
	}
	sort.Strings(out.AllowedDestinationCIDRs)
	data := []byte(strings.TrimSpace(caPEM))
	certs := map[string][]byte{}
	count := 0
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return out, ErrPolicy
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return out, ErrPolicy
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return out, ErrPolicy
		}
		count++
		if count > 8 {
			return out, ErrPolicy
		}
		sum := sha256.Sum256(cert.Raw)
		certs[hex.EncodeToString(sum[:])] = cert.Raw
		data = bytes.TrimSpace(rest)
	}
	keys := make([]string, 0, len(certs))
	for k := range certs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.OriginCAPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[k]}))
	}
	if out.OriginCAPEM != "" {
		digest := sha256.Sum256([]byte(out.OriginCAPEM))
		out.OriginCADigest = hex.EncodeToString(digest[:])
	}
	return out, nil
}

// Validate checks a resolved numeric destination against reviewed policy and the
// installation's control-plane/proxy IPs. All DNS answers must pass this check.
func (p Policy) Validate(ip netip.Addr, control []netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return ErrDestination
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) && !ip.IsPrivate() {
		return ErrDestination
	}
	for _, c := range control {
		if ip == c.Unmap() {
			return ErrDestination
		}
	}
	for _, r := range forbidden {
		if r.Contains(ip) {
			return ErrDestination
		}
	}
	isPrivate := false
	for _, r := range private {
		if r.Contains(ip) {
			isPrivate = true
		}
	}
	if len(p.AllowedDestinationCIDRs) == 0 {
		if isPrivate {
			return ErrDestination
		}
		return nil
	}
	for _, raw := range p.AllowedDestinationCIDRs {
		r, e := netip.ParsePrefix(raw)
		if e == nil && r.Contains(ip) {
			if !isPrivate || r.Addr().IsPrivate() {
				return nil
			}
		}
	}
	return ErrDestination
}
