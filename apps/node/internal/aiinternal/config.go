// Package aiinternal serves the internal AI endpoint (AI-KEYS-1): an HTTPS listener on the gateway's
// tunnel address and at most one LAN address that accepts only static workload keys (`tnx_sk_`) from the
// configured source ranges and relays each request to the control plane over node mTLS. The control
// plane authenticates the key and decides; the gateway only narrows what may reach it.
package aiinternal

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// DesiredVersion is the only desired-state document version this build understands. It is also the
// capability version the gateway reports (ai_internal_endpoint_version).
const DesiredVersion = 1

// TLS modes of the endpoint certificate (D8).
const (
	TLSModeTunnexCA = "tunnex_ca"
	TLSModeCustom   = "custom"
)

// Ports the endpoint can never take: the AI VPN listener and the MCP gateway listener.
var reservedPorts = map[int]bool{8083: true, 8084: true}

var (
	uuidRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Endpoint is a validated endpoint configuration. Every address is a canonical private IPv4 address and
// every source range a canonical private IPv4 prefix.
type Endpoint struct {
	ID        string
	Revision  int64
	Addresses []netip.Addr
	Port      int
	DNSName   string
	Sources   []netip.Prefix
	TLSMode   string
}

var errInvalidDesired = errors.New("invalid desired state")

// ParseDesired validates the delivered document. It returns (nil, nil) when no endpoint is configured
// and an error for anything it does not fully understand, which the runtime treats as "off".
func ParseDesired(doc control.AIInternalDesired) (*Endpoint, error) {
	if doc.Version != DesiredVersion {
		return nil, errInvalidDesired
	}
	if doc.Endpoint == nil {
		return nil, nil
	}
	in := doc.Endpoint
	if !uuidRE.MatchString(in.ID) || in.Revision < 1 {
		return nil, errInvalidDesired
	}
	if in.Port < 1024 || in.Port > 65535 || reservedPorts[in.Port] {
		return nil, errInvalidDesired
	}
	if in.TLSMode != TLSModeTunnexCA && in.TLSMode != TLSModeCustom {
		return nil, errInvalidDesired
	}
	if in.DNSName != "" && !validDNSName(in.DNSName) {
		return nil, errInvalidDesired
	}
	if len(in.ListenAddresses) < 1 || len(in.ListenAddresses) > 2 {
		return nil, errInvalidDesired
	}
	out := &Endpoint{ID: in.ID, Revision: in.Revision, Port: in.Port, DNSName: in.DNSName, TLSMode: in.TLSMode}
	for _, raw := range in.ListenAddresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.String() != raw || slices.Contains(out.Addresses, addr) {
			return nil, errInvalidDesired
		}
		out.Addresses = append(out.Addresses, addr)
	}
	if len(in.SourceCIDRs) < 1 || len(in.SourceCIDRs) > 32 {
		return nil, errInvalidDesired
	}
	for _, raw := range in.SourceCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != raw || !privatePrefix(prefix) || slices.Contains(out.Sources, prefix) {
			return nil, errInvalidDesired
		}
		out.Sources = append(out.Sources, prefix)
	}
	return out, nil
}

// privatePrefix is true when the whole range is private space (first and last address both private;
// the private blocks are aligned, so no private-to-public-to-private range exists).
func privatePrefix(p netip.Prefix) bool {
	first := p.Addr().As4()
	last := first
	for i := p.Bits(); i < 32; i++ {
		last[i/8] |= 1 << uint(7-i%8)
	}
	return netip.AddrFrom4(first).IsPrivate() && netip.AddrFrom4(last).IsPrivate()
}

// validDNSName accepts a lower-case hostname: labels of letters, digits and inner hyphens, at most 253
// characters, not an IP literal and without a trailing dot.
func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !labelRE.MatchString(label) {
			return false
		}
	}
	// An all-digit last label would read as an IPv4 form to some resolvers.
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// allows reports whether peer, after Unmap, is an IPv4 address inside one of the source ranges.
func allows(sources []netip.Prefix, peer netip.Addr) bool {
	peer = peer.Unmap()
	if !peer.Is4() {
		return false
	}
	for _, p := range sources {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// sameServing reports whether two configurations serve identically (the listener need not restart).
func sameServing(a, b *Endpoint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ID == b.ID && a.Revision == b.Revision && a.Port == b.Port && a.DNSName == b.DNSName &&
		a.TLSMode == b.TLSMode && slices.Equal(a.Addresses, b.Addresses) && slices.Equal(a.Sources, b.Sources)
}
