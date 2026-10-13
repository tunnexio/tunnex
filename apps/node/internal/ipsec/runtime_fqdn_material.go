package ipsec

import (
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RuntimeFQDNGrant is additive authenticated provenance, never an ordinary IP grant.
type RuntimeFQDNGrant struct {
	ExpiresAt             time.Time `json:"expires_at,omitzero"`
	ResolverSourceAddress string    `json:"resolver_source_address,omitempty"`
	RuntimeGrant
	FQDNManaged           bool   `json:"fqdn_managed"`
	ResourceID            string `json:"resource_id"`
	Name                  string `json:"name"`
	Generation            string `json:"generation"`
	ResolverConfigID      string `json:"resolver_config_id"`
	ResolverConfigVersion int64  `json:"resolver_config_version"`
	SelectedSiteID        string `json:"selected_site_id"`
	SelectedGatewayID     string `json:"selected_gateway_id"`
	ResolverProfileID     string `json:"resolver_profile_id"`
	ResolverMatchSuffix   string `json:"resolver_match_suffix"`
	ConnectionID          string `json:"connection_id"`
	ConfigurationRevision int64  `json:"configuration_revision"`
}

// Comparable provenance stays in fresh in-memory grants. The journal carries no
// answer permission, and a bare FQDNManaged bit can never qualify a renderer.
type FQDNGrantBinding struct {
	Version                                                         int       `json:",omitzero"`
	ExpiresAt                                                       time.Time `json:",omitzero"`
	ResolverSourceAddress                                           string    `json:",omitzero"`
	ResourceID, ResolverConfigID, SelectedSiteID, SelectedGatewayID uuid.UUID
	ResolverProfileID, ConnectionID, RuleID                         uuid.UUID
	Name, Generation, ResolverMatchSuffix                           string
	ResolverConfigVersion, ConfigurationRevision                    int64
}

func validFQDNName(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
func (b FQDNGrantBinding) valid() bool {
	if b.Version == 0 {
		if !b.ExpiresAt.IsZero() || b.ResolverSourceAddress != "" {
			return false
		}
	} else if b.Version == 2 {
		a, err := netip.ParseAddr(b.ResolverSourceAddress)
		if b.ExpiresAt.IsZero() || err != nil || !a.Is4() || !a.IsPrivate() || a.String() != b.ResolverSourceAddress {
			return false
		}
	} else {
		return false
	}
	return b.ResourceID != uuid.Nil && b.ResolverConfigID != uuid.Nil && b.SelectedSiteID != uuid.Nil && b.SelectedGatewayID != uuid.Nil && b.ResolverProfileID != uuid.Nil && b.ConnectionID != uuid.Nil && b.RuleID != uuid.Nil && b.ResolverConfigVersion > 0 && b.ConfigurationRevision > 0 && validDigest(b.Generation) && validFQDNName(b.Name) && validFQDNName(b.ResolverMatchSuffix) && (b.Name == b.ResolverMatchSuffix || strings.HasSuffix(b.Name, "."+b.ResolverMatchSuffix))
}
func runtimeFQDNGrants(m RuntimeMaterial, local, remote []netip.Prefix) ([]GuardGrant, error) {
	if (len(m.Policy.FQDNGrants) == 0 && m.Policy.FQDNPolicyVersion != 0) || (len(m.Policy.FQDNGrants) > 0 && (m.Policy.FQDNPolicyVersion != 1 && m.Policy.FQDNPolicyVersion != 2)) || len(m.Policy.FQDNGrants) > 128 || len(m.Policy.Grants)+2*len(m.Policy.DNSResolverGrants)+len(m.Policy.FQDNGrants) > 128 {
		return nil, ErrRuntimeController
	}
	var out []GuardGrant
	seen := map[GuardGrant]bool{}
	for _, f := range m.Policy.FQDNGrants {
		parse := func(s string) uuid.UUID {
			u, e := uuid.Parse(s)
			if e != nil || u.String() != s {
				return uuid.Nil
			}
			return u
		}
		b := FQDNGrantBinding{ResourceID: parse(f.ResourceID), ResolverConfigID: parse(f.ResolverConfigID), SelectedSiteID: parse(f.SelectedSiteID), SelectedGatewayID: parse(f.SelectedGatewayID), ResolverProfileID: parse(f.ResolverProfileID), ConnectionID: parse(f.ConnectionID), RuleID: parse(f.RuleID), Name: f.Name, Generation: f.Generation, ResolverMatchSuffix: f.ResolverMatchSuffix, ResolverConfigVersion: f.ResolverConfigVersion, ConfigurationRevision: f.ConfigurationRevision}
		if m.Policy.FQDNPolicyVersion == 2 {
			b.Version = 2
			b.ExpiresAt = f.ExpiresAt
			b.ResolverSourceAddress = f.ResolverSourceAddress
			a, err := netip.ParseAddr(f.ResolverSourceAddress)
			if f.ExpiresAt.IsZero() || f.ExpiresAt.After(time.Now().Add(time.Hour)) || err != nil || !withinPrefixes(netip.PrefixFrom(a, 32), local) {
				return nil, ErrRuntimeController
			}
		} else if !f.ExpiresAt.IsZero() || f.ResolverSourceAddress != "" {
			return nil, ErrRuntimeController
		}
		src, se := netip.ParsePrefix(f.Source)
		dst, de := netip.ParsePrefix(f.Destination)
		p := GuardProtocol(f.Protocol)
		if !f.FQDNManaged || !b.valid() || b.SelectedSiteID != m.Manifest.SiteID || b.SelectedGatewayID != m.Manifest.NodeID || b.ConnectionID != m.Manifest.ConnectionID || b.ConfigurationRevision != m.Manifest.ConfigurationRevision || se != nil || de != nil || f.Source != src.String() || f.Destination != dst.String() || !validGuardPrefix(src) || !validGuardPrefix(dst) || dst.Bits() != 32 || !withinPrefixes(src, local) || !withinPrefixes(dst, remote) || (p != GuardAny && p != GuardTCP && p != GuardUDP) || (p == GuardAny && (f.PortLow != 0 || f.PortHigh != 0)) || (p != GuardAny && (f.PortLow == 0 || f.PortHigh < f.PortLow)) {
			return nil, ErrRuntimeController
		}
		// Expired v2 authority is a selective withdrawal, not a connection failure.
		if b.Version == 2 && !b.ExpiresAt.After(time.Now()) {
			continue
		}
		g := GuardGrant{Source: src, Destination: dst, Protocol: p, PortLow: f.PortLow, PortHigh: f.PortHigh, FQDNManaged: true, FQDN: b}
		if seen[g] {
			return nil, ErrRuntimeController
		}
		seen[g] = true
		out = append(out, g)
	}
	return out, nil
}
