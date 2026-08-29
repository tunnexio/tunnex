package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// VIPMapDigest mirrors policyspec.VIPMapDigest exactly. It is report-only and
// deliberately outside CanonicalHash: legacy mappings without ServiceID still
// render, but cannot truthfully produce a complete VIP-map digest.
func VIPMapDigest(mappings []VIPMapping) string {
	if len(mappings) == 0 {
		return ""
	}
	type entry struct {
		ServiceID   string `json:"service_id"`
		VIP         string `json:"vip"`
		Namespace   string `json:"namespace"`
		Service     string `json:"service"`
		ServiceCIDR string `json:"service_cidr"`
		DNSName     string `json:"dns_name"`
		Protocol    string `json:"protocol"`
		PortLow     int    `json:"port_low"`
		PortHigh    int    `json:"port_high"`
	}
	entries := make([]entry, len(mappings))
	for i, m := range mappings {
		if m.ServiceID == "" {
			return ""
		}
		entries[i] = entry{m.ServiceID, m.VIP, m.Namespace, m.Service, m.ServiceCIDR, m.DNSName, m.Protocol, m.PortLow, m.PortHigh}
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.ServiceID != b.ServiceID {
			return a.ServiceID < b.ServiceID
		}
		if a.VIP != b.VIP {
			return a.VIP < b.VIP
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.ServiceCIDR != b.ServiceCIDR {
			return a.ServiceCIDR < b.ServiceCIDR
		}
		if a.DNSName != b.DNSName {
			return a.DNSName < b.DNSName
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.PortLow != b.PortLow {
			return a.PortLow < b.PortLow
		}
		return a.PortHigh < b.PortHigh
	})
	b, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
