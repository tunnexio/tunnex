package ipsec

import "net/netip"

// StaticConfig is a nonpersisting preflight input, not an activation request.
// Algorithms and engine text are deliberately absent from this bounded profile.
type StaticConfig struct {
	Mode                   string         `json:"mode"`
	CustomerOutsideAddress string         `json:"customer_outside_address"`
	LocalPrefixes          []string       `json:"local_prefixes"`
	RemotePrefixes         []string       `json:"remote_prefixes"`
	Tunnels                []StaticTunnel `json:"tunnels"`
}

type StaticTunnel struct {
	OutsideAddress        string `json:"outside_address"`
	InsideCIDR            string `json:"inside_cidr"`
	CustomerInsideAddress string `json:"customer_inside_address"`
	CloudInsideAddress    string `json:"cloud_inside_address"`
	PSK                   string `json:"-"`
}

type ConfigValidationCode string

// ConfigValidationError contains only fixed codes and structural locations.
// TunnelSlot is 1-based; zero denotes a connection-level field. No supplied
// value, parsed error text, credential or secret-derived fingerprint is retained.
type ConfigValidationError struct {
	Code       ConfigValidationCode `json:"code"`
	Field      string               `json:"field"`
	TunnelSlot int                  `json:"tunnel_slot,omitempty"`
}

func (e *ConfigValidationError) Error() string {
	return "IPsec configuration invalid: " + string(e.Code)
}
func configError(code ConfigValidationCode, field string, slot int) error {
	return &ConfigValidationError{Code: code, Field: field, TunnelSlot: slot}
}

// Conservative public-endpoint policy: all top-level IANA IPv4 special-purpose
// allocations plus multicast. It intentionally excludes globally reachable
// protocol-specific anycast too. LAN routing permits the three RFC1918 entries.
// Sources: https://www.iana.org/assignments/iana-ipv4-special-registry/ and
// https://www.iana.org/assignments/ipv4-address-space/ (reviewed 2026-09-24).
var staticSpecialIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}
var awsReservedInside = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/30"), netip.MustParsePrefix("169.254.1.0/30"), netip.MustParsePrefix("169.254.2.0/30"), netip.MustParsePrefix("169.254.3.0/30"), netip.MustParsePrefix("169.254.4.0/30"), netip.MustParsePrefix("169.254.5.0/30"), netip.MustParsePrefix("169.254.169.252/30"),
}
var awsInsideRange = netip.MustParsePrefix("169.254.0.0/16")

func canonicalIPv4Prefix(raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(raw)
	return p, err == nil && p.Addr().Is4() && p == p.Masked() && p.String() == raw
}
func canonicalIPv4Address(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(raw)
	return a, err == nil && a.Is4() && a.String() == raw
}
func routedPrefixes(raw []string, field string) ([]netip.Prefix, error) {
	// 64 is a Tunnex preflight input bound, not an AWS quota.
	if len(raw) < 1 || len(raw) > 64 {
		return nil, configError("prefix_count", field, 0)
	}
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		p, ok := canonicalIPv4Prefix(value)
		if !ok || p.Bits() == 0 {
			return nil, configError("prefix_invalid", field, 0)
		}
		for _, special := range staticSpecialIPv4 {
			if special.Addr().IsPrivate() {
				continue
			}
			if p.Overlaps(special) {
				return nil, configError("prefix_special_use", field, 0)
			}
		}
		for _, prior := range result {
			if p.Overlaps(prior) {
				return nil, configError("prefix_overlap", field, 0)
			}
		}
		result = append(result, p)
	}
	return result, nil
}
func awsStaticPSK(value string) bool {
	if !validPSK(value) || len(value) < 8 || len(value) > 64 || value[0] == '0' {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// ValidateAWSStaticConfig validates only the proposed public IPv4, static-route
// profile. Success never means provider support, a reachable endpoint, correct
// assignment in AWS, an installed engine, or verified traffic. Addresses must
// come from the customer's actual configuration; inside host order is explicit.
func ValidateAWSStaticConfig(c StaticConfig) error {
	if c.Mode != "ipv4-static" {
		return configError("mode_unsupported", "mode", 0)
	}
	local, err := routedPrefixes(c.LocalPrefixes, "local_prefixes")
	if err != nil {
		return err
	}
	remote, err := routedPrefixes(c.RemotePrefixes, "remote_prefixes")
	if err != nil {
		return err
	}
	for _, l := range local {
		for _, r := range remote {
			if l.Overlaps(r) {
				return configError("prefix_overlap", "remote_prefixes", 0)
			}
		}
	}
	if len(c.Tunnels) != 2 {
		return configError("tunnel_count", "tunnels", 0)
	}
	routes := append(local, remote...)
	customerOutside, ok := canonicalIPv4Address(c.CustomerOutsideAddress)
	if !ok {
		return configError("outside_invalid", "customer_outside_address", 0)
	}
	for _, special := range staticSpecialIPv4 {
		if special.Contains(customerOutside) {
			return configError("outside_special_use", "customer_outside_address", 0)
		}
	}
	for _, route := range routes {
		if route.Contains(customerOutside) {
			return configError("outside_route_overlap", "customer_outside_address", 0)
		}
	}
	var outside [2]netip.Addr
	var inside [2]netip.Prefix
	for i, t := range c.Tunnels {
		slot := i + 1
		address, ok := canonicalIPv4Address(t.OutsideAddress)
		if !ok {
			return configError("outside_invalid", "outside_address", slot)
		}
		for _, special := range staticSpecialIPv4 {
			if special.Contains(address) {
				return configError("outside_special_use", "outside_address", slot)
			}
		}
		for _, route := range routes {
			if route.Contains(address) {
				return configError("outside_route_overlap", "outside_address", slot)
			}
		}
		if address == customerOutside || i > 0 && address == outside[0] {
			return configError("outside_duplicate", "outside_address", slot)
		}
		outside[i] = address
		cidr, ok := canonicalIPv4Prefix(t.InsideCIDR)
		if !ok || cidr.Bits() != 30 || !awsInsideRange.Contains(cidr.Addr()) {
			return configError("inside_prefix_invalid", "inside_cidr", slot)
		}
		for _, reserved := range awsReservedInside {
			if cidr == reserved {
				return configError("inside_prefix_reserved", "inside_cidr", slot)
			}
		}
		for _, route := range routes {
			if cidr.Overlaps(route) {
				return configError("inside_route_overlap", "inside_cidr", slot)
			}
		}
		if i > 0 && cidr.Overlaps(inside[0]) {
			return configError("inside_prefix_overlap", "inside_cidr", slot)
		}
		inside[i] = cidr
		customer, customerOK := canonicalIPv4Address(t.CustomerInsideAddress)
		cloud, cloudOK := canonicalIPv4Address(t.CloudInsideAddress)
		first, second := cidr.Addr().Next(), cidr.Addr().Next().Next()
		if !customerOK || (customer != first && customer != second) {
			return configError("inside_host_invalid", "customer_inside_address", slot)
		}
		if !cloudOK || (cloud != first && cloud != second) || cloud == customer {
			return configError("inside_host_invalid", "cloud_inside_address", slot)
		}
		if !awsStaticPSK(t.PSK) {
			return configError("credential_invalid", "psk", slot)
		}
	}
	return nil
}
