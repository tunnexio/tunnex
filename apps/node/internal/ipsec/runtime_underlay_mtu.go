package ipsec

import "encoding/json"

// awsIPv4InnerMTU is a conservative packet ceiling for the fixed supported
// AES-CBC (16-byte block/IV), SHA2-256-128 (16-byte ICV), IPv4 tunnel profile.
// Always budget NAT-T: outer IPv4 20 + UDP 8 + ESP header 8 + IV 16 + ICV 16.
// ESP trailer 2 and padding are encrypted, rounded UP to a full AES block.
// This is not discovery of an unobserved path bottleneck. Never budget an IKE
// non-ESP marker for ESP data, and never raise the existing AWS 1422 ceiling.
func awsIPv4InnerMTU(outer uint32) (uint32, bool) {
	if outer < 68 || outer > 65535 {
		return 0, false
	}
	blocks := (outer - 68) / 16
	if blocks < 5 {
		return 0, false
	}
	inner := blocks*16 - 2
	if inner > AWSIPv4TunnelMTU {
		inner = AWSIPv4TunnelMTU
	}
	return inner, true
}

// runtimeOuterMTU derives only a current, observed upper bound. Linux iproute2
// may expose MTU in route metrics or a cached PMTU row. Unknown/malformed metric
// shapes refuse; an absent metric is not evidence of end-to-end PMTU discovery.
func runtimeOuterMTU(link uint32, row map[string]json.RawMessage) (uint32, bool) {
	if _, ok := awsIPv4InnerMTU(link); !ok {
		return 0, false
	}
	result := link
	take := func(raw json.RawMessage) bool {
		value, ok := kernelNumber(raw, 32)
		if !ok || value < 68 || value > 65535 {
			return false
		}
		if uint32(value) < result {
			result = uint32(value)
		}
		return true
	}
	if raw, exists := row["mtu"]; exists && !take(raw) {
		return 0, false
	}
	for _, key := range []string{"metrics", "cache"} {
		raw, exists := row[key]
		if !exists {
			continue
		}
		list, ok := kernelObjects(raw)
		if !ok || len(list) > 1 {
			return 0, false
		}
		for _, value := range list {
			object := value
			for name, field := range object {
				switch name {
				case "mtu":
					if !take(field) {
						return 0, false
					}
				case "expires":
					if key != "cache" {
						return 0, false
					}
					if _, ok := kernelNumber(field, 32); !ok {
						return 0, false
					}
				default:
					return 0, false
				}
			}
		}
	}
	if _, ok := awsIPv4InnerMTU(result); !ok {
		return 0, false
	}
	return result, true
}
