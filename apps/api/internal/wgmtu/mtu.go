// Package wgmtu interprets authenticated applied WireGuard MTU observations.
package wgmtu

import (
	"encoding/json"
	"time"
)

const Default = 1420

// Report freshness matches the ordinary node freshness window. A missing,
// malformed, future, or stale report keeps the legacy default; it is never
// authority for policy, addresses, or grants.
func Applied(capabilities []byte, reported time.Time, now time.Time) int {
	if reported.IsZero() || reported.After(now) || now.Sub(reported) > 90*time.Second {
		return Default
	}
	var caps struct {
		MTU int `json:"wireguard_applied_mtu"`
	}
	if json.Unmarshal(capabilities, &caps) != nil || caps.MTU < 1280 || caps.MTU > Default {
		return Default
	}
	return caps.MTU
}
