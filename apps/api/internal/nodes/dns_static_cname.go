package nodes

import (
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"time"
)

// Keep private authority present on older/offline gateways so LAN defaults can
// never take over its suffix. Only optional CNAME completion is suppressed.
func staticDNSCompletionForGateway(node sqlc.Node, profile policy.IPsecDNSProfile, now time.Time) policy.IPsecDNSProfile {
	if len(profile.Profile.StaticRecords) == 0 || len(profile.Profile.Endpoints) == 0 {
		return profile
	}
	var caps struct {
		Version int `json:"max_policy_version"`
	}
	if json.Unmarshal(node.Capabilities, &caps) != nil || caps.Version < 14 || node.Status != "active" || node.RevokedAt.Valid || node.CertSerial == "" || !node.PolicyReportedAt.Valid || node.PolicyReportedAt.Time.After(now) || now.Sub(node.PolicyReportedAt.Time) > 90*time.Second {
		profile.Profile.Endpoints = nil
	}
	return profile
}
