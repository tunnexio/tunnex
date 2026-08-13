package nodes

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestFleetHealthExcludesRevokedGateways — WF-S11-10b, found by ARITHMETIC on a live scrape rather than by any
// test: the kinds summed to 4 on a fleet with only 3 non-revoked gateways, so a revoked one was still being
// counted. It had merely moved from cert_expired_cannot_reconnect to site_link_down when the status gate landed.
//
// Why this matters more than the mislabelling it followed: revoked rows are NEVER DELETED (revoke preserves the
// audit trail deliberately, and there is no delete endpoint). So counting them means every degradation series
// drifts, over a deployment's life, toward being dominated by long-dead gateways — and an alert on
// `site_link_down > 0` becomes permanently firing, therefore permanently ignored. A metric that cannot return to
// zero cannot be alerted on.
//
// It is also a one-truth violation: the console suppresses badges on revoked rows, so the dashboard and the
// metric would disagree about how many gateways are unhealthy.
func TestFleetHealthExcludesRevokedGateways(t *testing.T) {
	mixed := []sqlc.Node{
		{Name: "live-1", Status: "active"},
		{Name: "retired-1", Status: "revoked"},
		{Name: "live-2", Status: "active"},
		{Name: "retired-2", Status: "revoked"},
		{Name: "retired-3", Status: "revoked"},
	}

	got := activeForFleetHealth(mixed)
	if len(got) != 2 {
		t.Fatalf("fleet health must count only active gateways: got %d of %d, want 2. Revoked rows accumulate "+
			"forever, so counting them makes every degradation series permanently non-zero", len(got), len(mixed))
	}
	for _, n := range got {
		if n.Status != "active" {
			t.Fatalf("a %q gateway reached the fleet tally: %s", n.Status, n.Name)
		}
	}

	// An all-revoked org contributes NOTHING, rather than a fleet-wide count of stale gateways.
	if n := len(activeForFleetHealth([]sqlc.Node{{Status: "revoked"}, {Status: "revoked"}})); n != 0 {
		t.Fatalf("an org whose every gateway is revoked must contribute nothing to the tally, got %d", n)
	}
}
