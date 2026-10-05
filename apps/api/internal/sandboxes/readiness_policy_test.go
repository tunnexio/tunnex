package sandboxes

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func TestPolicyAcknowledgements(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	org, gateway, second := uuid.New(), uuid.New(), uuid.New()
	newNode := func(id uuid.UUID) sqlc.Node {
		return sqlc.Node{ID: id, OrgID: org, Status: "active", PolicyReportedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}}
	}
	good := nodes.PolicyHealth{Kind: nodes.KindHealthy, PushKnown: true, PushedHash: "canonical-finalized-hash", AppliedHash: "canonical-finalized-hash"}
	tests := []struct {
		name   string
		change func(*[]sqlc.Node, map[uuid.UUID]nodes.PolicyHealth)
	}{
		{"missing health", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) { delete(h, second) }},
		{"unknown push", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) {
			v := h[second]
			v.PushKnown = false
			h[second] = v
		}},
		{"empty hash", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) {
			v := h[second]
			v.PushedHash = ""
			v.AppliedHash = ""
			h[second] = v
		}},
		{"not applied", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) {
			v := h[second]
			v.AppliedHash = "old"
			h[second] = v
		}},
		{"degraded", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) {
			v := h[second]
			v.Degraded = true
			h[second] = v
		}},
		{"unhealthy kind", func(_ *[]sqlc.Node, h map[uuid.UUID]nodes.PolicyHealth) {
			v := h[second]
			v.Kind = nodes.KindDesyncUnknown
			h[second] = v
		}},
		{"missing report", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { (*n)[1].PolicyReportedAt.Valid = false }},
		{"stale boundary", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) {
			(*n)[1].PolicyReportedAt.Time = now.Add(-nodes.ReportFreshnessWindow)
		}},
		{"future report", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) {
			(*n)[1].PolicyReportedAt.Time = now.Add(time.Second)
		}},
		{"cross organization", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { (*n)[1].OrgID = uuid.New() }},
		{"inactive", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { (*n)[1].Status = "idle" }},
		{"duplicate", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { (*n)[1] = (*n)[0] }},
		{"nil identity", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { (*n)[1].ID = uuid.Nil }},
		{"missing gateway", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { *n = (*n)[1:] }},
		{"empty set", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { *n = nil }},
		{"over limit", func(n *[]sqlc.Node, _ map[uuid.UUID]nodes.PolicyHealth) { *n = make([]sqlc.Node, 101) }},
	}
	selected := []sqlc.Node{newNode(gateway), newNode(second)}
	wantReasons := map[string]string{
		"missing health": "health_unavailable", "unknown push": "desired_hash_unknown",
		"empty hash": "desired_hash_missing", "not applied": "hash_mismatch",
		"degraded": "apply_unhealthy", "unhealthy kind": "apply_unhealthy",
		"missing report": "report_missing", "stale boundary": "report_stale",
		"future report": "report_future", "cross organization": "node_org_mismatch",
		"inactive": "node_inactive", "duplicate": "duplicate_node",
		"nil identity": "node_id_missing", "missing gateway": "gateway_missing",
		"empty set": "node_set_invalid", "over limit": "node_set_invalid",
	}
	health := map[uuid.UUID]nodes.PolicyHealth{gateway: good, second: good}
	got, err := validatePolicyAcknowledgements(now, org, gateway, selected, health)
	if err != nil || len(got) != 2 || got[0].NodeID != gateway || got[1].NodeID != second || got[0].Hash != good.PushedHash || !got[0].ReportedAt.Equal(selected[0].PolicyReportedAt.Time) {
		t.Fatalf("healthy acknowledgements: %v, %v", got, err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := []sqlc.Node{newNode(gateway), newNode(second)}
			h := map[uuid.UUID]nodes.PolicyHealth{gateway: good, second: good}
			tc.change(&n, h)
			got, err := validatePolicyAcknowledgements(now, org, gateway, n, h)
			if !errors.Is(err, ErrDisabled) || got != nil {
				t.Fatalf("gate accepted invalid evidence: %v, %v", got, err)
			}
			var gate *PolicyGateError
			if !errors.As(err, &gate) || gate.reason != wantReasons[tc.name] {
				t.Fatalf("wrong rejection diagnostic: %v", err)
			}
			if (tc.name == "cross organization" || tc.name == "duplicate" || tc.name == "nil identity") && gate.nodeID != uuid.Nil {
				t.Fatal("invalid selected identity entered diagnostic")
			}
		})
	}
}

func TestLocalAcknowledgementHealthDoesNotMaskApplyFailure(t *testing.T) {
	org, gateway := uuid.New(), uuid.New()
	now := time.Now().UTC()
	node := sqlc.Node{ID: gateway, OrgID: org, Status: "active", PolicyReportedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}}
	advisory := nodes.PolicyHealth{Kind: nodes.KindSiteHubDown, Degraded: true, PushKnown: true, PushedHash: "finalized", AppliedHash: "finalized"}
	health := map[uuid.UUID]nodes.PolicyHealth{gateway: advisory}
	if _, err := validatePolicyAcknowledgementsForLocal(now, org, gateway, []sqlc.Node{node}, health, true); err != nil {
		t.Fatal("remote-site advisory blocked local terminal", err)
	}
	if _, err := validatePolicyAcknowledgements(now, org, gateway, []sqlc.Node{node}, health); !errors.Is(err, ErrDisabled) {
		t.Fatal("legacy gate accepted degraded site", err)
	}
	for _, caps := range []string{`{"policy_error":"apply failed"}`, `{"policy_failing_since":"2026-10-03T00:00:00Z"}`, `{"policy_refused_version":1}`} {
		node.Capabilities = []byte(caps)
		if _, err := validatePolicyAcknowledgementsForLocal(now, org, gateway, []sqlc.Node{node}, health, true); !errors.Is(err, ErrDisabled) {
			t.Fatal("remote advisory masked apply failure", caps, err)
		}
	}
}

func TestLocalAcknowledgementStillRequiresFreshMatchingPolicy(t *testing.T) {
	now := time.Now().UTC()
	org, gateway := uuid.New(), uuid.New()
	tests := []struct {
		name   string
		change func(*sqlc.Node, *nodes.PolicyHealth)
	}{
		{"unknown push", func(_ *sqlc.Node, h *nodes.PolicyHealth) { h.PushKnown = false }},
		{"mismatch", func(_ *sqlc.Node, h *nodes.PolicyHealth) { h.AppliedHash = "old" }},
		{"empty hash", func(_ *sqlc.Node, h *nodes.PolicyHealth) { h.PushedHash = ""; h.AppliedHash = "" }},
		{"desync", func(_ *sqlc.Node, h *nodes.PolicyHealth) { h.Kind = nodes.KindDesyncUnknown }},
		{"stale", func(n *sqlc.Node, _ *nodes.PolicyHealth) {
			n.PolicyReportedAt.Time = now.Add(-nodes.ReportFreshnessWindow)
		}},
		{"future", func(n *sqlc.Node, _ *nodes.PolicyHealth) { n.PolicyReportedAt.Time = now.Add(time.Second) }},
		{"missing report", func(n *sqlc.Node, _ *nodes.PolicyHealth) { n.PolicyReportedAt.Valid = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := sqlc.Node{ID: gateway, OrgID: org, Status: "active", PolicyReportedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}}
			h := nodes.PolicyHealth{Kind: nodes.KindSiteHubDown, Degraded: true, PushKnown: true, PushedHash: "canonical", AppliedHash: "canonical"}
			tc.change(&n, &h)
			if _, err := validatePolicyAcknowledgementsForLocal(now, org, gateway, []sqlc.Node{n}, map[uuid.UUID]nodes.PolicyHealth{gateway: h}, true); !errors.Is(err, ErrDisabled) {
				t.Fatal("local gate accepted invalid evidence", err)
			}
		})
	}
}
