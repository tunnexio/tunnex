package http

import (
	"net/netip"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestAccessCheckBuilderKeepsOrderedFirstBlocker(t *testing.T) {
	b := accessCheckBuilder{}
	b.add(api.AgentAccessCheckStatusPass, "identity", "ok", nil)
	b.add(api.AgentAccessCheckStatusInconclusive, "dns", "unknown", nil)
	b.add(api.AgentAccessCheckStatusFail, "route", "missing", nil)
	if b.firstBlocker == nil || *b.firstBlocker != "dns" {
		t.Fatalf("first blocker must preserve ordered tri-state result: %#v", b.firstBlocker)
	}
	if got := b.overall(); got != api.AgentAccessDiagnosticOverallDenied {
		t.Fatalf("any authoritative fail makes the overall result denied, got %q", got)
	}
	if len(b.checks) != 3 {
		t.Fatalf("later independently-answerable checks must remain visible: %d", len(b.checks))
	}
}

func TestMatchingPrefixUsesConfiguredRouteIntent(t *testing.T) {
	ip := netip.MustParseAddr("10.99.3.7")
	if got := matchingPrefix([]string{"10.99.0.0/16", "192.168.0.0/16"}, ip); got != "10.99.0.0/16" {
		t.Fatalf("expected exact configured prefix, got %q", got)
	}
	if got := matchingPrefix([]string{"192.168.0.0/16", "not-a-prefix"}, ip); got != "" {
		t.Fatalf("missing route must remain missing, got %q", got)
	}
}

func TestPolicyFactsContainNoSecretMaterial(t *testing.T) {
	facts := policyFacts(policyspec.AccessEvaluation{Mode: "enforcing", PolicyVersion: 7, PolicyHash: "hash", RuleID: "rule"})
	if len(facts) != 4 || facts["mode"] != "enforcing" || facts["version"] != "7" || facts["policy_hash"] != "hash" || facts["rule_id"] != "rule" {
		t.Fatalf("unexpected bounded policy facts: %#v", facts)
	}
}
