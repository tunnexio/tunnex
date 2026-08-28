package k8s

import (
	"testing"
	"time"
)

func healthyConnectorEvidence(now time.Time) ConnectorEvidence {
	return ConnectorEvidence{
		ID: "connector", OrgID: "org", SiteID: "site", Status: "active",
		WGPublicKeyReady: true, EndpointReady: true,
		LastSeenAt: now.Add(-time.Second), PolicyReportedAt: now.Add(-time.Second),
		AppliedPolicyHash:    "expected",
		K8sEndpointViewKnown: true,
		Policy:               PolicyAcknowledgement{ExpectedKnown: true, ExpectedHash: "expected", HealthKnown: true},
	}
}

func TestAdaptConnectorEvidenceUsesCurrentCPEvidenceFailClosed(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	window := time.Minute
	tests := map[string]func(*ConnectorEvidence){
		"healthy":                    func(*ConnectorEvidence) {},
		"missing heartbeat":          func(e *ConnectorEvidence) { e.LastSeenAt = time.Time{} },
		"future heartbeat":           func(e *ConnectorEvidence) { e.LastSeenAt = now.Add(time.Second) },
		"stale heartbeat":            func(e *ConnectorEvidence) { e.LastSeenAt = now.Add(-window) },
		"missing policy report":      func(e *ConnectorEvidence) { e.PolicyReportedAt = time.Time{} },
		"future policy report":       func(e *ConnectorEvidence) { e.PolicyReportedAt = now.Add(time.Second) },
		"stale policy report":        func(e *ConnectorEvidence) { e.PolicyReportedAt = now.Add(-window) },
		"inactive status":            func(e *ConnectorEvidence) { e.Status = "offline" },
		"revoked":                    func(e *ConnectorEvidence) { e.Revoked = true },
		"policy degraded":            func(e *ConnectorEvidence) { e.Policy.Degraded = true },
		"policy expectation unknown": func(e *ConnectorEvidence) { e.Policy.ExpectedKnown = false },
		"policy health unknown":      func(e *ConnectorEvidence) { e.Policy.HealthKnown = false },
		"policy hash mismatch":       func(e *ConnectorEvidence) { e.AppliedPolicyHash = "old" },
		"empty expected policy hash": func(e *ConnectorEvidence) { e.Policy.ExpectedHash = "" },
		"empty applied policy hash":  func(e *ConnectorEvidence) { e.AppliedPolicyHash = "" },
		"applied policy error":       func(e *ConnectorEvidence) { e.AppliedPolicyError = "compile failed" },
		"applied policy refusal":     func(e *ConnectorEvidence) { e.AppliedPolicyRefusal = 1 },
		"endpoint view unknown":      func(e *ConnectorEvidence) { e.K8sEndpointViewKnown = false },
		"k8s endpoint view degraded": func(e *ConnectorEvidence) { e.K8sEndpointsUnavailable = true },
		"wrong organization":         func(e *ConnectorEvidence) { e.OrgID = "other-org" },
		"wrong site":                 func(e *ConnectorEvidence) { e.SiteID = "other-site" },
		"empty connector":            func(e *ConnectorEvidence) { e.ID = "" },
		"invalid key":                func(e *ConnectorEvidence) { e.WGPublicKeyReady = false },
		"invalid endpoint":           func(e *ConnectorEvidence) { e.EndpointReady = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := healthyConnectorEvidence(now)
			mutate(&evidence)
			candidate, health := AdaptConnectorEvidence(now, window, "org", "site", evidence)
			switch name {
			case "healthy":
				if !candidate.Active || !candidate.EndpointReady || !health.Healthy() {
					t.Fatalf("healthy CP evidence must yield an eligible dual-signal connector: candidate=%+v health=%+v", candidate, health)
				}
			case "k8s endpoint view degraded", "endpoint view unknown":
				if !candidate.Active || !candidate.EndpointReady || !health.ControlHealthy || health.DataHealthy {
					t.Fatalf("global endpoint-view loss must preserve control but fail data health: candidate=%+v health=%+v", candidate, health)
				}
			case "wrong organization", "wrong site", "empty connector", "inactive status", "revoked":
				if candidate.Active || health.ControlHealthy {
					t.Fatalf("%s must remove eligibility and control health: candidate=%+v health=%+v", name, candidate, health)
				}
			default:
				if health.ControlHealthy {
					t.Fatalf("%s must fail control health: candidate=%+v health=%+v", name, candidate, health)
				}
			}
		})
	}
}

func TestAdaptConnectorEvidenceRejectsInvalidFreshnessWindow(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	for _, window := range []time.Duration{0, -time.Second} {
		_, health := AdaptConnectorEvidence(now, window, "org", "site", healthyConnectorEvidence(now))
		if health.ControlHealthy || health.DataHealthy || health.Healthy() {
			t.Fatalf("freshness window %s must fail both evidence signals closed: %+v", window, health)
		}
	}
}

func TestAdaptConnectorEvidenceNeverInventsPerServiceReadiness(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	evidence := healthyConnectorEvidence(now)
	_, health := AdaptConnectorEvidence(now, time.Minute, "org", "site", evidence)
	if !health.DataHealthy {
		t.Fatal("a fresh successful global endpoint view is the only current data evidence")
	}
	evidence.K8sEndpointsUnavailable = true
	_, health = AdaptConnectorEvidence(now, time.Minute, "org", "site", evidence)
	if health.DataHealthy {
		t.Fatal("global endpoint-view degradation must fail data health; no per-Service inference exists")
	}
	evidence.K8sEndpointsUnavailable = false
	evidence.K8sEndpointViewKnown = false
	_, health = AdaptConnectorEvidence(now, time.Minute, "org", "site", evidence)
	if health.DataHealthy {
		t.Fatal("an absent endpoint-view report must fail closed, not read as explicit healthy")
	}
}
