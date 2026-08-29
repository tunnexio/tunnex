package k8s

import "time"

// PolicyAcknowledgement is the control-plane comparison for a connector's
// applied-policy report. ExpectedHash and Degraded are CP-derived rather than
// connector assertions. Unknown inputs deliberately do not acknowledge policy:
// this feeds health eligibility, not distributed fencing.
type PolicyAcknowledgement struct {
	ExpectedKnown bool
	ExpectedHash  string
	HealthKnown   bool
	Degraded      bool
}

// ConnectorEvidence is the current control-plane evidence relevant to one
// connector. It deliberately carries no per-Service readiness or active
// data-path probe: the current agent reports only whether its global Kubernetes
// endpoint view is unavailable.
//
// The persisted inputs are node org/site/status/revocation, WireGuard key and
// endpoint validity, last_seen_at, policy_reported_at, and the server-built
// capability report. Policy is the CP-derived comparison at this read and is
// unknown when compilation or health evaluation cannot determine it.
type ConnectorEvidence struct {
	ID     string
	OrgID  string
	SiteID string

	Status  string
	Revoked bool

	// These are evaluated by the CP's existing WireGuard-key and endpoint
	// validators before crossing into this pure package.
	WGPublicKeyReady bool
	EndpointReady    bool
	LastSeenAt       time.Time

	PolicyReportedAt     time.Time
	AppliedPolicyHash    string
	AppliedPolicyError   string
	AppliedPolicyRefusal int
	// K8sEndpointViewKnown distinguishes an explicit false from an absent or
	// malformed old-agent capability report. Unknown endpoint evidence must not
	// become data health.
	K8sEndpointViewKnown    bool
	K8sEndpointsUnavailable bool
	Policy                  PolicyAcknowledgement
}

// AdaptConnectorEvidence maps current CP evidence to the connector-pool model.
// The caller supplies the same freshness window used by its current CP read.
// Missing/future/stale timestamps and an unknown policy comparison fail closed.
// This pure adapter neither promotes nor fences a connector.
func AdaptConnectorEvidence(now time.Time, reportFreshness time.Duration, poolOrgID, poolSiteID string, e ConnectorEvidence) (ConnectorCandidate, ConnectorHealth) {
	scopeOK := e.ID != "" && e.OrgID == poolOrgID && e.SiteID == poolSiteID
	active := scopeOK && e.Status == "active" && !e.Revoked
	endpointReady := e.WGPublicKeyReady && e.EndpointReady
	candidate := ConnectorCandidate{
		ID:            e.ID,
		OrgID:         e.OrgID,
		SiteID:        e.SiteID,
		Active:        active,
		EndpointReady: endpointReady,
	}

	reportFresh := freshAt(now, e.PolicyReportedAt, reportFreshness)
	heartbeatFresh := freshAt(now, e.LastSeenAt, reportFreshness)
	policyAcknowledged := reportFresh &&
		e.Policy.ExpectedKnown && e.Policy.ExpectedHash != "" &&
		e.Policy.HealthKnown && !e.Policy.Degraded &&
		e.AppliedPolicyHash != "" && e.AppliedPolicyError == "" &&
		e.AppliedPolicyRefusal == 0 && e.AppliedPolicyHash == e.Policy.ExpectedHash

	return candidate, ConnectorHealth{
		ControlHealthy: active && endpointReady && heartbeatFresh && policyAcknowledged,
		// The endpoint watcher report is a global view of the Kubernetes API,
		// not evidence that a particular Service has ready pods.
		DataHealthy: reportFresh && e.K8sEndpointViewKnown && !e.K8sEndpointsUnavailable,
	}
}

func freshAt(now, observed time.Time, window time.Duration) bool {
	return window > 0 && !observed.IsZero() && !observed.After(now) && now.Sub(observed) < window
}
