// Package k8snetprep owns the provider-neutral Linux host and CNI posture needed
// by an in-cluster Tunnex gateway. It detects mechanisms from live kernel state;
// cloud-provider labels are deliberately not inputs.
package k8snetprep

import "strings"

// State is the finite outcome vocabulary shared by host preparation and CNI
// adapters. NotApplicable is a successful observation that a mechanism is not
// installed; Blocked means the mechanism could not be observed or reconciled.
type State string

const (
	StateReady         State = "ready"
	StateNotApplicable State = "not_applicable"
	StateBlocked       State = "blocked"
)

// ReasonNoRegisteredAdapter is the finite fail-closed reason for an active
// tunnel whose host exposes none of the CNI mechanisms this binary knows how
// to reconcile. Absence is not success while private return traffic depends on
// a proven masquerade exemption.
const ReasonNoRegisteredAdapter = "no_registered_adapter"

const maxReasonBytes = 240

// ComponentStatus is bounded, redacted evidence for one common check or
// mechanism adapter. It never contains command output or Kubernetes secrets.
type ComponentStatus struct {
	Name       string `json:"name"`
	State      State  `json:"state"`
	Reason     string `json:"reason,omitempty"`
	OwnedRules int    `json:"owned_rules,omitempty"`
}

// ReconcileStatus is the exact observed state after one steady-state pass.
type ReconcileStatus struct {
	Host     ComponentStatus   `json:"host"`
	Adapters []ComponentStatus `json:"adapters"`
}

// Summary returns a stable, bounded value suitable for change-only logging.
func (s ReconcileStatus) Summary() string {
	parts := []string{s.Host.Name, string(s.Host.State), s.Host.Reason}
	for _, adapter := range s.Adapters {
		parts = append(parts, adapter.Name, string(adapter.State), adapter.Reason)
	}
	return bounded(strings.Join(parts, ":"), maxReasonBytes)
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// HostPrepareReport is the bounded JSON contract emitted by
// `tunnex-node k8s-host-prepare --apply`.
type HostPrepareReport struct {
	SchemaVersion int               `json:"schema_version"`
	Operation     string            `json:"operation"`
	Status        State             `json:"status"`
	Checks        []ComponentStatus `json:"checks"`
}

// Ready reports whether every required host check was applied and read back.
func (r HostPrepareReport) Ready() bool { return r.Status == StateReady }
