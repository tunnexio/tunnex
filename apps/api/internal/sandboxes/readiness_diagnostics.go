package sandboxes

import (
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// PolicyGateError carries operator observations only. No node capability,
// policy/hash content or raw cause enters its message or log attributes.
type PolicyGateError struct {
	reason, bindingMode, healthKind string
	nodeID                          uuid.UUID
	healthKnown, pushKnown          bool
	hashesMatch, reportKnown        bool
	reportAge                       time.Duration
	healthEvaluated                 bool
	healthDuration, gateDuration    time.Duration
	cause                           error
}

func (e *PolicyGateError) Error() string { return "sandbox policy gate pending: " + e.reason }
func (e *PolicyGateError) Unwrap() error { return e.cause }

func policyGateFailure(reason string, cause error) *PolicyGateError {
	if cause == nil {
		cause = ErrDisabled
	}
	return &PolicyGateError{reason: reason, bindingMode: "unknown", healthKind: "unknown", cause: cause}
}

func observePolicyGateFailure(failure error, bindingMode string, started time.Time, evaluated bool, duration time.Duration) error {
	var gate *PolicyGateError
	if !errors.As(failure, &gate) {
		return failure
	}
	// Copy rather than modify a nested/shared error. A legacy fallback's health
	// evaluation remains known when its outer binding lookup did not evaluate it.
	observed := *gate
	observed.bindingMode = bindingMode
	observed.gateDuration = time.Since(started)
	if evaluated {
		observed.healthEvaluated, observed.healthDuration = true, duration
	}
	return &observed
}

func normalizedPolicyHealthKind(kind nodes.PolicyDegradedKind) string {
	for _, known := range nodes.AllKinds() {
		if kind == known {
			return string(known)
		}
	}
	return "unknown"
}

// ReconcileLogAttrs is the single explicit allowlist for operator retry logs.
// The caller must not add failure.Error(), its cause, or a policy payload.
func ReconcileLogAttrs(id uuid.UUID, failure error) []slog.Attr {
	stage := "coordination"
	var launch *LaunchStageError
	if errors.As(failure, &launch) {
		stage = launch.Stage
	}
	attrs := []slog.Attr{slog.String("sandbox_id", id.String()), slog.String("stage", stage)}
	var gate *PolicyGateError
	if !errors.As(failure, &gate) {
		return attrs
	}
	attrs = append(attrs,
		slog.String("policy_gate_reason", gate.reason),
		slog.String("policy_binding_mode", gate.bindingMode),
		slog.Bool("policy_health_known", gate.healthKnown),
		slog.Bool("policy_report_known", gate.reportKnown),
		slog.Bool("policy_health_evaluated", gate.healthEvaluated),
		slog.Float64("policy_gate_ms", float64(gate.gateDuration)/float64(time.Millisecond)))
	if gate.nodeID != uuid.Nil {
		attrs = append(attrs, slog.String("policy_node_id", gate.nodeID.String()))
	}
	if gate.healthKnown {
		attrs = append(attrs,
			slog.String("policy_health_kind", gate.healthKind),
			slog.Bool("policy_push_known", gate.pushKnown),
			slog.Bool("policy_hashes_match", gate.hashesMatch))
	}
	if gate.reportKnown {
		attrs = append(attrs, slog.Float64("policy_report_age_ms", float64(gate.reportAge)/float64(time.Millisecond)))
	}
	if gate.healthEvaluated {
		attrs = append(attrs, slog.Float64("policy_health_evaluation_ms", float64(gate.healthDuration)/float64(time.Millisecond)))
	}
	return attrs
}
