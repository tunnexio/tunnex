package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func diagnosticLog(t *testing.T, id uuid.UUID, failure error) (map[string]any, string) {
	t.Helper()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.LogAttrs(context.Background(), slog.LevelWarn, "sandbox_runtime_reconcile_pending", ReconcileLogAttrs(id, failure)...)
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal("decode structured diagnostic", err)
	}
	return record, output.String()
}

func TestPolicyGateDiagnosticLogDoesNotExposeEvidence(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	org, gateway, sandbox := uuid.New(), uuid.New(), uuid.New()
	const sentinel = "private-evidence-sentinel"
	tests := []struct {
		name   string
		reason string
		change func(*sqlc.Node, *nodes.PolicyHealth)
	}{
		{"unknown desired hash", "desired_hash_unknown", func(_ *sqlc.Node, h *nodes.PolicyHealth) {
			h.PushKnown = false
		}},
		{"hash mismatch", "hash_mismatch", func(_ *sqlc.Node, h *nodes.PolicyHealth) {
			h.PushedHash, h.AppliedHash = sentinel+"-desired", sentinel+"-applied"
		}},
		{"unknown health kind", "apply_unhealthy", func(_ *sqlc.Node, h *nodes.PolicyHealth) {
			h.Kind = nodes.PolicyDegradedKind(sentinel + "\nforged-log-entry")
		}},
		{"capability apply error", "apply_unhealthy", func(n *sqlc.Node, h *nodes.PolicyHealth) {
			n.Capabilities = []byte(`{"policy_error":"` + sentinel + `","policy_hash":"` + sentinel + `"}`)
			h.Kind, h.Degraded = nodes.KindSiteHubDown, true
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := sqlc.Node{ID: gateway, OrgID: org, Status: "active", PolicyReportedAt: pgtype.Timestamptz{Time: now.Add(-1250 * time.Millisecond), Valid: true}}
			health := nodes.PolicyHealth{Kind: nodes.KindHealthy, PushKnown: true, PushedHash: sentinel, AppliedHash: sentinel}
			tc.change(&node, &health)
			ack, failure := validatePolicyAcknowledgementsForLocal(now, org, gateway, []sqlc.Node{node}, map[uuid.UUID]nodes.PolicyHealth{gateway: health}, true)
			var gate *PolicyGateError
			if ack != nil || !errors.Is(failure, ErrDisabled) || !errors.As(failure, &gate) {
				t.Fatal("diagnostic changed denied admission or error compatibility", ack, failure)
			}
			failure = observePolicyGateFailure(failure, "remote", time.Now().Add(-time.Second), true, 1500*time.Microsecond)
			// Retry logging must traverse normal error wrappers without printing them.
			failure = &LaunchStageError{Stage: "readiness-policy-before", Cause: fmt.Errorf("%s: %w", sentinel, failure)}
			record, raw := diagnosticLog(t, sandbox, failure)
			if strings.Contains(raw, sentinel) || strings.Contains(failure.Error(), sentinel) {
				t.Fatal("diagnostic exposed private evidence", raw)
			}
			if record["stage"] != "readiness-policy-before" || record["sandbox_id"] != sandbox.String() || record["policy_node_id"] != gateway.String() || record["policy_gate_reason"] != tc.reason || record["policy_binding_mode"] != "remote" {
				t.Fatal("missing safe diagnostic identity or reason", record)
			}
			if record["policy_report_age_ms"] != float64(1250) || record["policy_health_evaluation_ms"] != float64(1.5) || record["policy_health_known"] != true || record["policy_report_known"] != true || record["policy_health_evaluated"] != true {
				t.Fatal("missing measured diagnostic facts", record)
			}
			if tc.name == "unknown health kind" && record["policy_health_kind"] != "unknown" {
				t.Fatal("unrecognized health kind was not normalized", record)
			}
			if tc.name == "hash mismatch" && record["policy_hashes_match"] != false {
				t.Fatal("mismatched hashes reported matching", record)
			}
			if tc.name == "unknown desired hash" && (record["policy_push_known"] != false || record["policy_hashes_match"] != false) {
				t.Fatal("known health snapshot misrepresented unknown desired policy", record)
			}
			assertDiagnosticKeys(t, record)
		})
	}
}

func TestPolicyGateDiagnosticUnknownFactsAndRawCause(t *testing.T) {
	org, gateway, sandbox := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	node := sqlc.Node{ID: gateway, OrgID: org, Status: "active"}
	_, failure := validatePolicyAcknowledgements(now, org, gateway, []sqlc.Node{node}, nil)
	record, _ := diagnosticLog(t, sandbox, failure)
	if record["policy_gate_reason"] != "health_unavailable" || record["policy_health_known"] != false || record["policy_report_known"] != false || record["policy_health_evaluated"] != false {
		t.Fatal("missing evidence became an affirmative observation", record)
	}
	for _, key := range []string{"policy_health_kind", "policy_push_known", "policy_hashes_match", "policy_report_age_ms", "policy_health_evaluation_ms"} {
		if _, exists := record[key]; exists {
			t.Fatal("unknown fact was logged as known", key, record)
		}
	}
	const sentinel = "private-database-error-sentinel"
	rawCause := fmt.Errorf("%s: %w", sentinel, ErrDisabled)
	gate := policyGateFailure("nodes_lookup_failed", rawCause)
	nested := &LaunchStageError{Stage: "readiness-policy-after", Cause: fmt.Errorf("nested retry: %w", gate)}
	var extracted *PolicyGateError
	if !errors.Is(nested, ErrDisabled) || !errors.Is(nested, rawCause) || !errors.As(nested, &extracted) || extracted != gate {
		t.Fatal("typed diagnostic broke nested error traversal")
	}
	record, raw := diagnosticLog(t, sandbox, nested)
	if strings.Contains(raw, sentinel) || strings.Contains(gate.Error(), sentinel) || record["stage"] != "readiness-policy-after" || record["policy_gate_reason"] != "nodes_lookup_failed" {
		t.Fatal("raw cause leaked or nested diagnostic disappeared", record)
	}
	assertDiagnosticKeys(t, record)

	// An invalid organization must not expose an unrelated node's identity.
	node.OrgID = uuid.New()
	_, failure = validatePolicyAcknowledgements(now, org, gateway, []sqlc.Node{node}, nil)
	record, _ = diagnosticLog(t, sandbox, failure)
	if _, exists := record["policy_node_id"]; exists || record["policy_gate_reason"] != "node_org_mismatch" {
		t.Fatal("invalid organization exposed a node identity", record)
	}
}

func TestPolicyGateDiagnosticEvaluationTimingIsObservedAndCopied(t *testing.T) {
	id := uuid.New()
	original := policyGateFailure("desired_hash_unknown", nil)
	inner := observePolicyGateFailure(original, "legacy", time.Now().Add(-time.Second), true, 0)
	// A legacy fallback's outer lookup has no independent health evaluation.
	outer := observePolicyGateFailure(inner, "legacy", time.Now().Add(-2*time.Second), false, 123*time.Second)
	record, _ := diagnosticLog(t, id, outer)
	if record["policy_health_evaluated"] != true || record["policy_health_evaluation_ms"] != float64(0) {
		t.Fatal("known zero-duration evaluation became unknown or was overwritten", record)
	}
	if duration, ok := record["policy_gate_ms"].(float64); !ok || duration < 2000 {
		t.Fatal("outer gate duration omitted lookup time", record)
	}
	unobserved, _ := diagnosticLog(t, id, original)
	if unobserved["policy_binding_mode"] != "unknown" || unobserved["policy_health_evaluated"] != false || unobserved["policy_gate_ms"] != float64(0) {
		t.Fatal("observation mutated the shared original error", unobserved)
	}
	if _, exists := unobserved["policy_health_evaluation_ms"]; exists {
		t.Fatal("unevaluated health emitted a measured duration", unobserved)
	}
	if observePolicyGateFailure(nil, "local", time.Now(), true, time.Second) != nil {
		t.Fatal("successful admission acquired a diagnostic failure")
	}
	if observePolicyGateFailure(ErrConflict, "local", time.Now(), true, time.Second) != ErrConflict {
		t.Fatal("unrelated failure changed classification")
	}
}

func TestReconcileDiagnosticNonPolicyFailureKeepsExistingLogShape(t *testing.T) {
	id := uuid.New()
	record, raw := diagnosticLog(t, id, errors.New("private-provider-error-sentinel"))
	if record["stage"] != "coordination" || record["sandbox_id"] != id.String() || len(record) != 5 || strings.Contains(raw, "private-provider-error-sentinel") {
		t.Fatal("non-policy retry changed log shape or exposed its error", record)
	}
}

func assertDiagnosticKeys(t *testing.T, record map[string]any) {
	t.Helper()
	allowed := map[string]bool{
		"time": true, "level": true, "msg": true, "sandbox_id": true, "stage": true,
		"policy_gate_reason": true, "policy_binding_mode": true, "policy_node_id": true,
		"policy_health_known": true, "policy_health_kind": true, "policy_push_known": true,
		"policy_hashes_match": true, "policy_report_known": true, "policy_report_age_ms": true,
		"policy_health_evaluated": true, "policy_health_evaluation_ms": true, "policy_gate_ms": true,
	}
	for key := range record {
		if !allowed[key] {
			t.Fatal("diagnostic emitted an unapproved field", key)
		}
	}
}
