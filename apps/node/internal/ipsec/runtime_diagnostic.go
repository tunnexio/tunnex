package ipsec

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// RuntimeDiagnostic contains only fixed local stage names and timing. It has
// no error body, material, credentials, configuration or forwarding authority.
type RuntimeDiagnostic struct {
	Operation, Stage, ContextState string
	ConnectionID                   uuid.UUID
	ElapsedMillis                  int64
	Refused                        bool
}

func validRuntimeDiagnostic(operation, stage string) bool {
	switch operation {
	case "apply", "bgp_apply", "validate", "heartbeat", "install_active", "guard_replace", "bgp_reconcile", "underlay_mtu", "runtime_proof", "bgp_proof":
	default:
		return false
	}
	switch stage {
	case "proof_readers", "proof_xfrm_before", "proof_daemon_before", "proof_kernel_before", "proof_inventory_before", "proof_environment_observe", "proof_environment_binding", "proof_xfrm_after", "proof_daemon_after", "proof_kernel_after", "proof_complete", "proof_bgp_journal", "proof_bgp_routes", "proof_bgp_status", "proof_bgp_any_up", "mtu_dependencies", "mtu_environment_observe", "mtu_environment_binding", "mtu_kernel_snapshot", "mtu_owned_ceiling", "mtu_unchanged", "mtu_lowering", "mtu_final_environment_observe", "mtu_final_environment_binding", "mtu_lowered", "input", "qualification", "material_contract", "journal_inventory", "startup_gate", "delivery_lineage", "environment", "journal_continuity", "bgp_apply", "static_apply", "bgp_qualification", "bgp_reconcile", "combined_guard", "permit_lease", "restored_transport", "transport_stage", "transport_initiate", "transport_retry", "native_current_proof", "journal_commit", "underlay_mtu", "active_continuity", "session_cleanup", "session_start", "route_initialization", "authority_binding", "remaining_authority", "native_status", "guard_denial_read", "native_current_proof_and_guard", "final_binding", "journal_sequence", "entry_current_proof", "entry_lease_remaining", "guard_projection", "entry_bgp_observation", "entry_static_observation", "entry_tunnel_mtu", "combined_guard_context", "combined_guard_authority", "entry_dns_source", "combined_guard_qualification", "entry_bgp_process", "combined_guard_replace", "combined_guard_final_binding", "combined_guard_final_lease", "guard_render", "guard_namespace", "guard_interfaces", "guard_table_read", "guard_prior_ownership", "guard_source_bracket", "guard_resolve_journal", "guard_prepare_journal", "guard_atomic_replace", "guard_complete_readback", "guard_finish_journal", "permit_freshness", "peer_summary_observation", "route_observation", "transport_status", "route_journal_binding", "route_guard_withdrawal", "route_commit_readback", "final_permit":
		return true
	}
	return false
}

func (c *RuntimeController) emitRuntimeDiagnostic(ctx context.Context, operation, stage string, connection uuid.UUID, started time.Time, refused bool) {
	if c == nil {
		return
	}
	emitRuntimeDiagnostic(c.config.Diagnostic, ctx, operation, stage, connection, started, refused)
}

func emitRuntimeDiagnostic(callback func(RuntimeDiagnostic), ctx context.Context, operation, stage string, connection uuid.UUID, started time.Time, refused bool) {
	if callback == nil || !validRuntimeDiagnostic(operation, stage) {
		return
	}
	state := "active"
	if ctx != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			state = "deadline"
		} else if ctx.Err() != nil {
			state = "canceled"
		}
	}
	elapsed := time.Since(started).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	callback(RuntimeDiagnostic{Operation: operation, Stage: stage, ConnectionID: connection, ElapsedMillis: elapsed, Refused: refused, ContextState: state})
}
