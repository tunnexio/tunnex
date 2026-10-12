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
	if operation == "maintenance_eligibility" {
		switch stage {
		case "eligibility_active", "eligibility_current", "eligibility_lineage", "eligibility_observe", "eligibility_namespace", "eligibility_phase", "eligibility_contract", "eligibility_entry_current", "eligibility_active_entry", "eligibility_delivery", "eligibility_environment", "eligibility_grants", "eligibility_identity", "eligibility_authority", "eligibility_recovery", "eligibility_bgp", "eligibility_proof":
			return true
		default:
			return false
		}
	}

	if operation == "maintenance" {
		switch stage {
		case "maintenance_authority", "maintenance_bgp_freshness", "maintenance_bridge_proof", "maintenance_candidate", "maintenance_candidate_authority", "maintenance_combined_guard", "maintenance_eligibility", "maintenance_eligibility_proof", "maintenance_final_binding", "maintenance_fresh_authority", "maintenance_input", "maintenance_journal", "maintenance_lease", "maintenance_lease_delivery", "maintenance_lease_revision", "maintenance_lease_policy", "maintenance_lease_nonce", "maintenance_lease_ttl", "maintenance_lease_active", "maintenance_lease_request", "maintenance_lease_parse", "maintenance_lease_transport_deadline", "maintenance_lease_transport_cancel", "maintenance_lease_transport_other", "maintenance_lease_http_400", "maintenance_lease_http_401", "maintenance_lease_http_403", "maintenance_lease_http_404", "maintenance_lease_http_409", "maintenance_lease_http_429", "maintenance_lease_http_5xx", "maintenance_lease_http_other", "maintenance_material", "maintenance_material_current", "maintenance_material_withdraw", "maintenance_namespace", "maintenance_publish", "maintenance_publish_binding", "maintenance_report_contract", "maintenance_startup_gate", "maintenance_status":
			return true
		default:
			return false
		}
	}
	if operation == "maintenance_current" {
		switch stage {
		case "maintenance_current_authority_after", "maintenance_current_authority_before", "maintenance_current_bgp_binding", "maintenance_current_bgp_health", "maintenance_current_bgp_process", "maintenance_current_bgp_qualification", "maintenance_current_bgp_routes", "maintenance_current_bgp_status", "maintenance_current_final_qualification", "maintenance_current_guard", "maintenance_current_native":
			return true
		default:
			return false
		}
	}
	if operation == "dns_proof" {
		switch stage {
		case "dns_refusal_input", "dns_refusal_endpoint", "dns_refusal_addresses", "dns_refusal_binding", "dns_refusal_view", "dns_refusal_owner", "dns_refusal_active", "dns_refusal_grant", "dns_refusal_authority_before", "dns_refusal_native", "dns_refusal_slot", "dns_refusal_interface", "dns_refusal_guard_initial", "dns_refusal_source_before", "dns_refusal_route", "dns_refusal_source_after", "dns_refusal_authority_after", "dns_refusal_owner_before_final", "dns_refusal_view_final", "dns_refusal_guard_retry_budget", "dns_refusal_guard_retry", "dns_refusal_owner_final", "dns_refusal_guard_final":
			return true
		default:
			return false
		}
	}
	switch operation {
	case "dns_exchange", "apply", "bgp_apply", "validate", "heartbeat", "install_active", "guard_replace", "bgp_reconcile", "underlay_mtu", "runtime_proof", "bgp_proof", "environment_observe":
	default:
		return false
	}
	switch stage {

	case "dns_proof_before", "dns_socket", "dns_proof_after", "dns_after_proof_refused", "dns_after_binding_refused", "dns_after_context_refused", "env_input", "env_namespace_before", "env_material", "env_hooks_before", "env_rules_before", "env_links_before", "env_routes_before", "env_addresses_before", "env_local_coverage", "env_peer_routes_before", "env_links_after", "env_rules_after", "env_hooks_after", "env_routes_after", "env_addresses_after", "env_peer_routes_after", "env_namespace_after", "env_complete", "proof_readers", "proof_xfrm_before", "proof_daemon_before", "proof_kernel_before", "proof_inventory_before", "proof_environment_observe", "proof_environment_binding", "proof_xfrm_after", "proof_daemon_after", "proof_kernel_after", "proof_complete", "proof_bgp_journal", "proof_bgp_routes", "proof_bgp_status", "proof_bgp_any_up", "mtu_dependencies", "mtu_environment_observe", "mtu_environment_binding", "mtu_kernel_snapshot", "mtu_owned_ceiling", "mtu_unchanged", "mtu_lowering", "mtu_final_environment_observe", "mtu_final_environment_binding", "mtu_lowered", "input", "qualification", "material_contract", "material_entry", "material_fqdn_withdraw", "material_fqdn_current", "material_bgp_qualification", "journal_handoff_refused", "journal_save_refused", "journal_boot_refused", "journal_restoration_refused", "journal_cleanup_phase_refused", "journal_retained_phase_refused", "journal_mismatch_lineage", "journal_mismatch_contract", "journal_mismatch_cleanup", "journal_mismatch_allocation", "journal_mismatch_engines", "journal_mismatch_history", "journal_mismatch_other", "journal_inventory", "startup_gate", "delivery_lineage", "environment", "journal_continuity", "bgp_apply", "static_apply", "bgp_qualification", "bgp_reconcile", "combined_guard", "permit_lease", "restored_transport", "transport_stage", "transport_initiate", "transport_retry", "native_current_proof", "journal_commit", "underlay_mtu", "active_continuity", "session_cleanup", "session_start", "route_initialization", "authority_binding", "remaining_authority", "native_status", "guard_denial_read", "native_current_proof_and_guard", "final_binding", "journal_sequence", "entry_current_proof", "entry_lease_remaining", "guard_projection", "entry_bgp_observation", "entry_static_observation", "entry_tunnel_mtu", "combined_guard_context", "combined_guard_authority", "entry_dns_source", "combined_guard_qualification", "entry_bgp_process", "combined_guard_replace", "combined_guard_final_binding", "combined_guard_final_lease", "guard_render", "guard_namespace", "guard_interfaces", "guard_table_read", "guard_prior_ownership", "guard_source_bracket", "guard_resolve_journal", "guard_prepare_journal", "guard_atomic_replace", "guard_complete_readback", "guard_finish_journal", "permit_freshness", "peer_summary_observation", "route_observation", "transport_status", "route_journal_binding", "route_guard_withdrawal", "route_commit_readback", "final_permit":
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
