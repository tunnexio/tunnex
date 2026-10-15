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
	DNSReadTiming                  *runtimeDNSReadTiming `json:",omitempty"`
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
		case "maintenance_authority", "maintenance_bgp_freshness", "maintenance_bridge_proof", "maintenance_candidate", "maintenance_candidate_authority", "maintenance_combined_guard", "maintenance_eligibility", "maintenance_eligibility_proof", "maintenance_final_binding", "maintenance_fresh_authority", "maintenance_input", "maintenance_journal", "maintenance_retained_bgp_reconcile", "maintenance_lease", "maintenance_lease_delivery", "maintenance_lease_revision", "maintenance_lease_policy", "maintenance_lease_nonce", "maintenance_lease_ttl", "maintenance_lease_active", "maintenance_lease_request", "maintenance_lease_parse", "maintenance_lease_transport_deadline", "maintenance_lease_transport_cancel", "maintenance_lease_transport_other", "maintenance_lease_http_400", "maintenance_lease_http_401", "maintenance_lease_http_403", "maintenance_lease_http_404", "maintenance_lease_http_409", "maintenance_lease_http_409_ineligible", "maintenance_lease_http_409_conflict", "maintenance_lease_http_429", "maintenance_lease_http_5xx", "maintenance_lease_http_other", "maintenance_material", "maintenance_material_current", "maintenance_material_withdraw", "maintenance_namespace", "maintenance_publish", "maintenance_publish_binding", "maintenance_report_contract", "maintenance_startup_gate", "maintenance_status":
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
	if operation == "dns_proof" || operation == "dns_before_proof" || operation == "dns_after_proof" {
		switch stage {
		case "dns_refusal_input", "dns_refusal_endpoint", "dns_refusal_addresses", "dns_refusal_binding", "dns_refusal_view", "dns_refusal_owner", "dns_refusal_active", "dns_refusal_grant", "dns_refusal_authority_before", "dns_refusal_native", "dns_refusal_slot", "dns_refusal_interface", "dns_refusal_guard_initial", "dns_refusal_source_before", "dns_refusal_route", "dns_refusal_source_after", "dns_refusal_authority_after", "dns_refusal_owner_before_final", "dns_refusal_view_final", "dns_refusal_guard_retry_budget", "dns_refusal_guard_retry", "dns_refusal_owner_final", "dns_refusal_guard_final":
			return true
		default:
			return false
		}
	}
	switch operation {
	case "maintenance_pulse", "native_proof", "maintenance", "maintenance_current", "recovery_observe", "recovery_apply", "recovery_refresh", "recovery_guard_denial", "apply", "bgp_apply", "validate", "heartbeat", "install_active", "guard_replace", "bgp_reconcile", "dns_proof", "dns_before_proof", "dns_after_proof", "dns_exchange", "underlay_mtu", "runtime_proof", "bgp_proof", "environment_observe", "cleanup":
	default:
		return false
	}
	switch stage {
	case "history", "history_entry", "history_epoch", "history_selection", "history_clock", "clock", "sample", "report_binding", "publish", "prior_reserve", "remember", "maintenance_qualification", "maintenance_candidate_qualification", "maintenance_candidate_report_reserve", "combined_guard_candidate_qualification", "combined_guard_final_prior_reserve", "combined_guard_prior_binding", "combined_guard_prior_reserve", "combined_guard_required_binding", "maintenance_active_pulse", "maintenance_authority_factory", "maintenance_begin", "maintenance_bgp_native_status", "maintenance_bgp_process", "maintenance_bgp_qualification", "maintenance_bgp_ready", "maintenance_bgp_routes", "maintenance_bgp_status", "maintenance_bgp_target", "maintenance_candidate_after_publish", "maintenance_candidate_binding", "maintenance_candidate_final", "maintenance_candidate_reserve", "maintenance_captured_owner", "maintenance_combined_install", "maintenance_current_after_fresh", "maintenance_current_before_fresh", "maintenance_exact_owner", "maintenance_final_context", "maintenance_final_prior_reserve", "maintenance_fresh_lease", "maintenance_journal_lineage", "maintenance_lease_accept", "maintenance_lease_binding", "maintenance_native_guard", "maintenance_native_proof", "maintenance_prior_reserve", "maintenance_publish", "maintenance_static_ready", "maintenance_status", "native_context_final", "native_daemon_alive", "native_environment_equal", "native_environment_observe", "native_inventory_after", "native_inventory_before", "native_kernel_after_equal", "native_kernel_after_read", "native_kernel_before_namespace", "native_kernel_before_read", "native_kernel_reader", "native_vici_after", "native_vici_before", "native_xfrm_after_equal", "native_xfrm_after_read", "native_xfrm_before_namespace", "native_xfrm_before_read", "native_xfrm_reader", "recovery_preparation", "transport_remove", "guard_fallback", "observation_window", "recovery_advice", "recovery_hold", "pending_target_observation", "route_selection", "active_install", "standby_retry", "inactive_history_inventory", "inactive_no_due_history", "inactive_no_denied_candidate", "prepared_binding", "input", "qualification", "material_contract", "journal_inventory", "startup_gate", "delivery_lineage", "environment", "journal_continuity", "bgp_apply", "static_apply", "bgp_qualification", "bgp_reconcile", "combined_guard", "permit_lease", "restored_transport", "transport_stage", "transport_initiate", "transport_retry", "native_current_proof", "journal_commit", "underlay_mtu", "active_continuity", "session_cleanup", "session_start", "route_initialization", "authority_binding", "remaining_authority", "native_status", "guard_denial_read", "native_current_proof_and_guard", "final_binding", "journal_sequence", "entry_current_proof", "entry_lease_remaining", "guard_projection", "entry_bgp_observation", "entry_static_observation", "entry_tunnel_mtu", "combined_guard_context", "combined_guard_authority", "entry_dns_source", "combined_guard_qualification", "entry_bgp_process", "combined_guard_replace", "combined_guard_final_binding", "combined_guard_final_lease", "guard_render", "guard_namespace", "guard_interfaces", "guard_table_read", "guard_prior_ownership", "guard_source_bracket", "guard_resolve_journal", "guard_prepare_journal", "guard_atomic_replace", "guard_complete_readback", "guard_finish_journal", "permit_freshness", "peer_summary_observation", "route_observation", "transport_status", "route_journal_binding", "route_guard_withdrawal", "route_commit_readback", "final_permit", "dns_input", "dns_endpoint", "dns_binding", "dns_owner", "dns_authority", "dns_grant", "dns_original_lease", "dns_native_proof", "dns_route_slot", "dns_guard", "dns_source_before", "dns_route", "dns_source_after", "dns_current_lease", "dns_epoch", "dns_latest_guard", "dns_before_proof", "dns_socket", "dns_socket_udp", "dns_socket_tcp", "dns_guard_template", "dns_guard_required", "dns_guard_full_read", "dns_guard_superseded_verified", "dns_guard_current_refused", "dns_after_proof", "dns_after_binding", "dns_latest_guard_stability", "dns_latest_guard_template", "dns_latest_guard_required", "dns_latest_guard_full_read", "dns_socket_tcp_input", "dns_socket_tcp_dial", "dns_socket_tcp_write", "dns_socket_tcp_length", "dns_socket_tcp_body", "dns_socket_tcp_complete", "dns_proof_before", "dns_proof_after", "dns_after_proof_refused", "dns_after_binding_refused", "dns_after_context_refused", "env_snapshot_before", "env_snapshot_after", "env_input", "env_namespace_before", "env_material", "env_hooks_before", "env_rules_before", "env_links_before", "env_routes_before", "env_addresses_before", "env_local_coverage", "env_peer_routes_before", "env_links_after", "env_rules_after", "env_hooks_after", "env_routes_after", "env_addresses_after", "env_peer_routes_after", "env_namespace_after", "env_complete", "proof_readers", "proof_xfrm_before", "proof_daemon_before", "proof_kernel_before", "proof_inventory_before", "proof_environment_observe", "proof_environment_binding", "proof_xfrm_after", "proof_daemon_after", "proof_kernel_after", "proof_complete", "proof_bgp_journal", "proof_bgp_routes", "proof_bgp_status", "proof_bgp_any_up", "mtu_dependencies", "mtu_environment_observe", "mtu_environment_binding", "mtu_kernel_snapshot", "mtu_owned_ceiling", "mtu_unchanged", "mtu_lowering", "mtu_final_environment_observe", "mtu_final_environment_binding", "mtu_lowered", "material_entry", "material_fqdn_withdraw", "material_fqdn_current", "material_bgp_qualification", "journal_handoff_refused", "journal_save_refused", "journal_boot_refused", "journal_restoration_refused", "journal_cleanup_phase_refused", "journal_retained_phase_refused", "journal_mismatch_lineage", "journal_mismatch_contract", "journal_mismatch_cleanup", "journal_mismatch_allocation", "journal_mismatch_engines", "journal_mismatch_history", "journal_mismatch_other", "cleanup_validation", "cleanup_journal_read", "cleanup_lineage", "cleanup_journal_commit", "cleanup_covered_lineage", "cleanup_install_active", "cleanup_environment", "cleanup_reset_receipt", "cleanup_prove_reset_absent", "cleanup_prove_absent", "cleanup_bgp_duties", "cleanup_remove_tunnel", "cleanup_kernel_remove", "cleanup_environment_drain", "cleanup_retained_guard_commit":
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

// DNS reads can be concurrent and high volume. Refusal diagnostics share one
// controller-wide one-second gate; this never affects packet admission.
func (c *RuntimeController) claimDNSDiagnostic(now time.Time) bool {
	n := now.UnixNano()
	for {
		previous := c.dnsDiagnosticAfter.Load()
		if n < previous {
			return false
		}
		if c.dnsDiagnosticAfter.CompareAndSwap(previous, n+int64(time.Second)) {
			return true
		}
	}
}

// Native phase timings describe existing BGP proof calls only. They confer no authority.
type runtimeEnvironmentTiming struct {
	CommandMillis, VerificationMillis int64
	CommandCount                      int
}

type runtimeNativePhaseTiming struct {
	Environment                                                                           runtimeEnvironmentTiming
	RouteMillis, RecoveryMillis, EnvironmentMillis, ElapsedMillis, RemainingAtEntryMillis int64
}

type runtimeDNSReadTiming struct {
	Native                                                                runtimeNativePhaseTiming
	GuardCommandMillis, GuardVerificationMillis, SocketMillis             int64
	GuardBracketCount                                                     int
	GuardFailureClass, SocketStage, GuardRevalidation, NativeFailureClass string
}

func (c *RuntimeController) emitDNSRuntimeDiagnostic(ctx context.Context, operation, stage string, connection uuid.UUID, started time.Time, refused bool, detail ...runtimeDNSReadTiming) {
	if c == nil || c.config.Diagnostic == nil || !refused || !validRuntimeDiagnostic(operation, stage) || !c.claimDNSDiagnostic(time.Now()) {
		return
	}
	if !c.config.DNSReadTiming || len(detail) != 1 || !validDNSReadTiming(detail[0]) {
		c.emitRuntimeDiagnostic(ctx, operation, stage, connection, started, true)
		return
	}
	timing := detail[0]
	callback := c.config.Diagnostic
	emitRuntimeDiagnostic(func(event RuntimeDiagnostic) { event.DNSReadTiming = &timing; callback(event) }, ctx, operation, stage, connection, started, true)
}

// This private telemetry can never contain an error body or DNS data.
func validDNSReadTiming(t runtimeDNSReadTiming) bool {
	if t.Native.Environment.CommandMillis < 0 || t.Native.Environment.CommandMillis > 60000 || t.Native.Environment.VerificationMillis < 0 || t.Native.Environment.VerificationMillis > 60000 || t.Native.Environment.CommandCount < 0 || t.Native.Environment.CommandCount > 18 {
		return false
	}
	for _, value := range []int64{t.Native.RouteMillis, t.Native.RecoveryMillis, t.Native.EnvironmentMillis, t.Native.ElapsedMillis, t.Native.RemainingAtEntryMillis} {
		if value < 0 || value > 60000 {
			return false
		}
	}
	if t.GuardCommandMillis < 0 || t.GuardVerificationMillis < 0 || t.SocketMillis < 0 || t.GuardCommandMillis > 60000 || t.GuardVerificationMillis > 60000 || t.SocketMillis > 60000 || t.GuardBracketCount < 0 || t.GuardBracketCount > 4 {
		return false
	}
	switch t.GuardFailureClass {
	case "", "none", "target_not_permitted", "structural_or_read", "interface_mapping", "observed_invalid", "object_count", "nonset_mismatch", "nonset_kind_mismatch", "table_mismatch", "chain_mismatch", "rule_mismatch", "owner_structure_mismatch", "owner_comment_mismatch", "owner_revision_mismatch", "owner_digest_mismatch", "owner_revision_digest_mismatch", "set_member_mismatch", "set_metadata_mismatch", "required_set_missing", "context_deadline", "context_canceled":
	default:
		return false
	}
	switch t.GuardRevalidation {
	case "", "input_refused", "latest_absent", "latest_unchanged", "owner_entry_refused", "latest_guard_refused", "digest_changed_again", "final_owner_entry_refused", "context_inactive", "accepted":
	default:
		return false
	}
	if !validNativeFailureClass(t.NativeFailureClass) {
		return false
	}
	switch t.SocketStage {
	case "", "input", "dial", "write", "length", "body", "complete":
	default:
		return false
	}
	return true
}

func validNativeFailureClass(reason string) bool {
	switch reason {
	case "", "binding_invalid", "route_read_or_binding", "daemon_read", "kernel_read", "xfrm_read", "kernel_snapshot_changed", "xfrm_snapshot_changed", "owned_status_unknown", "all_tunnels_down", "environment_read_or_validation", "environment_changed", "context_deadline", "context_canceled":
		return true
	}
	return false
}
func reportNativeFailure(ctx context.Context, observe func(string), reason string) {
	if observe == nil {
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		reason = "context_deadline"
	} else if ctx.Err() != nil {
		reason = "context_canceled"
	}
	observe(reason)
}
