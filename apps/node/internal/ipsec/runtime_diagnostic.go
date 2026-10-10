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
	DNSReadTiming                  *runtimeDNSReadTiming
}

func validRuntimeDiagnostic(operation, stage string) bool {
	switch operation {
	case "cleanup", "apply", "bgp_apply", "validate", "heartbeat", "install_active", "guard_replace", "bgp_reconcile", "dns_proof", "dns_before_proof", "dns_after_proof", "dns_exchange":
	default:
		return false
	}
	switch stage {
	case "cleanup_validation", "cleanup_journal_read", "cleanup_lineage", "cleanup_journal_commit", "cleanup_covered_lineage", "cleanup_install_active", "cleanup_environment", "cleanup_reset_receipt", "cleanup_prove_reset_absent", "cleanup_prove_absent", "cleanup_bgp_duties", "cleanup_remove_tunnel", "cleanup_kernel_remove", "cleanup_environment_drain", "cleanup_retained_guard_commit", "input", "qualification", "material_contract", "journal_inventory", "startup_gate", "delivery_lineage", "environment", "journal_continuity", "bgp_apply", "static_apply", "bgp_qualification", "bgp_reconcile", "combined_guard", "permit_lease", "restored_transport", "transport_stage", "transport_initiate", "transport_retry", "native_current_proof", "journal_commit", "underlay_mtu", "active_continuity", "session_cleanup", "session_start", "route_initialization", "authority_binding", "remaining_authority", "native_status", "guard_denial_read", "native_current_proof_and_guard", "final_binding", "journal_sequence", "entry_current_proof", "entry_lease_remaining", "guard_projection", "entry_bgp_observation", "entry_static_observation", "entry_tunnel_mtu", "combined_guard_context", "combined_guard_authority", "entry_dns_source", "combined_guard_qualification", "entry_bgp_process", "combined_guard_replace", "combined_guard_final_binding", "combined_guard_final_lease", "guard_render", "guard_namespace", "guard_interfaces", "guard_table_read", "guard_prior_ownership", "guard_source_bracket", "guard_resolve_journal", "guard_prepare_journal", "guard_atomic_replace", "guard_complete_readback", "guard_finish_journal", "permit_freshness", "peer_summary_observation", "route_observation", "transport_status", "route_journal_binding", "route_guard_withdrawal", "route_commit_readback", "final_permit", "dns_input", "dns_endpoint", "dns_binding", "dns_owner", "dns_authority", "dns_grant", "dns_original_lease", "dns_native_proof", "dns_route_slot", "dns_guard", "dns_source_before", "dns_route", "dns_source_after", "dns_current_lease", "dns_epoch", "dns_latest_guard", "dns_before_proof", "dns_socket", "dns_socket_udp", "dns_socket_tcp", "dns_socket_tcp_input", "dns_socket_tcp_dial", "dns_socket_tcp_write", "dns_socket_tcp_length", "dns_socket_tcp_body", "dns_socket_tcp_complete", "dns_guard_template", "dns_guard_required", "dns_guard_full_read", "dns_latest_guard_template", "dns_latest_guard_required", "dns_latest_guard_full_read", "dns_latest_guard_stability", "dns_guard_superseded_verified", "dns_guard_current_refused", "dns_after_proof", "dns_after_binding":
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

type runtimeDNSReadTiming struct {
	GuardCommandMillis, GuardVerificationMillis, SocketMillis int64
	GuardBracketCount                                         int
	GuardFailureClass, SocketStage, GuardRevalidation         string
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
	switch t.SocketStage {
	case "", "input", "dial", "write", "length", "body", "complete":
	default:
		return false
	}
	return true
}
