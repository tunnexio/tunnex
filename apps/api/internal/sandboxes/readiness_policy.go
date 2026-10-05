package sandboxes

import (
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type canonicalPolicyReader interface {
	PolicyHealthForNodes(context.Context, uuid.UUID, []sqlc.Node, ...nodes.SiteTopoBatch) map[uuid.UUID]nodes.PolicyHealth
}
type PolicyAcknowledgement struct {
	NodeID     uuid.UUID
	Hash       string
	ReportedAt time.Time
}

// CurrentPolicyAcknowledgements consumes the same finalized hash computation
// as node health. It conservatively includes all active organization gateways,
// bounded to 100. Legacy records retain this conservative gate.
func (s *Store) CurrentPolicyAcknowledgements(ctx context.Context, org, gateway uuid.UUID, reader canonicalPolicyReader) (acknowledgements []PolicyAcknowledgement, failure error) {
	started := time.Now()
	evaluated, duration := false, time.Duration(0)
	defer func() { failure = observePolicyGateFailure(failure, "legacy", started, evaluated, duration) }()
	if reader == nil || org == uuid.Nil || gateway == uuid.Nil {
		return nil, policyGateFailure("invalid_target", nil)
	}
	selected, err := sqlc.New(s.pool).ListActiveSandboxEnforcementNodes(ctx, org)
	if err != nil {
		return nil, policyGateFailure("nodes_lookup_failed", err)
	}
	if len(selected) == 0 || len(selected) > 100 {
		return nil, policyGateFailure("node_set_invalid", nil)
	}
	healthStarted := time.Now()
	health := reader.PolicyHealthForNodes(ctx, org, selected)
	evaluated, duration = true, time.Since(healthStarted)
	return validatePolicyAcknowledgements(time.Now().UTC(), org, gateway, selected, health)
}

// CurrentSandboxPolicyAcknowledgements selects the construction-bound terminal
// and runtime gateways. Legacy records retain organization-wide convergence.
func (s *Store) CurrentSandboxPolicyAcknowledgements(ctx context.Context, target PrivateNetworkTarget, reader canonicalPolicyReader) (acknowledgements []PolicyAcknowledgement, failure error) {
	started, mode := time.Now(), "unknown"
	evaluated, duration := false, time.Duration(0)
	defer func() { failure = observePolicyGateFailure(failure, mode, started, evaluated, duration) }()
	if reader == nil || target.SandboxID == uuid.Nil || target.OrgID == uuid.Nil || target.GatewayID == uuid.Nil || target.OperationID == uuid.Nil {
		return nil, policyGateFailure("invalid_target", nil)
	}
	var local, remoteTerminal, remoteRuntime pgtype.UUID
	err := s.pool.QueryRow(ctx, `SELECT s.local_terminal_gateway_id,r.terminal_gateway_id,r.runtime_gateway_id FROM sandboxes s JOIN sandbox_launch_operations l ON l.sandbox_id=s.id AND l.org_id=s.org_id LEFT JOIN sandbox_remote_terminal_routes r ON r.sandbox_id=s.id AND r.org_id=s.org_id AND r.terminal_device_id=s.terminal_device_id WHERE s.id=$1 AND s.org_id=$2 AND l.id=$3 AND l.gateway_node_id=$4 AND l.generation=$5 AND l.runtime_id=$6 AND l.spec_hash=$7`, target.SandboxID, target.OrgID, enrollmentOperation(target), target.GatewayID, target.Generation, target.RuntimeID, target.SpecHash).Scan(&local, &remoteTerminal, &remoteRuntime)
	if err != nil {
		return nil, policyGateFailure("binding_lookup_failed", nil)
	}
	selectedIDs := []uuid.UUID{}
	if remoteTerminal.Valid || remoteRuntime.Valid {
		mode = "remote"
		if local.Valid || !remoteTerminal.Valid || !remoteRuntime.Valid || uuid.UUID(remoteRuntime.Bytes) != target.GatewayID || remoteTerminal.Bytes == remoteRuntime.Bytes {
			return nil, policyGateFailure("binding_inconsistent", nil)
		}
		selectedIDs = append(selectedIDs, uuid.UUID(remoteTerminal.Bytes), target.GatewayID)
	} else if !local.Valid {
		mode = "legacy"
		return s.CurrentPolicyAcknowledgements(ctx, target.OrgID, target.GatewayID, reader)
	} else if uuid.UUID(local.Bytes) != target.GatewayID {
		mode = "local"
		return nil, policyGateFailure("binding_inconsistent", nil)
	} else {
		mode = "local"
		selectedIDs = append(selectedIDs, target.GatewayID)
	}
	selected := make([]sqlc.Node, 0, len(selectedIDs))
	for _, id := range selectedIDs {
		node, err := sqlc.New(s.pool).GetSandboxEnforcementNode(ctx, sqlc.GetSandboxEnforcementNodeParams{OrgID: target.OrgID, ID: id})
		if err != nil {
			gate := policyGateFailure("node_unavailable", nil)
			gate.nodeID = id // Validated construction-bound selection, not a returned foreign row.
			return nil, gate
		}
		selected = append(selected, node)
	}
	healthStarted := time.Now()
	health := reader.PolicyHealthForNodes(ctx, target.OrgID, selected)
	evaluated, duration = true, time.Since(healthStarted)
	return validatePolicyAcknowledgementsForLocal(time.Now().UTC(), target.OrgID, target.GatewayID, selected, health, true)
}

func validatePolicyAcknowledgements(now time.Time, org, gateway uuid.UUID, selected []sqlc.Node, health map[uuid.UUID]nodes.PolicyHealth) ([]PolicyAcknowledgement, error) {
	return validatePolicyAcknowledgementsForLocal(now, org, gateway, selected, health, false)
}
func validatePolicyAcknowledgementsForLocal(now time.Time, org, gateway uuid.UUID, selected []sqlc.Node, health map[uuid.UUID]nodes.PolicyHealth, local bool) ([]PolicyAcknowledgement, error) {
	if len(selected) == 0 || len(selected) > 100 {
		return nil, policyGateFailure("node_set_invalid", nil)
	}
	out := make([]PolicyAcknowledgement, 0, len(selected))
	seen := map[uuid.UUID]bool{}
	for _, node := range selected {
		// Preserve the existing admission order, omitting identities from
		// invalid/cross-organization evidence before taking a health snapshot.
		switch {
		case node.ID == uuid.Nil:
			return nil, policyGateFailure("node_id_missing", nil)
		case seen[node.ID]:
			return nil, policyGateFailure("duplicate_node", nil)
		case node.OrgID != org:
			return nil, policyGateFailure("node_org_mismatch", nil)
		}
		gate := policyGateFailure("", nil)
		gate.nodeID = node.ID
		if node.Status != "active" {
			gate.reason = "node_inactive"
			return nil, gate
		}
		value, ok := health[node.ID]
		gate.healthKnown = ok
		if ok {
			gate.pushKnown = value.PushKnown
			gate.hashesMatch = value.PushKnown && value.PushedHash != "" && value.PushedHash == value.AppliedHash
			gate.healthKind = normalizedPolicyHealthKind(value.Kind)
		}
		gate.reportKnown = node.PolicyReportedAt.Valid
		if gate.reportKnown {
			gate.reportAge = now.Sub(node.PolicyReportedAt.Time)
		}
		switch {
		case !ok:
			gate.reason = "health_unavailable"
		case !value.PushKnown:
			gate.reason = "desired_hash_unknown"
		case value.PushedHash == "":
			gate.reason = "desired_hash_missing"
		case value.PushedHash != value.AppliedHash:
			gate.reason = "hash_mismatch"
		case !acknowledgementHealth(node, value, local):
			gate.reason = "apply_unhealthy"
		case !node.PolicyReportedAt.Valid:
			gate.reason = "report_missing"
		}
		if gate.reason != "" {
			return nil, gate
		}
		age := now.Sub(node.PolicyReportedAt.Time)
		if age < 0 || age >= nodes.ReportFreshnessWindow {
			gate.reason = "report_stale"
			if age < 0 {
				gate.reason = "report_future"
			}
			return nil, gate
		}
		seen[node.ID] = true
		out = append(out, PolicyAcknowledgement{node.ID, value.PushedHash, node.PolicyReportedAt.Time})
	}
	if !seen[gateway] {
		return nil, policyGateFailure("gateway_missing", nil)
	}
	return out, nil
}

// Local terminals require policy convergence, not unrelated remote-site reachability.
// Apply/refusal signals are checked directly so advisory site health cannot mask them.
func acknowledgementHealth(node sqlc.Node, value nodes.PolicyHealth, local bool) bool {
	if !local {
		return !value.Degraded && value.Kind == nodes.KindHealthy
	}
	caps := nodes.Capabilities(node.Capabilities)
	if caps.PolicyError != "" || caps.PolicyFailingSince != "" || caps.PolicyRefusedVersion > 0 {
		return false
	}
	switch value.Kind {
	case nodes.KindHealthy:
		return !value.Degraded
	case nodes.KindSiteHubDown, nodes.KindSiteLinkDown, nodes.KindSiteSubnetUnreachable:
		return true
	default:
		return false
	}
}
