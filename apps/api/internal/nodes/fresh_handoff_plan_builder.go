package nodes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

const (
	freshHandoffLeaseTTL      = 30 * time.Second
	freshHandoffPostCASBudget = 90 * time.Second
)

// BuildAndClaimFreshHandoffPlanWithLeadership is the production P1/P2 claim
// writer.  It derives all four immutable artifacts from the locked current
// serving manifest and the locked CP topology, then persists the claim before
// releasing either the transaction or scheduler-leader session.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) BuildAndClaimFreshHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	if s == nil || s.pool == nil || conn == nil || !validHandoffPlanIntent(intent) || intent.Existing || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return k8s.DurableHandoffPlan{}, false, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	leaderEpoch := PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: leaderEpoch, Conn: conn}); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leaderEpoch); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	topology, found, err := loadHandoffBootstrapTopology(ctx, tx, intent.Scope)
	if errors.Is(err, ErrHandoffBootstrapPlanRefused) || errors.Is(err, pgx.ErrNoRows) || !found {
		logFreshHandoffClaimUnavailable(intent.Scope, "topology", err)
		return k8s.DurableHandoffPlan{}, false, nil
	}
	if err != nil {
		logFreshHandoffClaimUnavailable(intent.Scope, "topology_error", err)
		return k8s.DurableHandoffPlan{}, false, err
	}
	if topology.Generation != intent.ExpectedGeneration || topology.ActiveNodeID != intent.ExpectedActiveID {
		logFreshHandoffClaimUnavailable(intent.Scope, "topology_mismatch", nil)
		return k8s.DurableHandoffPlan{}, false, nil
	}
	claim, err := buildFreshHandoffClaim(ctx, tx, time.Now().UTC(), topology, intent)
	if err != nil {
		if errors.Is(err, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused) {
			logFreshHandoffClaimUnavailable(intent.Scope, "build", err)
			return k8s.DurableHandoffPlan{}, false, nil
		}
		logFreshHandoffClaimUnavailable(intent.Scope, "build_error", err)
		return k8s.DurableHandoffPlan{}, false, err
	}
	prepared, err := preparePoolVIPOwnershipFreshHandoffClaim(claim)
	if err != nil {
		logFreshHandoffClaimUnavailable(intent.Scope, "prepare", err)
		return k8s.DurableHandoffPlan{}, false, err
	}
	if err := persistPoolVIPOwnershipFreshHandoffClaim(ctx, tx, prepared); err != nil {
		logFreshHandoffClaimUnavailable(intent.Scope, "persist", err)
		return k8s.DurableHandoffPlan{}, false, err
	}
	created, err := sqlc.New(tx).CreateOrResumeK8sConnectorHandoffOperation(ctx, k8s.CreateOperationParams(claim.Plan, epoch, intent.ObservedMembershipEpoch))
	if err != nil {
		logFreshHandoffClaimUnavailable(intent.Scope, "create_operation", err)
		return k8s.DurableHandoffPlan{}, false, err
	}
	if created.ID != intent.OperationID {
		return k8s.DurableHandoffPlan{}, false, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leaderEpoch); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	return claim.Plan, true, nil
}

func logFreshHandoffClaimUnavailable(scope k8s.HandoffPoolScope, stage string, err error) {
	args := []any{"org_id", scope.OrgID, "site_id", scope.SiteID, "cluster_id", scope.ClusterID, "pool_id", scope.PoolID, "stage", stage}
	if err != nil {
		args = append(args, "error", err)
	}
	slog.Default().Warn("k8s_ha_fresh_handoff_claim_unavailable", args...)
}

func buildFreshHandoffClaim(ctx context.Context, tx pgx.Tx, now time.Time, topology handoffBootstrapTopology, intent HandoffTickIntent) (PoolVIPOwnershipFreshHandoffClaim, error) {
	if now.IsZero() || !validHandoffPlanIntent(intent) || topology.Scope != intent.Scope || topology.Generation != intent.ExpectedGeneration || topology.ActiveNodeID != intent.ExpectedActiveID {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	_, old, err := scanPoolVIPOwnershipDeliveryV3(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV3Select+` WHERE wire_version=3 AND org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4 AND connector_node_id=$5 AND target_node_id=$5 AND promotion_generation=$6 AND role='serving' AND expires_at>clock_timestamp() AND EXISTS (SELECT 1 FROM pool_vip_ownership_delivery_ack_receipts a WHERE a.delivery_row_id=pool_vip_ownership_deliveries.id AND a.org_id=pool_vip_ownership_deliveries.org_id) ORDER BY manifest_revision DESC,created_at DESC LIMIT 1 FOR UPDATE`,
		intent.Scope.OrgID, intent.Scope.SiteID, intent.Scope.ClusterID, intent.Scope.PoolID, intent.ExpectedActiveID, int64(intent.ExpectedGeneration)))
	if err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if ValidatePoolVIPOwnershipDeliveryEnvelopeV3(old) != nil || old.Role != policyspec.PoolVIPOwnershipServing {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	counters := map[uuid.UUID]handoffBootstrapCounter{}
	for _, member := range topology.Members {
		var revision, lease int64
		if err := tx.QueryRow(ctx, `SELECT manifest_revision,lease_epoch FROM pool_vip_ownership_delivery_states WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4 AND connector_node_id=$5 FOR UPDATE`, intent.Scope.OrgID, intent.Scope.SiteID, intent.Scope.ClusterID, intent.Scope.PoolID, member.NodeID).Scan(&revision, &lease); err != nil || revision <= 0 || lease <= 0 {
			return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		counters[member.NodeID] = handoffBootstrapCounter{ManifestRevision: uint64(revision), LeaseEpoch: uint64(lease)}
	}
	oldCounter, oldOK := counters[intent.ExpectedActiveID]
	newCounter, newOK := counters[intent.CandidateID]
	if !oldOK || !newOK || oldCounter.ManifestRevision == math.MaxInt64 || newCounter.ManifestRevision >= math.MaxInt64-1 {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	targetEpoch := oldCounter.LeaseEpoch
	if newCounter.LeaseEpoch > targetEpoch {
		targetEpoch = newCounter.LeaseEpoch
	}
	if targetEpoch == math.MaxInt64 {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	targetEpoch++
	targetExpiry := canonicalPoolVIPOwnershipDeliveryExpiry(now.Truncate(freshHandoffLeaseTTL).Add(2 * freshHandoffLeaseTTL))
	minimumTargetExpiry := canonicalPoolVIPOwnershipDeliveryExpiry(old.ExpiresAt.Add(freshHandoffPostCASBudget))
	if targetExpiry.Before(minimumTargetExpiry) {
		targetExpiry = minimumTargetExpiry
	}
	if !targetExpiry.After(now) {
		return PoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}

	oldManifest := cloneFreshHandoffManifest(old.Manifest)
	oldManifest.HandoffOwnerID = intent.OperationID.String()
	oldManifest.ManifestRevision = old.ManifestRevision
	oldManifest.LeaseEpoch = old.LeaseEpoch
	oldManifest.LeaseExpiresAt = old.ExpiresAt
	oldManifestIdentity, err := policyspec.PoolVIPOwnershipManifestIdentity(oldManifest.policyManifest())
	if err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, err
	}
	preparedManifest := freshHandoffManifest(old.Manifest, intent.CandidateID, policyspec.PoolVIPOwnershipPreparedNonServing, intent.TargetGeneration, newCounter.ManifestRevision+1, targetEpoch, targetExpiry, intent.OperationID, false)
	withdrawalManifest := freshHandoffManifest(old.Manifest, intent.ExpectedActiveID, policyspec.PoolVIPOwnershipWithdrawal, intent.TargetGeneration, oldCounter.ManifestRevision+1, targetEpoch, targetExpiry, intent.OperationID, false)
	servingManifest := freshHandoffManifest(old.Manifest, intent.CandidateID, policyspec.PoolVIPOwnershipServing, intent.TargetGeneration, newCounter.ManifestRevision+2, targetEpoch, targetExpiry, intent.OperationID, true)

	oldArtifact := freshArtifactFromManifest(oldManifest, oldManifestIdentity, old.ExpectedRouteDigest, old.ExpectedVIPMapDigest, old.ExpiresAt, k8s.Serving)
	preparedArtifact, err := freshArtifactForManifest(preparedManifest, k8s.PreparedNonServing)
	if err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, err
	}
	withdrawalArtifact, err := freshArtifactForManifest(withdrawalManifest, k8s.PreparedNonServing)
	if err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, err
	}
	servingArtifact, err := freshArtifactForManifest(servingManifest, k8s.Serving)
	if err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, err
	}
	plan := k8s.DurableHandoffPlan{OldLeaseIdentity: "delivery:" + old.DeliveryID, TargetLeaseIdentity: "handoff:" + intent.OperationID.String(), Plan: k8s.HandoffPlan{
		OperationID: intent.OperationID, Scope: intent.Scope, ExpectedActiveID: intent.ExpectedActiveID, CandidateID: intent.CandidateID,
		ExpectedGeneration: intent.ExpectedGeneration, TargetGeneration: intent.TargetGeneration, Decision: intent.Decision,
		OldServing: oldArtifact, NewPrepared: preparedArtifact, OldWithdrawal: withdrawalArtifact, NewServing: servingArtifact,
	}}
	if err := k8s.ValidateDurableHandoffPlan(plan); err != nil {
		return PoolVIPOwnershipFreshHandoffClaim{}, fmt.Errorf("%w: %v", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused, err)
	}
	manifests := map[k8s.P2HandoffArtifact]PoolVIPOwnershipManifestV3{
		k8s.P2OldServingArtifact: oldManifest, k8s.P2NewPreparedArtifact: preparedManifest,
		k8s.P2OldWithdrawalArtifact: withdrawalManifest, k8s.P2NewServingArtifact: servingManifest,
	}
	artifacts := make([]PoolVIPOwnershipFreshHandoffArtifact, 0, 4)
	for _, which := range []k8s.P2HandoffArtifact{k8s.P2OldServingArtifact, k8s.P2NewPreparedArtifact, k8s.P2OldWithdrawalArtifact, k8s.P2NewServingArtifact} {
		envelope, err := freshHandoffEnvelope(plan, which, manifests[which])
		if err != nil {
			return PoolVIPOwnershipFreshHandoffClaim{}, err
		}
		artifacts = append(artifacts, PoolVIPOwnershipFreshHandoffArtifact{Which: which, Envelope: envelope, ExpiresAt: envelope.ExpiresAt})
	}
	serviceUIDs := make([]PoolVIPOwnershipFreshHandoffServiceUID, 0, len(topology.Services))
	for _, service := range topology.Services {
		serviceUIDs = append(serviceUIDs, PoolVIPOwnershipFreshHandoffServiceUID{ActiveNodeID: intent.ExpectedActiveID, PromotionGeneration: intent.ExpectedGeneration, Namespace: service.Namespace, Service: service.Name, UID: service.UID, ObservationRevision: service.ObservationRevision})
	}
	return PoolVIPOwnershipFreshHandoffClaim{Intent: intent, Plan: plan, MembershipSnapshot: append([]uuid.UUID(nil), intent.OrderedCandidateIDs...), ServiceUIDs: serviceUIDs, Artifacts: artifacts}, nil
}

func cloneFreshHandoffManifest(in PoolVIPOwnershipManifestV3) PoolVIPOwnershipManifestV3 {
	out := in
	out.WGPeers = append([]PoolVIPOwnershipWGPeerV3(nil), in.WGPeers...)
	for i := range out.WGPeers {
		out.WGPeers[i].AllowedIPs = append([]string(nil), in.WGPeers[i].AllowedIPs...)
	}
	out.Routes = append([]string(nil), in.Routes...)
	out.Services = append([]PoolVIPOwnershipServiceV3(nil), in.Services...)
	return out
}

func freshHandoffManifest(base PoolVIPOwnershipManifestV3, node uuid.UUID, role string, generation, revision, lease uint64, expires time.Time, operation uuid.UUID, serving bool) PoolVIPOwnershipManifestV3 {
	m := cloneFreshHandoffManifest(base)
	m.ConnectorNodeID, m.Role, m.PromotionGeneration, m.ManifestRevision = node.String(), role, generation, revision
	m.LeaseEpoch, m.LeaseExpiresAt, m.HandoffOwnerID = lease, expires, operation.String()
	if serving {
		m.RouteIntent = "serving"
	} else {
		m.RouteIntent, m.WGPeers, m.Routes, m.Services = "non_serving", []PoolVIPOwnershipWGPeerV3{}, nil, nil
		if role == policyspec.PoolVIPOwnershipWithdrawal {
			m.RouteIntent = "withdrawal"
		}
	}
	return m
}

func freshArtifactForManifest(manifest PoolVIPOwnershipManifestV3, role k8s.OwnershipRole) (k8s.ArtifactPrerequisite, error) {
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(manifest.policyManifest())
	if err != nil {
		return k8s.ArtifactPrerequisite{}, err
	}
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil {
		return k8s.ArtifactPrerequisite{}, err
	}
	return freshArtifactFromManifest(manifest, identity, routeDigest, poolVIPOwnershipManifestVIPMapDigest(manifest.policyManifest()), manifest.LeaseExpiresAt, role), nil
}

func freshArtifactFromManifest(manifest PoolVIPOwnershipManifestV3, identity, routeDigest, vipDigest string, expires time.Time, role k8s.OwnershipRole) k8s.ArtifactPrerequisite {
	org, _ := uuid.Parse(manifest.OrgID)
	site, _ := uuid.Parse(manifest.SiteID)
	cluster, _ := uuid.Parse(manifest.ClusterID)
	poolID, _ := uuid.Parse(manifest.PoolID)
	node, _ := uuid.Parse(manifest.ConnectorNodeID)
	return k8s.ArtifactPrerequisite{Scope: k8s.OwnershipScope{OrgID: org, SiteID: site, ClusterID: cluster, PoolID: poolID, ConnectorID: node}, PromotionGeneration: manifest.PromotionGeneration, ManifestRevision: manifest.ManifestRevision, ManifestIdentity: identity, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipDigest, IdentityValidated: true, Lease: k8s.CPOwnershipLease{Epoch: manifest.LeaseEpoch, ExpiresAt: expires, CPIssuedValidated: true}, Role: role}
}

func freshHandoffEnvelope(plan k8s.DurableHandoffPlan, which k8s.P2HandoffArtifact, manifest PoolVIPOwnershipManifestV3) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	delivery, err := k8s.P2HandoffDeliveryForPlanArtifact(plan, which)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	i := delivery.Identity
	envelope := PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: PoolVIPOwnershipDeliveryEnvelope{Version: i.Version, OrgID: i.OrgID.String(), SiteID: i.SiteID.String(), ClusterID: i.ClusterID.String(), PoolID: i.PoolID.String(), ConnectorNodeID: i.ConnectorNodeID.String(), TargetNodeID: i.TargetNodeID.String(), OperationID: i.OperationID.String(), ManifestIdentity: i.ManifestIdentity, Role: string(i.Role), PromotionGeneration: i.PromotionGeneration, ManifestRevision: i.ManifestRevision, LeaseEpoch: i.LeaseEpoch, DeliveryPhase: i.DeliveryPhase, DeliveryID: i.DeliveryID.String(), DeliveryNonce: handoffBootstrapNonce(i.DeliveryID)}, ExpiresAt: delivery.LeaseExpiresAt.UTC(), Manifest: manifest, ExpectedRouteDigest: i.ExpectedRouteDigest, ExpectedVIPMapDigest: i.ExpectedVIPMapDigest, PriorLeaseEpoch: i.PriorLeaseEpoch}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	return envelope, nil
}
