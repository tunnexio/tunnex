package nodes

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestPoolVIPOwnershipFreshHandoffCapabilityQueryFencesGenerationAndRole(t *testing.T) {
	source, err := os.ReadFile("pool_vip_ownership_fresh_handoff_provenance.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"expectedRole := string(k8s.PreparedNonServing)",
		"expectedRole = string(k8s.Serving)",
		"d.promotion_generation=$7 AND d.role=$8",
		"int64(plan.ExpectedGeneration), expectedRole",
		"d.promotion_generation=$10 AND d.role=$11",
		"int64(p.ExpectedGeneration), expectedRole",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("fresh capability authority query missing %q", want)
		}
	}
}

func TestPoolVIPOwnershipFreshHandoffCapabilitiesRequireExactV3(t *testing.T) {
	oldNode, newNode := uuid.New(), uuid.New()
	plan := k8s.DurableHandoffPlan{Plan: k8s.HandoffPlan{ExpectedActiveID: oldNode, CandidateID: newNode}}
	receipt := time.Now().UTC()
	values := []PoolVIPOwnershipFreshHandoffCapability{
		{NodeID: oldNode, WireVersion: PoolVIPOwnershipDeliveryHandoffVersion, DeliveryRowID: uuid.New(), ReceiptTime: receipt, ExpiresAt: receipt.Add(time.Minute)},
		{NodeID: newNode, WireVersion: PoolVIPOwnershipDeliveryHandoffVersion, DeliveryRowID: uuid.New(), ReceiptTime: receipt, ExpiresAt: receipt.Add(time.Minute)},
	}
	if !validPoolVIPOwnershipFreshHandoffCapabilities(values, plan) {
		t.Fatal("two exact capability-3 receipts must satisfy the fresh provenance boundary")
	}
	values[0].WireVersion = PoolVIPOwnershipDeliveryAttestationVersion
	if validPoolVIPOwnershipFreshHandoffCapabilities(values, plan) {
		t.Fatal("legacy capability 2 must remain non-authorizing")
	}
}

func TestPoolVIPOwnershipFreshHandoffTopologyBindsFullV3Manifest(t *testing.T) {
	artifacts := freshHandoffV3Topology(t)
	if !validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology(artifacts) {
		t.Fatal("coherent full v3 topology must be accepted")
	}

	serving := artifacts[k8s.P2NewServingArtifact]
	serving.envelope.Manifest.DNSZone = "other.k8s.example"
	refreshFreshHandoffV3Identity(t, &serving.envelope)
	artifacts[k8s.P2NewServingArtifact] = serving
	if validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology(artifacts) {
		t.Fatal("a DNS topology change outside the legacy route/VIP digests must be refused")
	}

	artifacts = freshHandoffV3Topology(t)
	serving = artifacts[k8s.P2NewServingArtifact]
	serving.envelope.Manifest.WGPeers[0].PublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	refreshFreshHandoffV3Identity(t, &serving.envelope)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(serving.envelope); err != nil {
		t.Fatalf("mutated peer-specific manifest should remain individually valid: %v", err)
	}
	artifacts[k8s.P2NewServingArtifact] = serving
	if validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology(artifacts) {
		t.Fatal("a peer-specific WireGuard topology change must be refused")
	}
}

func freshHandoffV3Topology(t *testing.T) map[k8s.P2HandoffArtifact]preparedPoolVIPOwnershipFreshHandoffArtifact {
	t.Helper()
	old, _ := ownershipDeliveryV3(t)
	oldExpiry := old.ExpiresAt
	targetExpiry := oldExpiry.Add(time.Hour)
	old.LeaseEpoch, old.Manifest.LeaseEpoch = 10, 10
	old.ExpiresAt, old.Manifest.LeaseExpiresAt = oldExpiry, oldExpiry
	old.DeliveryID = "00000000-0000-4000-8000-000000000031"
	refreshFreshHandoffV3Identity(t, &old)

	prepared := clonePoolVIPOwnershipDeliveryEnvelopeV3(old)
	prepared.TargetNodeID, prepared.ConnectorNodeID = "00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000032"
	prepared.Role, prepared.DeliveryPhase, prepared.DeliveryID = policyspec.PoolVIPOwnershipPreparedNonServing, poolVIPOwnershipPhasePrepare, "00000000-0000-4000-8000-000000000033"
	prepared.LeaseEpoch, prepared.ExpiresAt = 11, targetExpiry
	prepared.Manifest.ConnectorNodeID, prepared.Manifest.Role, prepared.Manifest.RouteIntent = prepared.ConnectorNodeID, prepared.Role, "non_serving"
	prepared.Manifest.LeaseEpoch, prepared.Manifest.LeaseExpiresAt = prepared.LeaseEpoch, targetExpiry
	prepared.Manifest.WGPeers, prepared.Manifest.Routes, prepared.Manifest.Services = nil, nil, nil
	refreshFreshHandoffV3Identity(t, &prepared)

	withdrawal := clonePoolVIPOwnershipDeliveryEnvelopeV3(prepared)
	withdrawal.TargetNodeID, withdrawal.ConnectorNodeID = old.TargetNodeID, old.ConnectorNodeID
	withdrawal.Role, withdrawal.DeliveryPhase, withdrawal.DeliveryID = policyspec.PoolVIPOwnershipWithdrawal, poolVIPOwnershipPhaseWithdraw, "00000000-0000-4000-8000-000000000034"
	withdrawal.PriorLeaseEpoch = old.LeaseEpoch
	withdrawal.Manifest.ConnectorNodeID, withdrawal.Manifest.Role, withdrawal.Manifest.RouteIntent = withdrawal.ConnectorNodeID, withdrawal.Role, "withdrawal"
	refreshFreshHandoffV3Identity(t, &withdrawal)

	serving := clonePoolVIPOwnershipDeliveryEnvelopeV3(old)
	serving.TargetNodeID, serving.ConnectorNodeID = prepared.TargetNodeID, prepared.ConnectorNodeID
	serving.DeliveryID, serving.LeaseEpoch, serving.ExpiresAt = "00000000-0000-4000-8000-000000000035", prepared.LeaseEpoch, targetExpiry
	serving.Manifest.ConnectorNodeID, serving.Manifest.LeaseEpoch, serving.Manifest.LeaseExpiresAt = serving.ConnectorNodeID, serving.LeaseEpoch, targetExpiry
	refreshFreshHandoffV3Identity(t, &serving)

	values := map[k8s.P2HandoffArtifact]PoolVIPOwnershipDeliveryEnvelopeV3{
		k8s.P2OldServingArtifact: old, k8s.P2NewPreparedArtifact: prepared,
		k8s.P2OldWithdrawalArtifact: withdrawal, k8s.P2NewServingArtifact: serving,
	}
	out := make(map[k8s.P2HandoffArtifact]preparedPoolVIPOwnershipFreshHandoffArtifact, len(values))
	for which, envelope := range values {
		if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
			t.Fatalf("%s v3 fixture invalid: %v", which, err)
		}
		out[which] = preparedPoolVIPOwnershipFreshHandoffArtifact{envelope: envelope, expiresAt: envelope.ExpiresAt}
	}
	return out
}

func refreshFreshHandoffV3Identity(t *testing.T, envelope *PoolVIPOwnershipDeliveryEnvelopeV3) {
	t.Helper()
	envelope.Manifest.OrgID, envelope.Manifest.SiteID, envelope.Manifest.ClusterID, envelope.Manifest.PoolID = envelope.OrgID, envelope.SiteID, envelope.ClusterID, envelope.PoolID
	envelope.Manifest.PromotionGeneration, envelope.Manifest.ManifestRevision = envelope.PromotionGeneration, envelope.ManifestRevision
	envelope.Manifest.HandoffOwnerID = envelope.OperationID
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(envelope.Manifest.policyManifest())
	if err != nil {
		t.Fatal(err)
	}
	envelope.ManifestIdentity = identity
	envelope.ExpectedRouteDigest, err = PoolVIPOwnershipOwnedRouteDigest(envelope.Manifest.Routes)
	if err != nil {
		t.Fatal(err)
	}
	envelope.ExpectedVIPMapDigest = poolVIPOwnershipManifestVIPMapDigest(envelope.Manifest.policyManifest())
}
