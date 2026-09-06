package nodes

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestBuildHandoffBootstrapPlanProducesCompleteExactV3Artifacts(t *testing.T) {
	topology, expires := handoffBootstrapTopologyForTest()
	plan, err := buildHandoffBootstrapPlan(topology, expires)
	if err != nil {
		t.Fatal(err)
	}
	if !validHandoffBootstrapPlan(plan, expires.Add(-time.Second)) || plan.CurrentOwnerEnvelope.Version != 3 || len(plan.StandbyEnvelopes) != 2 || len(plan.ServiceUIDs) != 1 {
		t.Fatalf("invalid plan: %+v", plan)
	}
	serving := plan.CurrentOwnerEnvelope
	if serving.Role != policyspec.PoolVIPOwnershipServing || len(serving.Manifest.WGPeers) != 1 || len(serving.Manifest.Routes) != 1 || len(serving.Manifest.Services) != 1 ||
		serving.Manifest.Services[0].ServiceCIDR != topology.ServiceCIDR || serving.Manifest.Services[0].DNSName != "api.default.svc.cluster.k8s.example" {
		t.Fatalf("serving manifest is incomplete: %+v", serving.Manifest)
	}
	for _, prepared := range plan.StandbyEnvelopes {
		if prepared.Version != 3 || prepared.Role != policyspec.PoolVIPOwnershipPreparedNonServing || prepared.Manifest.WGPeers == nil || len(prepared.Manifest.WGPeers) != 0 || len(prepared.Manifest.Routes) != 0 || len(prepared.Manifest.Services) != 0 || prepared.ExpectedVIPMapDigest != "" {
			t.Fatalf("prepared manifest owns dataplane state: %+v", prepared)
		}
	}
	retry, err := buildHandoffBootstrapPlan(topology, expires)
	if err != nil || retry.CurrentOwnerEnvelope.DeliveryID != serving.DeliveryID || retry.CurrentOwnerEnvelope.DeliveryNonce != serving.DeliveryNonce || retry.CurrentOwnerEnvelope.ManifestIdentity != serving.ManifestIdentity {
		t.Fatalf("retry was not byte-stable: err=%v first=%+v retry=%+v", err, serving, retry.CurrentOwnerEnvelope)
	}
	bad := plan
	bad.ServiceUIDs = append([]HandoffBootstrapServiceUID(nil), plan.ServiceUIDs...)
	bad.ServiceUIDs[0].UID = ""
	if validHandoffBootstrapPlan(bad, expires.Add(-time.Second)) {
		t.Fatal("a missing exact live Service UID remained bootstrap authority")
	}
	newIncarnation := cloneHandoffBootstrapTopology(topology)
	newIncarnation.Services[0].UID = "uid-api-v2"
	newIncarnation.Services[0].ObservationRevision++
	changed, err := buildHandoffBootstrapPlan(newIncarnation, expires)
	if err != nil || changed.CurrentOwnerEnvelope.OperationID == serving.OperationID || changed.CurrentOwnerEnvelope.DeliveryID == serving.DeliveryID || changed.CurrentOwnerEnvelope.ManifestIdentity == serving.ManifestIdentity {
		t.Fatalf("Service UID incarnation was not bound to V3 authority: err=%v changed=%+v", err, changed.CurrentOwnerEnvelope)
	}
	conflict := cloneHandoffBootstrapTopology(topology)
	conflict.Existing = map[uuid.UUID]PoolVIPOwnershipDeliveryEnvelopeV3{topology.ActiveNodeID: serving}
	conflictingEnvelope := clonePoolVIPOwnershipDeliveryEnvelopeV3(serving)
	conflictingEnvelope.Manifest.DNSVIP = "100.64.0.9"
	conflict.Existing[topology.ActiveNodeID] = conflictingEnvelope
	if _, err := buildHandoffBootstrapPlan(conflict, expires); !errors.Is(err, ErrHandoffBootstrapPlanRefused) {
		t.Fatalf("durable/topology conflict err=%v", err)
	}
}

func TestBuildHandoffBootstrapPlanFailsClosedOnIncompleteTopology(t *testing.T) {
	base, expires := handoffBootstrapTopologyForTest()
	tests := map[string]func(*handoffBootstrapTopology){
		"active WG key":    func(v *handoffBootstrapTopology) { v.Members[0].WGPublicKey = "" },
		"standby endpoint": func(v *handoffBootstrapTopology) { v.Members[1].Endpoint = "" },
		"edge WG key":      func(v *handoffBootstrapTopology) { v.EdgeWGPublicKey = "" },
		"owned route":      func(v *handoffBootstrapTopology) { v.DevicePoolCIDR = "" },
		"ServiceCIDR":      func(v *handoffBootstrapTopology) { v.ServiceCIDR = "" },
		"DNS name":         func(v *handoffBootstrapTopology) { v.ClusterName = "Bad_Cluster" },
		"DNS VIP":          func(v *handoffBootstrapTopology) { v.DNSVIP = "" },
		"Service UID":      func(v *handoffBootstrapTopology) { v.Services[0].UID = "" },
		"UID revision":     func(v *handoffBootstrapTopology) { v.Services[0].ObservationRevision = 0 },
		"singular port":    func(v *handoffBootstrapTopology) { high := int32(444); v.Services[0].PortHigh = &high },
		"protocol":         func(v *handoffBootstrapTopology) { v.Services[0].Protocol = "any" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneHandoffBootstrapTopology(base)
			mutate(&candidate)
			if _, err := buildHandoffBootstrapPlan(candidate, expires); !errors.Is(err, ErrHandoffBootstrapPlanRefused) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func handoffBootstrapTopologyForTest() (handoffBootstrapTopology, time.Time) {
	active := uuid.MustParse("00000000-0000-4000-8000-000000000030")
	standbyA := uuid.MustParse("00000000-0000-4000-8000-000000000031")
	standbyB := uuid.MustParse("00000000-0000-4000-8000-000000000032")
	scope := k8s.HandoffPoolScope{OrgID: uuid.MustParse("00000000-0000-4000-8000-000000000011"), SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000012"),
		ClusterID: uuid.MustParse("00000000-0000-4000-8000-000000000013"), PoolID: uuid.MustParse("00000000-0000-4000-8000-000000000014")}
	port := int32(443)
	return handoffBootstrapTopology{Scope: scope, Generation: 7, ActiveNodeID: active, ClusterName: "cluster", DNSZone: "k8s.example", DNSVIP: "100.64.0.2",
			ServiceCIDR: "10.96.0.0/12", DevicePoolCIDR: "10.44.0.0/16", EdgeWGPublicKey: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
			Members: []handoffBootstrapMember{
				{NodeID: active, SiteID: scope.SiteID, WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "10.0.0.1:51820"},
				{NodeID: standbyA, SiteID: scope.SiteID, WGPublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Endpoint: "10.0.0.2:51820"},
				{NodeID: standbyB, SiteID: scope.SiteID, WGPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", Endpoint: "10.0.0.3:51820"},
			},
			Services: []handoffBootstrapService{{ID: uuid.MustParse("00000000-0000-4000-8000-000000000020"), Namespace: "default", Name: "api", VIP: "100.64.0.10", Protocol: "tcp", PortLow: &port, PortHigh: &port, UID: "uid-api", ObservationRevision: 9}},
			Counters: map[uuid.UUID]handoffBootstrapCounter{active: {ManifestRevision: 20, LeaseEpoch: 30}, standbyA: {ManifestRevision: 21, LeaseEpoch: 31}, standbyB: {ManifestRevision: 22, LeaseEpoch: 32}}},
		time.Date(2026, 8, 28, 12, 10, 0, 0, time.UTC)
}

func cloneHandoffBootstrapTopology(in handoffBootstrapTopology) handoffBootstrapTopology {
	out := in
	out.Members = append([]handoffBootstrapMember(nil), in.Members...)
	out.Services = append([]handoffBootstrapService(nil), in.Services...)
	out.Counters = make(map[uuid.UUID]handoffBootstrapCounter, len(in.Counters))
	for key, value := range in.Counters {
		out.Counters[key] = value
	}
	out.Existing = make(map[uuid.UUID]PoolVIPOwnershipDeliveryEnvelopeV3, len(in.Existing))
	for key, value := range in.Existing {
		out.Existing[key] = clonePoolVIPOwnershipDeliveryEnvelopeV3(value)
	}
	return out
}
