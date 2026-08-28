package nodes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestPoolVIPOwnershipHandoffRequiresExactCapabilityThree(t *testing.T) {
	for capability, want := range map[string]bool{"": false, "1": false, "2": false, "03": false, "3": true, "4": false, "2,3": false} {
		if got := PoolVIPOwnershipCapabilityAuthorizesHandoff(capability); got != want {
			t.Fatalf("capability %q authorizes=%t want=%t", capability, got, want)
		}
	}
}

func TestPoolVIPOwnershipDeliveryV3BindsFullManifestAndCPExpiry(t *testing.T) {
	envelope, agent := ownershipDeliveryV3(t)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		t.Fatalf("valid v3 envelope: %v", err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"expires_at"`, `"wg_peers"`, `"public_key"`, `"allowed_ips"`, `"routes"`, `"dns_zone"`, `"dns_vip"`, `"services"`, `"service_id"`, `"service_cidr"`, `"dns_name"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("v3 wire payload omits %s: %s", field, raw)
		}
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	manifest, ok := wire["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("v3 wire manifest has unexpected shape: %s", raw)
	}
	if _, ambiguous := manifest["allowed_ips"]; ambiguous {
		t.Fatalf("v3 manifest retained ambiguous flat allowed_ips: %s", raw)
	}
	ack := ownershipAckV3(envelope)
	receipt := envelope.ExpiresAt.Add(-time.Minute)
	got, err := ValidatePoolVIPOwnershipDeliveryAckV3(receipt, agent, envelope, ack, PoolVIPOwnershipAckState{})
	if err != nil || got.ReceiptTime.IsZero() {
		t.Fatalf("valid v3 ack=%+v err=%v", got, err)
	}
	if _, err := ValidatePoolVIPOwnershipDeliveryAckV3(envelope.ExpiresAt, agent, envelope, ack, PoolVIPOwnershipAckState{}); err == nil {
		t.Fatal("receipt at CP lease expiry must fail closed")
	}
}

func TestPoolVIPOwnershipDeliveryV3RejectsPartialOrReboundManifest(t *testing.T) {
	base, agent := ownershipDeliveryV3(t)
	for name, mutate := range map[string]func(*PoolVIPOwnershipDeliveryEnvelopeV3){
		"expiry": func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) },
		"WG peer": func(v *PoolVIPOwnershipDeliveryEnvelopeV3) {
			v.Manifest.WGPeers[0].PublicKey = "qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M="
		},
		"allowed IP":   func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.Manifest.WGPeers[0].AllowedIPs[0] = "10.99.0.0/16" },
		"route":        func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.Manifest.Routes[0] = "10.99.0.0/16" },
		"DNS":          func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.Manifest.DNSVIP = "100.64.0.9" },
		"VIP/DNAT":     func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.Manifest.Services[0].VIP = "100.64.0.9" },
		"service CIDR": func(v *PoolVIPOwnershipDeliveryEnvelopeV3) { v.Manifest.Services[0].ServiceCIDR = "10.97.0.0/16" },
		"DNS name": func(v *PoolVIPOwnershipDeliveryEnvelopeV3) {
			v.Manifest.Services[0].DNSName = "other.default.cluster.k8s.example"
		},
		"operation": func(v *PoolVIPOwnershipDeliveryEnvelopeV3) {
			v.Manifest.HandoffOwnerID = "00000000-0000-4000-8000-000000000099"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneOwnershipDeliveryV3(base)
			mutate(&candidate)
			if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(candidate); err == nil {
				t.Fatal("changed full manifest must fail its CP identity/expiry binding")
			}
		})
	}
	ack := ownershipAckV3(base)
	ack.AppliedManifest.Services[0].VIP = "100.64.0.9"
	if _, err := ValidatePoolVIPOwnershipDeliveryAckV3(base.ExpiresAt.Add(-time.Minute), agent, base, ack, PoolVIPOwnershipAckState{}); err == nil {
		t.Fatal("partial applied VIP state must not produce a handoff acknowledgement")
	}
}

func TestPoolVIPOwnershipDeliveryV1V2RemainValidButNeverAuthorizeHandoff(t *testing.T) {
	v1, _ := ownershipDelivery()
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(v1); err != nil {
		t.Fatalf("v1 compatibility regressed: %v", err)
	}
	v2, _ := ownershipDeliveryV2(policyspec.PoolVIPOwnershipServing)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(v2); err != nil {
		t.Fatalf("v2 compatibility regressed: %v", err)
	}
	if PoolVIPOwnershipCapabilityAuthorizesHandoff("1") || PoolVIPOwnershipCapabilityAuthorizesHandoff("2") {
		t.Fatal("receipt-only v1 or digest-only v2 must never authorize handoff")
	}
}

func ownershipDeliveryV3(t *testing.T) (PoolVIPOwnershipDeliveryEnvelopeV3, PoolVIPOwnershipAgentIdentity) {
	t.Helper()
	base, agent := ownershipDelivery()
	base.Version = PoolVIPOwnershipDeliveryHandoffVersion
	expires := time.Date(2026, 8, 28, 12, 30, 0, 0, time.UTC)
	manifest := PoolVIPOwnershipManifestV3{Version: policyspec.PoolVIPOwnershipManifestVersion, OrgID: base.OrgID, SiteID: base.SiteID,
		ClusterID: base.ClusterID, PoolID: base.PoolID, ConnectorNodeID: base.ConnectorNodeID, Role: base.Role,
		PromotionGeneration: base.PromotionGeneration, ManifestRevision: base.ManifestRevision, LeaseEpoch: base.LeaseEpoch,
		LeaseExpiresAt: expires, DNSZone: "cluster.k8s.example", DNSVIP: "100.64.0.2", HandoffOwnerID: base.OperationID,
		RouteIntent: "serving", WGPeers: []PoolVIPOwnershipWGPeerV3{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16", "100.64.0.2/32"}}}, Routes: []string{"10.44.0.0/16", "100.64.0.2/32"},
		Services: []PoolVIPOwnershipServiceV3{{ServiceID: "00000000-0000-4000-8000-000000000020", VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", DNSName: "api.default.cluster.k8s.example", Protocol: "tcp", Port: 443}}}
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(manifest.policyManifest())
	if err != nil {
		t.Fatal(err)
	}
	base.ManifestIdentity = identity
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil {
		t.Fatal(err)
	}
	return PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: base, ExpiresAt: expires, Manifest: manifest,
		ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: poolVIPOwnershipManifestVIPMapDigest(manifest.policyManifest())}, agent
}

func ownershipAckV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) PoolVIPOwnershipDeliveryAckV3 {
	return PoolVIPOwnershipDeliveryAckV3{PoolVIPOwnershipDeliveryAck: ownershipAck(envelope.PoolVIPOwnershipDeliveryEnvelope),
		AppliedManifest: envelope.Manifest, AppliedLeaseEpoch: envelope.LeaseEpoch}
}

func cloneOwnershipDeliveryV3(in PoolVIPOwnershipDeliveryEnvelopeV3) PoolVIPOwnershipDeliveryEnvelopeV3 {
	out := in
	out.Manifest.WGPeers = append([]PoolVIPOwnershipWGPeerV3(nil), in.Manifest.WGPeers...)
	for i := range out.Manifest.WGPeers {
		out.Manifest.WGPeers[i].AllowedIPs = append([]string(nil), in.Manifest.WGPeers[i].AllowedIPs...)
	}
	out.Manifest.Routes = append([]string(nil), in.Manifest.Routes...)
	out.Manifest.Services = append([]PoolVIPOwnershipServiceV3(nil), in.Manifest.Services...)
	return out
}
