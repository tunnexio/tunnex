package nodes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func validKubernetesOwnershipAuthorityFixture() KubernetesOwnershipBaseAuthority {
	return KubernetesOwnershipBaseAuthority{
		WireVersion: 1, AuthorityRevision: 7,
		NodeID: "99999999-9999-9999-9999-999999999999", OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		BaseVersion: 17, BaseHash: strings.Repeat("a", 64),
		Classifications: []KubernetesOwnershipPoolClassification{{
			Scope:       KubernetesOwnershipPoolScope{OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222", ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444"},
			Disposition: KubernetesOwnershipPoolDispositionArmFence,
			Fields: KubernetesOwnershipPoolFields{Routes: []string{"100.64.0.2/32", "10.44.0.0/16"}, WGPeers: []KubernetesOwnershipWGPeer{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"100.64.0.2/32", "10.44.0.0/16"}}},
				VIPMappings: []policyspec.VIPMapping{{ServiceID: "66666666-6666-6666-6666-666666666666", VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", Protocol: "tcp", PortLow: 443, PortHigh: 443, DNSName: "api.default.svc.cluster.example"}},
				DNSZones:    []policyspec.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "cluster.example"}}},
		}},
	}
}

func TestCanonicalKubernetesOwnershipBaseAuthorityIsDeterministicAndClosed(t *testing.T) {
	fixture := validKubernetesOwnershipAuthorityFixture()
	canonical, digest, err := CanonicalKubernetesOwnershipBaseAuthority(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Classifications == nil || canonical.UnfencedPools == nil || canonical.Classifications[0].Fields.Routes[0] != "10.44.0.0/16" ||
		canonical.Classifications[0].Fields.WGPeers[0].AllowedIPs[0] != "10.44.0.0/16" || len(digest) != 64 {
		t.Fatalf("canonical=%+v digest=%q", canonical, digest)
	}
	const crossRuntimeGolden = "3869701fc1d1578083ce0e70078d40413db2516e84a9d08c2b11155303da1db2"
	if digest != crossRuntimeGolden {
		t.Fatalf("wire-v1 digest=%s want=%s", digest, crossRuntimeGolden)
	}
	reordered := fixture
	reordered.Classifications[0].Fields.Routes = []string{"10.44.0.0/16", "100.64.0.2/32"}
	reordered.Classifications[0].Fields.WGPeers[0].AllowedIPs = []string{"10.44.0.0/16", "100.64.0.2/32"}
	_, reorderedDigest, err := CanonicalKubernetesOwnershipBaseAuthority(reordered)
	if err != nil || reorderedDigest != digest {
		t.Fatalf("reordered digest=%s want=%s err=%v", reorderedDigest, digest, err)
	}
	for name, mutate := range map[string]func(*KubernetesOwnershipBaseAuthority){
		"future wire":         func(v *KubernetesOwnershipBaseAuthority) { v.WireVersion++ },
		"zero revision":       func(v *KubernetesOwnershipBaseAuthority) { v.AuthorityRevision = 0 },
		"cross scope":         func(v *KubernetesOwnershipBaseAuthority) { v.Classifications[0].Scope.OrgID = uuid.New().String() },
		"unknown disposition": func(v *KubernetesOwnershipBaseAuthority) { v.Classifications[0].Disposition = "unfence" },
		"duplicate pool": func(v *KubernetesOwnershipBaseAuthority) {
			v.UnfencedPools = []KubernetesOwnershipPoolScope{v.Classifications[0].Scope}
		},
		"noncanonical prefix": func(v *KubernetesOwnershipBaseAuthority) { v.Classifications[0].Fields.Routes[0] = "10.44.1.1/16" },
		"duplicate peer prefix": func(v *KubernetesOwnershipBaseAuthority) {
			v.Classifications[0].Fields.WGPeers = append(v.Classifications[0].Fields.WGPeers, KubernetesOwnershipWGPeer{PublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validKubernetesOwnershipAuthorityFixture()
			mutate(&candidate)
			if _, _, err := CanonicalKubernetesOwnershipBaseAuthority(candidate); err == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
}

func TestValidateKubernetesOwnershipBaseAuthorityAckBindsPrincipalAndExactPayload(t *testing.T) {
	authority, digest, err := CanonicalKubernetesOwnershipBaseAuthority(validKubernetesOwnershipAuthorityFixture())
	if err != nil {
		t.Fatal(err)
	}
	agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: uuid.MustParse(authority.NodeID), OrgID: uuid.MustParse(authority.OrgID), SiteID: uuid.MustParse(authority.SiteID)}
	ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: authority.AuthorityRevision, NodeID: authority.NodeID, OrgID: authority.OrgID,
		SiteID: authority.SiteID, BaseVersion: authority.BaseVersion, BaseHash: authority.BaseHash, AuthorityDigest: digest, AppliedAt: "2026-08-28T10:11:12.000000345Z"}
	if got, err := ValidateKubernetesOwnershipBaseAuthorityAck(agent, authority, digest, ack); err != nil || got.Format(time.RFC3339Nano) != ack.AppliedAt {
		t.Fatalf("applied=%v err=%v", got, err)
	}
	for name, mutate := range map[string]func(*KubernetesOwnershipBaseAuthorityAck){
		"node":   func(v *KubernetesOwnershipBaseAuthorityAck) { v.NodeID = uuid.New().String() },
		"digest": func(v *KubernetesOwnershipBaseAuthorityAck) { v.AuthorityDigest = strings.Repeat("b", 64) },
		"base":   func(v *KubernetesOwnershipBaseAuthorityAck) { v.BaseVersion++ },
		"time":   func(v *KubernetesOwnershipBaseAuthorityAck) { v.AppliedAt = "2026-08-28T10:11:12+00:00" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := ack
			mutate(&candidate)
			if _, err := ValidateKubernetesOwnershipBaseAuthorityAck(agent, authority, digest, candidate); err == nil {
				t.Fatal("mismatched receipt accepted")
			}
		})
	}
}

func TestKubernetesOwnershipBaseStateHashUsesStableExplicitView(t *testing.T) {
	base := DesiredState{ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", InterfaceAddress: "10.99.0.1/24", MTU: 1380, ListenPort: 51820, Version: 17,
		Peers: []Peer{}, OVPNEnabled: true, OVPNClients: []OVPNClient{{CommonName: "alice", IP: "10.99.0.20", FullTunnel: true}}}
	digest, err := KubernetesOwnershipBaseStateHash(base)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	const crossRuntimeGolden = "ad039cb612f05abdf22eae00d3fe6bb5102c333ddc5fbb3a98d4b4b94e9d7e67"
	if digest != crossRuntimeGolden {
		t.Fatalf("base digest=%s want=%s", digest, crossRuntimeGolden)
	}
	b, _ := json.Marshal(base)
	if len(b) == 0 {
		t.Fatal("fixture did not marshal")
	}
	base.MTU++
	changed, _ := KubernetesOwnershipBaseStateHash(base)
	if changed == digest {
		t.Fatal("ordinary base change did not change digest")
	}
}
