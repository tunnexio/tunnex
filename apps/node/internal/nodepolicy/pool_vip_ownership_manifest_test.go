package nodepolicy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// CROSS-MODULE GOLDEN: this fixture and expected full SHA-256 are mirrored in
// policyspec. These two pure modules must agree before any manifest can ride a
// transport boundary.
func TestPoolVIPOwnershipManifestIdentityGoldenAndCanonicalOrder(t *testing.T) {
	base := ownershipManifest()
	const want = "2bf2c9f756643724f2dc880d97147e50208d25a673a72f7406e35198a7948744"
	got, err := nodepolicy.PoolVIPOwnershipManifestIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}
	ordered := base
	ordered.WGPeers = []nodepolicy.PoolVIPOwnershipWGPeer{base.WGPeers[1], base.WGPeers[0]}
	ordered.WGPeers[0].AllowedIPs = []string{base.WGPeers[1].AllowedIPs[1], base.WGPeers[1].AllowedIPs[0]}
	ordered.Routes = []string{base.Routes[1], base.Routes[0]}
	ordered.Services = []nodepolicy.PoolVIPOwnershipService{base.Services[1], base.Services[0]}
	if got, err := nodepolicy.PoolVIPOwnershipManifestIdentity(ordered); err != nil || got != want {
		t.Fatalf("order changed identity: %q, %v", got, err)
	}
}

func TestPoolVIPOwnershipManifestIdentityBindsEveryIncludedField(t *testing.T) {
	base := ownershipManifest()
	want, err := nodepolicy.PoolVIPOwnershipManifestIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*nodepolicy.PoolVIPOwnershipManifest){
		"org":     func(m *nodepolicy.PoolVIPOwnershipManifest) { m.OrgID = "00000000-0000-4000-8000-000000000011" },
		"site":    func(m *nodepolicy.PoolVIPOwnershipManifest) { m.SiteID = "00000000-0000-4000-8000-000000000012" },
		"cluster": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.ClusterID = "00000000-0000-4000-8000-000000000013" },
		"pool":    func(m *nodepolicy.PoolVIPOwnershipManifest) { m.PoolID = "00000000-0000-4000-8000-000000000014" },
		"connector": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.ConnectorNodeID = "00000000-0000-4000-8000-000000000015"
		},
		"owner": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.HandoffOwnerID = "00000000-0000-4000-8000-000000000016"
		},
		"promotion":    func(m *nodepolicy.PoolVIPOwnershipManifest) { m.PromotionGeneration++ },
		"revision":     func(m *nodepolicy.PoolVIPOwnershipManifest) { m.ManifestRevision++ },
		"lease epoch":  func(m *nodepolicy.PoolVIPOwnershipManifest) { m.LeaseEpoch++ },
		"lease expiry": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.LeaseExpiresAt = m.LeaseExpiresAt.Add(time.Second) },
		"DNS zone":     func(m *nodepolicy.PoolVIPOwnershipManifest) { m.DNSZone = "other.k8s.example" },
		"DNS VIP":      func(m *nodepolicy.PoolVIPOwnershipManifest) { m.DNSVIP = "100.64.0.9" },
		"WG public key": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.WGPeers[0].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"allowed IP": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.WGPeers[0].AllowedIPs[0] = "10.100.0.0/16" },
		"route":      func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Routes[0] = "100.65.0.0/24" },
		"service ID": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Services[0].ServiceID = "00000000-0000-4000-8000-000000000017"
		},
		"service VIP":  func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].VIP = "100.64.0.8" },
		"namespace":    func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].Namespace = "other" },
		"service":      func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].Service = "other" },
		"service CIDR": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].ServiceCIDR = "10.97.0.0/16" },
		"DNS name": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Services[0].DNSName = "other.prod.svc.cluster.k8s.example"
		},
		"protocol": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].Protocol = "udp" },
		"port":     func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].Port = 8443 },
		"role intent": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Role, m.RouteIntent, m.WGPeers, m.Routes = nodepolicy.PoolVIPOwnershipPreparedNonServing, "non_serving", nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneOwnershipManifest(base)
			mutate(&changed)
			got, err := nodepolicy.PoolVIPOwnershipManifestIdentity(changed)
			if err != nil || got == want {
				t.Fatalf("mutation %s = %q, %v", name, got, err)
			}
		})
	}
}

func TestPoolVIPOwnershipManifestIdentityRejectsUnsafeOrAmbiguousData(t *testing.T) {
	for name, mutate := range map[string]func(*nodepolicy.PoolVIPOwnershipManifest){
		"nil scope":          func(m *nodepolicy.PoolVIPOwnershipManifest) { m.OrgID = "00000000-0000-0000-0000-000000000000" },
		"noncanonical scope": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.SiteID = strings.ToUpper(m.SiteID) },
		"zero revision":      func(m *nodepolicy.PoolVIPOwnershipManifest) { m.ManifestRevision = 0 },
		"non-UTC lease": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.LeaseExpiresAt = m.LeaseExpiresAt.In(time.FixedZone("offset", 3600))
		},
		"noncanonical DNS VIP": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.DNSVIP = "100.64.0.02" },
		"duplicate service ID": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[1].ServiceID = m.Services[0].ServiceID },
		"duplicate service tuple": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Services[1] = m.Services[0]
			m.Services[1].ServiceID = "00000000-0000-4000-8000-000000000018"
		},
		"noncanonical service":      func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].Namespace = "Prod" },
		"noncanonical service CIDR": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Services[0].ServiceCIDR = "10.96.0.1/12" },
		"noncanonical DNS name": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Services[0].DNSName = "API.prod.svc.cluster.k8s.example"
		},
		"malformed WG key":             func(m *nodepolicy.PoolVIPOwnershipManifest) { m.WGPeers[0].PublicKey = "not-a-wireguard-key" },
		"host-bit allowed IP":          func(m *nodepolicy.PoolVIPOwnershipManifest) { m.WGPeers[0].AllowedIPs[0] = "10.99.1.1/16" },
		"host-bit route":               func(m *nodepolicy.PoolVIPOwnershipManifest) { m.Routes[0] = "10.99.1.1/16" },
		"duplicate WG peer":            func(m *nodepolicy.PoolVIPOwnershipManifest) { m.WGPeers[1].PublicKey = m.WGPeers[0].PublicKey },
		"prefix assigned to two peers": func(m *nodepolicy.PoolVIPOwnershipManifest) { m.WGPeers[1].AllowedIPs[0] = m.WGPeers[0].AllowedIPs[0] },
		"prepared carries route": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Role, m.RouteIntent = nodepolicy.PoolVIPOwnershipPreparedNonServing, "non_serving"
		},
		"withdrawal carries allowed IP": func(m *nodepolicy.PoolVIPOwnershipManifest) {
			m.Role, m.RouteIntent = nodepolicy.PoolVIPOwnershipWithdrawal, "withdrawal"
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := cloneOwnershipManifest(ownershipManifest())
			mutate(&m)
			if got, err := nodepolicy.PoolVIPOwnershipManifestIdentity(m); err == nil || got != "" {
				t.Fatalf("unsafe manifest = %q, %v", got, err)
			}
		})
	}
}

func TestPoolVIPOwnershipManifestSuccessorRequiresSameScopeAndHigherRevision(t *testing.T) {
	previous := ownershipManifest()
	next := cloneOwnershipManifest(previous)
	next.ManifestRevision++
	if err := nodepolicy.ValidatePoolVIPOwnershipManifestSuccessor(previous, next); err != nil {
		t.Fatalf("strictly newer same-scope manifest: %v", err)
	}
	if err := nodepolicy.ValidatePoolVIPOwnershipManifestSuccessor(previous, previous); err == nil {
		t.Fatal("unchanged revision must reject")
	}
	next = cloneOwnershipManifest(next)
	next.PoolID = "00000000-0000-4000-8000-000000000019"
	if err := nodepolicy.ValidatePoolVIPOwnershipManifestSuccessor(previous, next); err == nil {
		t.Fatal("scope change must reject")
	}
	next = cloneOwnershipManifest(previous)
	next.ManifestRevision++
	next.LeaseEpoch--
	if err := nodepolicy.ValidatePoolVIPOwnershipManifestSuccessor(previous, next); err == nil {
		t.Fatal("lease epoch regression must reject")
	}
}

func ownershipManifest() nodepolicy.PoolVIPOwnershipManifest {
	return nodepolicy.PoolVIPOwnershipManifest{
		Version: 1, OrgID: "00000000-0000-4000-8000-000000000001", SiteID: "019f6400-0000-4000-8000-000000000002",
		ClusterID: "00000000-0000-4000-8000-000000000003", PoolID: "00000000-0000-4000-8000-000000000004",
		ConnectorNodeID: "00000000-0000-4000-8000-000000000005", Role: nodepolicy.PoolVIPOwnershipServing,
		PromotionGeneration: 7, ManifestRevision: 11, LeaseEpoch: 13, LeaseExpiresAt: time.Date(2026, 8, 13, 12, 30, 0, 123456789, time.UTC),
		DNSZone: "cluster.k8s.example", DNSVIP: "100.64.0.2", HandoffOwnerID: "00000000-0000-4000-8000-000000000006", RouteIntent: "serving",
		WGPeers: []nodepolicy.PoolVIPOwnershipWGPeer{
			{PublicKey: "qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M=", AllowedIPs: []string{"10.99.0.0/16"}},
			{PublicKey: "ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=", AllowedIPs: []string{"100.64.0.3/32", "100.64.0.2/32"}},
		}, Routes: []string{"10.99.0.0/16", "100.64.0.2/32"},
		Services: []nodepolicy.PoolVIPOwnershipService{
			{ServiceID: "00000000-0000-4000-8000-000000000008", VIP: "100.64.0.4", Namespace: "prod", Service: "web", ServiceCIDR: "10.96.0.0/12", DNSName: "web.prod.svc.cluster.k8s.example", Protocol: "tcp", Port: 443},
			{ServiceID: "00000000-0000-4000-8000-000000000007", VIP: "100.64.0.3", Namespace: "prod", Service: "api", ServiceCIDR: "10.96.0.0/12", DNSName: "api.prod.svc.cluster.k8s.example", Protocol: "udp", Port: 53},
		},
	}
}

func cloneOwnershipManifest(in nodepolicy.PoolVIPOwnershipManifest) nodepolicy.PoolVIPOwnershipManifest {
	out := in
	out.WGPeers = make([]nodepolicy.PoolVIPOwnershipWGPeer, len(in.WGPeers))
	for i, peer := range in.WGPeers {
		out.WGPeers[i] = nodepolicy.PoolVIPOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)}
	}
	out.Routes = append([]string(nil), in.Routes...)
	out.Services = append([]nodepolicy.PoolVIPOwnershipService(nil), in.Services...)
	return out
}
