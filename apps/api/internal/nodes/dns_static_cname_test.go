package nodes

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"testing"
	"time"
)

func TestStaticCNAMEPublicationPreservesPrivateAuthorityAcrossDowngrade(t *testing.T) {
	now := time.Now()
	node := sqlc.Node{ID: uuid.New(), Status: "active", CertSerial: "authenticated", Capabilities: []byte(`{"max_policy_version":14}`), PolicyReportedAt: pgtype.Timestamptz{Time: now, Valid: true}}
	p := policy.IPsecDNSProfile{Profile: policyspec.DNSResolverProfile{ContextConfigID: uuid.NewString(), ContextConfigVersion: 2, ProfileID: uuid.NewString(), ZoneSuffixes: []string{"office.test"}, StaticRecords: []policyspec.DNSStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "public.example", TTL: 300}}, Endpoints: []policyspec.DNSResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}, LANListener: &policyspec.DNSLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1"}}}}
	topo := siteTopology{poolCIDR: "10.99.0.0/24", dnsResolverProfiles: map[uuid.UUID][]policy.IPsecDNSProfile{node.ID: {p}}}
	project := func(n sqlc.Node) *policyspec.Compiled {
		return (&Service{}).finalizeArtifact(topo, n, &policyspec.Compiled{Mode: "enforcing"})
	}
	good := project(node)
	if good.Version != 14 || len(good.DNSResolverProfiles[0].Endpoints) != 1 {
		t.Fatal("capable gateway lost completion")
	}
	for name, mutate := range map[string]func(*sqlc.Node){"v13": func(n *sqlc.Node) { n.Capabilities = []byte(`{"max_policy_version":13}`) }, "stale": func(n *sqlc.Node) { n.PolicyReportedAt.Time = now.Add(-91 * time.Second) }, "future": func(n *sqlc.Node) { n.PolicyReportedAt.Time = now.Add(time.Minute) }, "unauthenticated": func(n *sqlc.Node) { n.CertSerial = "" }, "revoked": func(n *sqlc.Node) { n.RevokedAt = pgtype.Timestamptz{Time: now, Valid: true} }} {
		t.Run(name, func(t *testing.T) {
			n := node
			mutate(&n)
			got := project(n)
			if got.Version != 13 || len(got.DNSResolverProfiles) != 1 || len(got.DNSResolverProfiles[0].Endpoints) != 0 || len(got.DNSResolverProfiles[0].StaticRecords) != 1 || got.DNSResolverProfiles[0].LANListener == nil {
				t.Fatal("private authority lost or completion leaked", got)
			}
			if policyspec.CanonicalHash(*got) == policyspec.CanonicalHash(*good) {
				t.Fatal("completion withdrawal hash blind")
			}
		})
	}
	if len(topo.dnsResolverProfiles[node.ID][0].Profile.Endpoints) != 1 || project(node).Version != 14 {
		t.Fatal("projection mutated immutable authority")
	}
}
