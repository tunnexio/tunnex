package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// TestArtifactCarriesSiteLANMasquerade — SSI-8. A gateway whose site chose gateway_address carries the flag
// (and therefore v15) once it has a remote range to translate; the other site's gateway, left on
// preserve_source, keeps the artifact it had before, byte for byte.
func TestArtifactCarriesSiteLANMasquerade(t *testing.T) {
	fresh := time.Now()
	awsSite, gcpSite := idAt(0xA), idAt(0xB)
	aws := gw(1, "aws:51820", "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", nil, &fresh)
	aws.SiteID = pgtype.UUID{Bytes: awsSite, Valid: true}
	gcp := gw(2, "gcp:51820", "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo=", nil, &fresh)
	gcp.SiteID = pgtype.UUID{Bytes: gcpSite, Valid: true}
	subnets := map[uuid.UUID][]string{awsSite: {"172.31.37.55/32"}, gcpSite: {"10.70.0.0/24"}}
	nodeOf := func(g sqlc.ListSiteGatewaysForOrgRow) sqlc.Node { return sqlc.Node{ID: g.ID, SiteID: g.SiteID} }
	enforcing := func() *policyspec.Compiled { return &policyspec.Compiled{Mode: "enforcing"} }
	svc := &Service{}

	before := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{aws, gcp}, subnets: subnets, poolCIDR: "10.99.0.0/24"}
	quick := before
	quick.lanMasquerade = map[uuid.UUID]bool{gcpSite: true}

	gcpArtifact := svc.finalizeArtifact(quick, nodeOf(gcp), enforcing())
	if !gcpArtifact.SiteLANMasquerade || gcpArtifact.Version != 15 {
		t.Fatalf("the gateway of a gateway_address site must carry the flag at v15, got flag=%v v%d", gcpArtifact.SiteLANMasquerade, gcpArtifact.Version)
	}
	if len(gcpArtifact.Routes) != 1 || gcpArtifact.Routes[0].DstCIDR != "172.31.37.55/32" {
		t.Fatalf("the flag rides with the remote routes it translates, got %+v", gcpArtifact.Routes)
	}

	// The OTHER site did not opt in: its artifact is exactly what it was before the setting existed.
	awsQuick := svc.finalizeArtifact(quick, nodeOf(aws), enforcing())
	awsBefore := svc.finalizeArtifact(before, nodeOf(aws), enforcing())
	if awsQuick.SiteLANMasquerade || awsQuick.Version != awsBefore.Version || policyspec.CanonicalHash(*awsQuick) != policyspec.CanonicalHash(*awsBefore) {
		t.Fatalf("a preserve_source site must keep its artifact: v%d/%s vs v%d/%s", awsQuick.Version, policyspec.CanonicalHash(*awsQuick), awsBefore.Version, policyspec.CanonicalHash(*awsBefore))
	}

	// With enforcement off (the mesh artifact) the flag is carried the same way.
	if mesh := svc.finalizeArtifact(quick, nodeOf(gcp), nil); !mesh.SiteLANMasquerade || mesh.Version != 15 || !mesh.Mesh {
		t.Fatalf("the mesh artifact of a gateway_address site must carry the flag too, got %+v", mesh)
	}

	// No remote range, nothing to translate: no flag, no version raise.
	alone := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{gcp}, subnets: map[uuid.UUID][]string{gcpSite: {"10.70.0.0/24"}}, lanMasquerade: map[uuid.UUID]bool{gcpSite: true}}
	if only := svc.finalizeArtifact(alone, nodeOf(gcp), enforcing()); only.SiteLANMasquerade || only.Version >= 15 {
		t.Fatalf("a single-site gateway has nothing remote to translate, got flag=%v v%d", only.SiteLANMasquerade, only.Version)
	}
}
