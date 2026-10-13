package ipsec_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// The compiler's authority inputs come from the locked store, not request fields.
// Rejected capability/provenance leaves the disabled connection revision intact.
func TestRuntimeFQDNGatedLockedInputPreservesMixedProviderAdmission(t *testing.T) {
	for _, profile := range []string{"aws-static-ipv4-v1", "aws-bgp-ipv4-v1", ipsec.GCPClassicProfile, ipsec.GCPHAProfile} {
		t.Run(profile, func(t *testing.T) {
			ctx, p, org, actor, sealer, identity := createFixture(t)
			if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
				t.Fatal(err)
			}
			req := providerRequest(identity)
			req.Config.ProfileID = profile
			if profile == ipsec.GCPClassicProfile {
				req.Config.Tunnels = req.Config.Tunnels[:1]
				req.TunnelIDs[1] = uuid.Nil
				req.Config.Tunnels[0].InsideCIDR = ""
				req.Config.Tunnels[0].CustomerInsideAddress = ""
				req.Config.Tunnels[0].CloudInsideAddress = ""
			}
			if profile == "aws-bgp-ipv4-v1" || profile == ipsec.GCPHAProfile {
				req.Config = bgpConfigFixture()
				req.Config.ProfileID = profile
				if profile == ipsec.GCPHAProfile {
					req.Config.BGP.RemoteASN = 65002
				}
			}
			if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":1,"ipsec_gcp_ha_version":1,"ipsec_bgp_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
				t.Fatal(err)
			}
			store := ipsec.NewConnectionStore(p)
			c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
			if err != nil {
				t.Fatal(err)
			}
			var captured ipsec.RuntimePolicyInput
			refuseCompiler := errors.New("stop after locked input observation")
			store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
				captured = in
				return ipsec.RuntimePolicy{}, refuseCompiler
			})
			for _, tc := range []struct {
				name, value string
				want        int
			}{{"missing", "{}", 0}, {"string", "{\"ipsec_fqdn_policy_version\":\"1\"}", 0}, {"future", "{\"ipsec_fqdn_policy_version\":3}", 0}, {"current v2", "{\"ipsec_fqdn_policy_version\":2}", 2}, {"current", "{\"ipsec_fqdn_policy_version\":1}", 1}} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities=(capabilities-'ipsec_fqdn_policy_version')||$2::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID, tc.value); err != nil {
						t.Fatal(err)
					}
					captured = ipsec.RuntimePolicyInput{}
					if _, err := store.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
						t.Fatalf("compiler refusal lost: %v", err)
					}
					if captured.FQDNPolicyVersion != tc.want || captured.ConfigurationRevision != 1 || captured.Transaction == nil || captured.ConnectionID != c.ID || captured.NodeID != identity.GatewayID || captured.Config.ProfileID != profile || captured.Config.Mode != req.Config.Mode {
						t.Fatalf("locked input changed: %+v", captured)
					}
					got, err := store.Read(ctx, org, c.ID)
					if err != nil || got.DesiredIntent != "disabled" || got.DesiredRevision != 1 {
						t.Fatal("refusal mutated intent", err)
					}
				})
			}
			grant := ipsec.RuntimeFQDNGrant{RuntimeGrant: ipsec.RuntimeGrant{Source: "10.10.0.10/32", Destination: "10.20.0.10/32", Protocol: "tcp", PortLow: 8080, PortHigh: 8080, RuleID: uuid.NewString()}, FQDNManaged: true, ResourceID: uuid.NewString(), Name: "app.private.example", Generation: strings.Repeat("b", 64), ResolverConfigID: uuid.NewString(), ResolverConfigVersion: 1, SelectedSiteID: identity.SiteID.String(), SelectedGatewayID: identity.GatewayID.String(), ResolverProfileID: uuid.NewString(), ResolverMatchSuffix: "private.example", ConnectionID: c.ID.String(), ConfigurationRevision: 1}
			store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
				g := grant
				g.ConnectionID = uuid.NewString()
				return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), FQDNPolicyVersion: 1, FQDNGrants: []ipsec.RuntimeFQDNGrant{g}}, nil
			})
			if _, err := store.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
				t.Fatalf("foreign provenance admitted: %v", err)
			}
			validUntil := time.Now().Add(5 * time.Second)
			store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
				return ipsec.RuntimePolicy{FQDNLeaseDeadline: validUntil, Hash: strings.Repeat("a", 64), FQDNPolicyVersion: 1, FQDNGrants: []ipsec.RuntimeFQDNGrant{grant}}, nil
			})
			enabled, err := store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
			if err != nil || enabled.DesiredRevision != 2 {
				t.Fatal("valid common FQDN policy rejected", err)
			}
			principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
			material, err := store.Material(ctx, principal, c.ID, 2, sealer)
			if err != nil {
				t.Fatal(err)
			}
			leaseRequest := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: 2, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("c", 64)}
			lease, err := store.PermitLease(ctx, principal, c.ID, leaseRequest)
			if err != nil || lease.TTLMS <= 0 || lease.TTLMS > 5000 {
				t.Fatalf("answer expiry not bounding lease: %d %v", lease.TTLMS, err)
			}
			validUntil = time.Now().Add(-time.Second)
			if _, err := store.PermitLease(ctx, principal, c.ID, leaseRequest); !errors.Is(err, ipsec.ErrConnectionConflict) {
				t.Fatalf("expired answer renewed: %v", err)
			}
			want := 2
			if profile == ipsec.GCPClassicProfile {
				want = 1
			}
			actual := 0
			for _, tun := range material.Manifest.Tunnels {
				if tun.ID != uuid.Nil {
					actual++
				}
			}
			if actual != want || material.Manifest.ProfileID != profile || len(material.Policy.FQDNGrants) != 1 || material.Policy.FQDNGrants[0] != grant {
				t.Fatal("FQDN graft changed provider cardinality or policy")
			}
		})
	}
}
