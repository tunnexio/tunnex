package ipsec_test

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func TestAzureBGPRecreationExpansionContraction(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 226); e != nil {
		t.Fatal(e)
	}
	req.Config.Mode = "ipv4-bgp"
	req.Config.ProfileID = ipsec.AzureActiveActiveBGPProfile
	req.Config.Azure = &ipsec.AzureContract{GatewaySKU: "VpnGw1AZ", VPNType: "RouteBased", IKEVersion: 2, CustomPolicy: "aes256-sha256-dh14-pfs2048"}
	req.Config.BGP = &ipsec.BGPConfig{LocalASN: 64512, RemoteASN: 65515, RouterID: "10.10.0.1", MaximumPrefixes: 8}
	for i := range req.Config.Tunnels {
		req.Config.Tunnels[i].InsideCIDR = "169.254.10.1/32"
		req.Config.Tunnels[i].CustomerInsideAddress = "169.254.10.1"
		req.Config.Tunnels[i].CloudInsideAddress = []string{"169.254.21.2", "169.254.22.2"}[i]
		req.Config.Tunnels[i].PSK = "Azure-test-secret"
	}
	_, e := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_bgp_version":1,"ipsec_azure_version":1,"ipsec_retained_guard_version":1,"ipsec_azure_bgp_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
	if e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial)
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	fresh := func() ipsec.CreateProviderRequest {
		r := req
		r.ID = uuid.New()
		r.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
		return r
	}
	var prior ipsec.Connection
	var priorManifest ipsec.RuntimeManifest
	for stage := 0; stage < 3; stage++ {
		r := fresh()
		b := *req.Config.BGP
		r.Config.BGP = &b
		if stage == 1 {
			r.Config.RemotePrefixes = append(append([]string(nil), req.Config.RemotePrefixes...), "10.235.77.0/24")
			r.Config.BGP.MaximumPrefixes = 1
		}
		if stage > 0 {
			_, e = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_bgp_recreation_version' WHERE id=$1`, req.GatewayID)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, r); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("missingcap %v", e)
			}
			p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_bgp_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
			_, e = p.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, req.GatewayID)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, r); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("stale %v", e)
			}
			p.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
			foreign := uuid.New()
			_, e = p.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) SELECT $1::uuid,org_id,($1::uuid)::text,($1::uuid)::text,site_id,capabilities,clock_timestamp() FROM nodes WHERE id=$2`, foreign, req.GatewayID)
			if e != nil {
				t.Fatal(e)
			}
			foreignRequest := r
			foreignRequest.GatewayID = foreign
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, foreignRequest); !errors.Is(e, ipsec.ErrConnectionConflict) {
				t.Fatalf("foreign gateway %v", e)
			}
			changed := r
			changed.Config.Tunnels = append([]ipsec.StaticTunnel(nil), r.Config.Tunnels...)
			changed.Config.Tunnels[0].OutsideAddress = "8.8.4.4"
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, changed); !errors.Is(e, ipsec.ErrConnectionConflict) {
				t.Fatalf("changedpeer %v", e)
			}
			bad := r
			bad.Config.RemotePrefixes = []string{req.Config.RemotePrefixes[0], "10.20.1.0/24"}
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, bad); !errors.Is(e, ipsec.ErrConnectionConflict) && !errors.Is(e, ipsec.ErrConnectionInvalid) {
				t.Fatalf("overlap %v", e)
			}
		}
		c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, r)
		if e != nil {
			t.Fatalf("create%d %v", stage, e)
		}
		if stage > 0 {
			p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_bgp_recreation_version' WHERE id=$1`, req.GatewayID)
			if _, e = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("enable missingcap %v", e)
			}
			p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_bgp_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
		}
		c, e = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if e != nil {
			t.Fatal(e)
		}
		if stage > 0 {
			for _, kind := range []string{"missingrefs", "forgedref", "wrongversion"} {
				f := priorManifest
				f.ConnectionID = c.ID
				f.DesiredRevision = c.DesiredRevision
				v := 1
				f.AzureBGPRecreationVersion = &v
				f.RetainedGuardPredecessors = nil
				if kind == "forgedref" {
					f.RetainedGuardPredecessors = []ipsec.RuntimeRetainedGuardPredecessor{{ConnectionID: prior.ID, DeliveryID: uuid.New(), CleanupDeliveryID: uuid.New(), OwnershipDigest: strings.Repeat("f", 64)}}
				}
				if kind == "wrongversion" {
					v = 2
				}
				raw, _ := json.Marshal(f)
				_, e = p.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,'apply',1,$7,$8,$9)`, uuid.New(), c.ID, org, req.GatewayID, req.SiteID, c.DesiredRevision, strings.Repeat("a", 64), raw, serial)
				if e == nil {
					t.Fatal("direct SQL forged delivery accepted")
				}
			}
		}
		if stage > 0 {
			p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_bgp_recreation_version' WHERE id=$1`, req.GatewayID)
			if _, e = s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("material missingcap %v", e)
			}
			page, e := s.Pending(ctx, principal, nil, 20)
			if e != nil {
				t.Fatal(e)
			}
			for _, item := range page.Items {
				if item.ConnectionID == c.ID {
					t.Fatal("pending missingcap exposed")
				}
			}
			p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_bgp_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
		}
		m, e := s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatalf("material%d %v", stage, e)
		}
		if stage == 0 && m.Manifest.AzureBGPRecreationVersion != nil || stage > 0 && (m.Manifest.AzureBGPRecreationVersion == nil || *m.Manifest.AzureBGPRecreationVersion != 1 || len(m.Manifest.RetainedGuardPredecessors) != stage) {
			t.Fatal("refs/version")
		}
		c, e = s.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, fresh()); !errors.Is(e, ipsec.ErrConnectionConflict) {
			t.Fatalf("pending/finalized barrier %v", e)
		}
		cleanup, e := s.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		e = s.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true})
		if e != nil {
			t.Fatal(e)
		}
		prior = c
		priorManifest = m.Manifest
	}
	if e = db.MigrateTo(p.Config().ConnString(), 225); e == nil {
		t.Fatal("down used history")
	}
	_ = prior
}
