package ipsec_test

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

// This exercises genuine disposable PostgreSQL creation, compiler delivery and
// authenticated cleanup before requesting a distinct immutable Azure profile.
func TestAzureProfileRecreationFinalizedBGPToStatic(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 227); e != nil {
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
	if _, e := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_bgp_version":1,"ipsec_recovery_version":1,"ipsec_azure_version":1,"ipsec_retained_guard_version":1,"ipsec_azure_bgp_recreation_version":1,"ipsec_azure_profile_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	if e := p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); e != nil {
		t.Fatal(e)
	}
	c, e = s.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	cleanup, e := s.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
		t.Fatal(e)
	}
	next := req
	next.ID = uuid.New()
	next.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	next.Config = staticConfigFixture()
	next.Config.ProfileID = ipsec.AzureActiveActiveStaticProfile
	next.Config.Azure = req.Config.Azure
	for i := range next.Config.Tunnels {
		next.Config.Tunnels[i].InsideCIDR = []string{"169.254.70.0/30", "169.254.71.0/30"}[i]
		next.Config.Tunnels[i].CustomerInsideAddress = []string{"169.254.70.1", "169.254.71.1"}[i]
		next.Config.Tunnels[i].CloudInsideAddress = []string{"169.254.70.2", "169.254.71.2"}[i]
		next.Config.Tunnels[i].PSK = "Azure-test-secret"
	}

	for stage, profile := range []string{ipsec.AzureActiveActiveStaticProfile, ipsec.AzureActiveStandbyBGPProfile, ipsec.AzureActiveStandbyStaticProfile, ipsec.AzureActiveActiveBGPProfile, ipsec.AzureActiveStandbyBGPProfile, ipsec.AzureActiveActiveBGPProfile} {
		candidate := next
		candidate.ID = uuid.New()
		candidate.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
		if profile == ipsec.AzureActiveStandbyBGPProfile || profile == ipsec.AzureActiveActiveBGPProfile {
			candidate.Config = req.Config
			candidate.Config.Tunnels = append([]ipsec.StaticTunnel(nil), req.Config.Tunnels...)
		} else {
			candidate.Config = next.Config
			candidate.Config.Tunnels = append([]ipsec.StaticTunnel(nil), next.Config.Tunnels...)
		}
		candidate.Config.ProfileID = profile
		if profile == ipsec.AzureActiveStandbyBGPProfile || profile == ipsec.AzureActiveStandbyStaticProfile {
			candidate.Config.Tunnels = candidate.Config.Tunnels[:1]
			candidate.TunnelIDs[1] = uuid.Nil
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_profile_recreation_version' WHERE id=$1`, req.GatewayID)
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, candidate); !errors.Is(e, ipsec.ErrConnectionIneligible) {
			t.Fatalf("stage%d missing capability: %v", stage, e)
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_profile_recreation_version":1}'::jsonb,policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, req.GatewayID)
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, candidate); !errors.Is(e, ipsec.ErrConnectionIneligible) {
			t.Fatalf("stage%d stale: %v", stage, e)
		}
		p.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
		for _, bgpBit := range []string{"0", "2"} {
			if _, e = p.Exec(ctx, `UPDATE nodes SET capabilities=jsonb_set(capabilities,'{ipsec_bgp_version}',$2::jsonb) WHERE id=$1`, req.GatewayID, bgpBit); e != nil {
				t.Fatal(e)
			}
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, candidate); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("stage%d unsupported BGP capability: %v", stage, e)
			}
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_bgp_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
		changed := candidate
		changed.Config.Tunnels = append([]ipsec.StaticTunnel(nil), candidate.Config.Tunnels...)
		changed.Config.Tunnels[0].OutsideAddress = "8.8.4.4"
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, changed); !errors.Is(e, ipsec.ErrConnectionConflict) {
			t.Fatalf("changed shared peer accepted: %v", e)
		}
		overlap := candidate
		overlap.Config.RemotePrefixes = []string{"10.20.0.0/16", "10.20.1.0/24"}
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, overlap); !errors.Is(e, ipsec.ErrConnectionConflict) && !errors.Is(e, ipsec.ErrConnectionInvalid) {
			t.Fatalf("unequal overlap accepted: %v", e)
		}

		foreign := candidate
		foreign.SiteID = uuid.New()
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, foreign); e == nil {
			t.Fatal("foreign Site accepted")
		}
		foreign = candidate
		foreign.GatewayID = uuid.New()
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, foreign); e == nil {
			t.Fatal("foreign gateway accepted")
		}
		for _, legacy := range []string{"aws-static-ipv4-v1", ipsec.GCPClassicProfile} {
			foreign = candidate
			foreign.Config = next.Config
			foreign.Config.ProfileID = legacy
			foreign.Config.Azure = nil
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, foreign); e == nil {
				t.Fatal("foreign provider accepted")
			}
		}
		if candidate.Config.BGP != nil {
			changed = candidate
			b := *candidate.Config.BGP
			b.LocalASN = 64513
			changed.Config.BGP = &b
			if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, changed); !errors.Is(e, ipsec.ErrConnectionConflict) {
				t.Fatalf("changed ASN accepted: %v", e)
			}
		}
		c, e = s.CreateProviderDisabled(ctx, org, actor, sealer, candidate)
		if e != nil {
			t.Fatalf("fully finalized stage%d %s refused: %v", stage, profile, e)
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_profile_recreation_version' WHERE id=$1`, req.GatewayID)
		if _, e = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
			t.Fatalf("enable missing capability: %v", e)
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_profile_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
		c, e = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if e != nil {
			t.Fatal(e)
		}
		material, e := s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatalf("material stage%d: %v", stage, e)
		}

		archived, _ := json.Marshal(material.Manifest)
		for _, field := range []string{"slot", "outside_address", "inside_cidr", "customer_inside_address", "cloud_inside_address"} {
			for _, null := range []bool{false, true} {
				var broken map[string]any
				json.Unmarshal(archived, &broken)
				tunnel := broken["tunnels"].([]any)[0].(map[string]any)
				if null {
					tunnel[field] = nil
				} else {
					delete(tunnel, field)
				}
				raw, _ := json.Marshal(broken)
				var accepted bool
				if e = p.QueryRow(ctx, `SELECT ipsec_azure_profile_historical_contract($1::jsonb)`, raw).Scan(&accepted); e != nil || accepted {
					t.Fatalf("malformed historical %s null=%t accepted=%t error=%v", field, null, accepted, e)
				}
			}
		}
		if material.Manifest.AzureProfileRecreationVersion == nil || *material.Manifest.AzureProfileRecreationVersion != 1 || material.Manifest.AzureBGPRecreationVersion != nil || len(material.Manifest.RetainedGuardPredecessors) != stage+1 {
			t.Fatal("incomplete cross-profile version/history")
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_profile_recreation_version' WHERE id=$1`, req.GatewayID)
		if _, e = s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); !errors.Is(e, ipsec.ErrConnectionIneligible) {
			t.Fatalf("material missing capability: %v", e)
		}
		pending, e := s.Pending(ctx, principal, nil, 20)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range pending.Items {
			if item.ConnectionID == c.ID {
				t.Fatal("pending exposed incompatible node")
			}
		}
		p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_azure_profile_recreation_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
		forged := material.Manifest
		forged.AzureProfileRecreationVersion = nil
		raw, _ := json.Marshal(forged)
		if _, e = p.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,'apply',1,$7,$8,$9)`, uuid.New(), c.ID, org, req.GatewayID, req.SiteID, c.DesiredRevision, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", raw, serial); e == nil {
			t.Fatal("direct SQL omitted cross-profile version accepted")
		}
		var predicateError *pgconn.PgError
		if !errors.As(e, &predicateError) || predicateError.Code != "23514" || predicateError.ConstraintName != "ipsec_runtime_binding" || predicateError.Message != "Azure profile recreation manifest invalid" {
			t.Fatalf("direct SQL failed at wrong boundary: %v", e)
		}
		c, e = s.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		blocked := candidate
		blocked.ID = uuid.New()
		blocked.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
		if len(blocked.Config.Tunnels) == 1 {
			blocked.TunnelIDs[1] = uuid.Nil
		}
		if _, e = s.CreateProviderDisabled(ctx, org, actor, sealer, blocked); !errors.Is(e, ipsec.ErrConnectionConflict) {
			t.Fatalf("pending cleanup accepted: %v", e)
		}
		cleanup, e = s.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
			t.Fatal(e)
		}
	}
	if e = db.MigrateTo(p.Config().ConnString(), 226); e == nil {
		t.Fatal("downgrade discarded cross-profile history")
	}
}
