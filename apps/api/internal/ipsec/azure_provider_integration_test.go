package ipsec_test

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func TestAzureProviderPersistenceCapabilityAndMaterial(t *testing.T) {
	for _, profile := range []string{ipsec.AzureActiveActiveBGPProfile, ipsec.AzureActiveActiveStaticProfile, ipsec.AzureActiveStandbyBGPProfile, ipsec.AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			ctx, p, org, actor, sealer, identity := createFixture(t)
			if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 225); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
				t.Fatal(err)
			}
			req := providerRequest(identity)
			req.Config = bgpConfigFixture()
			req.Config.ProfileID = profile
			req.Config.Azure = &ipsec.AzureContract{GatewaySKU: "VpnGw1AZ", VPNType: "RouteBased", IKEVersion: 2, CustomPolicy: "aes256-sha256-dh14-pfs2048"}
			for i := range req.Config.Tunnels {
				if i == 0 {
					req.Config.Tunnels[i].InsideCIDR = "169.254.21.0/30"
					req.Config.Tunnels[i].CustomerInsideAddress = "169.254.21.1"
					req.Config.Tunnels[i].CloudInsideAddress = "169.254.21.2"
				} else {
					req.Config.Tunnels[i].InsideCIDR = "169.254.22.0/30"
					req.Config.Tunnels[i].CustomerInsideAddress = "169.254.22.1"
					req.Config.Tunnels[i].CloudInsideAddress = "169.254.22.2"
				}
				req.Config.Tunnels[i].PSK = "0-Azure-secret!"
			}
			bgp := profile == ipsec.AzureActiveActiveBGPProfile || profile == ipsec.AzureActiveStandbyBGPProfile
			standby := profile == ipsec.AzureActiveStandbyBGPProfile || profile == ipsec.AzureActiveStandbyStaticProfile
			if bgp {
				for i := range req.Config.Tunnels {
					req.Config.Tunnels[i].InsideCIDR = "169.254.20.1/32"
					req.Config.Tunnels[i].CustomerInsideAddress = "169.254.20.1"
				}
				req.Config.BGP.RemoteASN = 65515
				req.Config.BGP.LocalASN = 12345
			} else {
				req.Config.Mode = "ipv4-static"
				req.Config.BGP = nil
			}
			if standby {
				req.Config.Tunnels = req.Config.Tunnels[:1]
				req.TunnelIDs[1] = uuid.Nil
			}
			s := ipsec.NewConnectionStore(p)
			s.ConfigureRuntimePolicy(runtimeCompiler)
			c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Exec(ctx, `UPDATE ipsec_azure_configs SET gateway_sku='VpnGw2AZ' WHERE connection_id=$1`, c.ID); err == nil {
				t.Fatal("Azure metadata mutation accepted")
			}

			deleted, err := s.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
			if err != nil || deleted.FinalizedAt == nil {
				t.Fatal("never-delivered delete", err)
			}
			tombstone, err := s.ReadProvider(ctx, org, c.ID)
			if err != nil || tombstone.Config != nil || tombstone.ProfileID != profile {
				t.Fatal("deleted metadata projection", err)
			}
			req.ID = uuid.New()
			req.TunnelIDs[0] = uuid.New()
			if !standby {
				req.TunnelIDs[1] = uuid.New()
			}
			c, err = s.CreateProviderDisabled(ctx, org, actor, sealer, req)
			if err != nil {
				t.Fatal("disabled recreation", err)
			}
			for _, bad := range []string{"short", strings.Repeat("x", 65)} {
				replacements := []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: bad}}
				if !standby {
					replacements = append(replacements, ipsec.RotatePSK{TunnelID: req.TunnelIDs[1], PSK: bad})
				}
				if _, err = s.RotatePSKs(ctx, org, actor, c.ID, 1, replacements, sealer); !errors.Is(err, ipsec.ErrConnectionInvalid) {
					t.Fatal("invalid Azure rotation length", err)
				}
			}
			if !standby {
				if _, err = s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "newAzureKey"}}, sealer); !errors.Is(err, ipsec.ErrConnectionInvalid) {
					t.Fatal("single-slot Azure connection key rotation accepted")
				}
			}

			replacements := []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "sameAzureReplacement"}}
			if !standby {
				replacements = append(replacements, ipsec.RotatePSK{TunnelID: req.TunnelIDs[1], PSK: "sameAzureReplacement"})
			}
			c, err = s.RotatePSKs(ctx, org, actor, c.ID, 1, replacements, sealer)
			if err != nil || c.DesiredRevision != 2 {
				t.Fatal("atomic Azure key rotation", err)
			}
			if _, err = s.RotatePSKs(ctx, org, actor, c.ID, 1, replacements, sealer); !errors.Is(err, ipsec.ErrConnectionConflict) {
				t.Fatal("stale rotation CAS accepted", err)
			}
			got, err := s.ReadProvider(ctx, org, c.ID)
			if err != nil || got.Config == nil || len(got.Config.Tunnels) != len(req.Config.Tunnels) {
				t.Fatalf("read mismatch %v", err)
			}
			if _, err = s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
				t.Fatalf("missing Azure capability accepted: %v", err)
			}
			if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_bgp_version":1,"ipsec_azure_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
				t.Fatal(err)
			}
			enabled, err := s.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
			if err != nil {
				t.Fatal(err)
			}
			principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
			material, err := s.Material(ctx, principal, c.ID, enabled.DesiredRevision, sealer)
			if err != nil {
				t.Fatal(err)
			}
			if material.Manifest.ProfileID != profile || bgp && (material.Manifest.BGPVersion == nil || *material.Manifest.BGPVersion != 3) || standby && (material.Manifest.TunnelCount == nil || *material.Manifest.TunnelCount != 1 || material.Secrets[1] != (ipsec.RuntimeSecret{})) {
				t.Fatal("wire contract mismatch")
			}
			report := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: enabled.DesiredRevision, ConfigurationRevision: 1, TransportVersion: material.Manifest.TransportVersion, TunnelCount: material.Manifest.TunnelCount}
			for i, tun := range material.Manifest.Tunnels[:len(req.Config.Tunnels)] {
				report.Tunnels[i] = ipsec.RuntimeTunnelStatus{ID: tun.ID, Slot: tun.Slot, Status: "up", Selected: tun.Selected}
			}
			if bgp {
				report.BGP = &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 1, Routes: []ipsec.RuntimeBGPRoute{}}
				for i := range req.Config.Tunnels {
					report.BGP.Peers[i] = ipsec.RuntimeBGPPeerStatus{Slot: i + 1, State: "established"}
				}
			}
			if err = s.ReportStatus(ctx, principal, c.ID, report); err != nil {
				t.Fatal("report status", err)
			}
			status, err := s.ReadStatus(ctx, org, c.ID)
			if err != nil || len(status.Tunnels) != len(req.Config.Tunnels) || status.Tunnels[0].Status != "up" || bgp && status.BGP == nil {
				t.Fatalf("status readback failed %v", err)
			}
			if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_azure_version' WHERE id=$1`, identity.GatewayID); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Material(ctx, principal, c.ID, enabled.DesiredRevision, sealer); !errors.Is(err, ipsec.ErrConnectionIneligible) {
				t.Fatalf("revoked Azure capability accepted: %v", err)
			}
			if err = db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err == nil {
				t.Fatal("rollback erased Azure ownership")
			}
		})
	}
}

func TestAzureMigrationEmptyRollbackPreservesLegacy(t *testing.T) {
	_, p, _, _, _, _ := createFixture(t)
	dsn := p.Config().ConnConfig.ConnString()
	for _, version := range []uint{225, 224, 225} {
		if err := db.MigrateTo(dsn, version); err != nil {
			t.Fatal(err)
		}
	}
}
