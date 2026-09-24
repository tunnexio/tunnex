package ipsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func providerRequest(r ipsec.CreateDisabledRequest) ipsec.CreateProviderRequest {
	c := staticConfigFixture()
	return ipsec.CreateProviderRequest{ID: r.ID, SiteID: r.SiteID, GatewayID: r.GatewayID, Name: r.Name, TunnelIDs: [2]uuid.UUID{r.Tunnels[0].ID, r.Tunnels[1].ID}, Config: c}
}
func TestProviderCreateReadDelete(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	subnet := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, subnet, identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	s := ipsec.NewConnectionStore(p)
	created, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil || created.DesiredIntent != "disabled" {
		t.Fatalf("create: %v", err)
	}
	config, err := s.ReadProvider(ctx, org, created.ID)
	if err != nil || config.ProfileID != "aws-static-ipv4-v1" || config.ConfigurationRevision != 1 || config.Config == nil || len(config.Config.Tunnels) != 2 {
		t.Fatalf("provider read: %v", err)
	}
	raw, _ := json.Marshal(config)
	if strings.Contains(string(raw), "PSK") || strings.Contains(string(raw), "psk") || strings.Contains(string(raw), "sealed") {
		t.Fatal("provider read disclosed credential metadata")
	}
	if _, err = s.ReadProvider(ctx, uuid.New(), created.ID); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("provider cross-org read allowed")
	}
	if _, err = s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("duplicate identity=%v", err)
	}
	if _, err = s.Delete(ctx, org, actor, created.ID, 1); err != nil {
		t.Fatalf("delete=%v", err)
	}
	config, err = s.ReadProvider(ctx, org, created.ID)
	if err != nil || config.Config != nil || config.ProfileID != "aws-static-ipv4-v1" {
		t.Fatalf("tombstone projection: %v", err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_aws_static_configs WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_tunnel_configs WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_local_prefixes WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("owned cleanup residue%d %v", count, err)
	}
	if err = p.QueryRow(ctx, `SELECT count(*) FROM site_subnets WHERE id=$1 AND status='approved'`, subnet).Scan(&count); err != nil || count != 1 {
		t.Fatal("shared subnet changed")
	}
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	if _, err = s.CreateProviderDisabled(ctx, org, actor, sealer, req); err != nil {
		t.Fatalf("owned reservations not released: %v", err)
	}
}
func TestProviderCreateAdmissionAndRollback(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	req := providerRequest(identity)
	s := ipsec.NewConnectionStore(p)
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("missing exact subnet:%v", err)
	}
	subnet := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, subnet, identity.SiteID); err != nil {
		t.Fatal(err)
	}
	// Audit's actor FK fails after all provider children/secrets were inserted.
	if _, err := s.CreateProviderDisabled(ctx, org, uuid.New(), sealer, req); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("audit fault=%v", err)
	}
	var count int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1)+(SELECT count(*) FROM ipsec_provider_bindings WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback residue%d %v", count, err)
	}
	req.Config.LocalPrefixes = []string{"10.10.1.0/24"}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("subprefix accepted:%v", err)
	}
	req = providerRequest(identity)
	if _, err := p.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("optout accepted:%v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=true,revision=revision+1 WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities='{}' WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("unsupported accepted:%v", err)
	}
}

func providerFixture(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID, *crypto.Sealer, ipsec.CreateProviderRequest) {
	t.Helper()
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	return ctx, p, org, actor, sealer, providerRequest(identity)
}

func TestProviderGatewayReservationsAndDeleteRollback(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	s := ipsec.NewConnectionStore(p)
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); err != nil {
		t.Fatal(err)
	}
	second := req
	second.ID = uuid.New()
	second.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	second.Config.RemotePrefixes = []string{"10.21.0.0/16"}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, second); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("same gateway address reuse:%v", err)
	}
	insideOnly := second
	insideOnly.Config.Tunnels = append([]ipsec.StaticTunnel(nil), second.Config.Tunnels...)
	insideOnly.Config.Tunnels[0].OutsideAddress = "2.2.2.2"
	insideOnly.Config.Tunnels[1].OutsideAddress = "3.3.3.3"
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, insideOnly); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("same gateway inside-only reuse:%v", err)
	}
	peerOnly := second
	peerOnly.Config.Tunnels = append([]ipsec.StaticTunnel(nil), second.Config.Tunnels...)
	peerOnly.Config.Tunnels[0].InsideCIDR = "169.254.20.0/30"
	peerOnly.Config.Tunnels[0].CustomerInsideAddress = "169.254.20.2"
	peerOnly.Config.Tunnels[0].CloudInsideAddress = "169.254.20.1"
	peerOnly.Config.Tunnels[1].InsideCIDR = "169.254.20.4/30"
	peerOnly.Config.Tunnels[1].CustomerInsideAddress = "169.254.20.6"
	peerOnly.Config.Tunnels[1].CloudInsideAddress = "169.254.20.5"
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, peerOnly); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("same gateway peer-only reuse:%v", err)
	}
	second.GatewayID = uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'other provider gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, second.GatewayID, org, second.GatewayID.String(), second.SiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, second); err != nil {
		t.Fatalf("different gateway disjoint remote may reuse peer/inside:%v", err)
	}
	third := second
	third.ID = uuid.New()
	third.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	third.Config.RemotePrefixes = []string{"10.20.1.0/24"}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, third); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("cross-gateway remote overlap:%v", err)
	}
	// Terminal audit failure must restore both owned reservations and config.
	if _, err := s.Delete(ctx, org, uuid.New(), req.ID, 1); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("delete audit failure:%v", err)
	}
	var retained int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_provider_bindings WHERE connection_id=$1 AND NOT withdrawal_started)+(SELECT count(*) FROM ipsec_aws_static_configs WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_aws_tunnel_configs WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_aws_local_prefixes WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$1)`, req.ID).Scan(&retained); err != nil || retained != 10 {
		t.Fatalf("faileddelete rollback retained%d:%v", retained, err)
	}
	if read, err := s.ReadProvider(ctx, org, req.ID); err != nil || read.Config == nil {
		t.Fatalf("failed delete lost config:%v", err)
	}
	if _, err := s.Delete(ctx, org, actor, req.ID, 1); err != nil {
		t.Fatal(err)
	}
	if read, err := s.ReadProvider(ctx, org, second.ID); err != nil || read.Config == nil {
		t.Fatalf("delete removed unrelated reservations:%v", err)
	}
}
func TestProviderConflictAndChildFailureAtomicity(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	s := ipsec.NewConnectionStore(p)
	req.Config.RemotePrefixes = []string{"10.199.0.0/24"}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("pool overlap:%v", err)
	}
	req.Config.RemotePrefixes = []string{"10.20.0.0/16"}
	// Fail after connection, envelopes, binding and tunnel configs have been written.
	if _, err := p.Exec(ctx, `CREATE FUNCTION test_provider_child_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private database detail'; END $$; CREATE TRIGGER test_provider_child_failure BEFORE INSERT ON ipsec_aws_remote_prefixes FOR EACH ROW EXECUTE FUNCTION test_provider_child_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatalf("child fault not redacted:%v", err)
	}
	var n int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1)+(SELECT count(*) FROM ipsec_provider_bindings WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_static_configs WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_tunnel_configs WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_local_prefixes WHERE org_id=$1)+(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1)+(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("child fault residue%d:%v", n, err)
	}
}

func TestProviderConcurrentConflictingCreates(t *testing.T) {
	ctx, p, org, actor, sealer, first := providerFixture(t)
	second := first
	second.ID = uuid.New()
	second.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	second.GatewayID = uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'competing provider gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, second.GatewayID, org, second.GatewayID.String(), second.SiteID); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, req := range []ipsec.CreateProviderRequest{first, second} {
		workers.Add(1)
		go func(req ipsec.CreateProviderRequest) {
			defer workers.Done()
			<-start
			_, err := ipsec.NewConnectionStore(p).CreateProviderDisabled(ctx, org, actor, sealer, req)
			results <- err
		}(req)
	}
	close(start)
	workers.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ipsec.ErrConnectionConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected create outcome:%v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success%d conflict%d", success, conflict)
	}
	var records, audits int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_provider_bindings WHERE org_id=$1),(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&records, &audits); err != nil || records != 1 || audits != 1 {
		t.Fatalf("concurrent atomic result%d/%d:%v", records, audits, err)
	}
}
