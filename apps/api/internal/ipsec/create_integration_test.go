package ipsec_test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func createFixture(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID, *crypto.Sealer, ipsec.CreateDisabledRequest) {
	ctx, p, org, actor := settingsFixture(t)
	site, node := uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'create site')`, site, org); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'create gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, node, org, node.String(), site); err != nil {
		t.Fatal(err)
	}
	if _, err := ipsec.NewSettingsStore(p).Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x49}, 32))
	if err != nil {
		t.Fatal(err)
	}
	req := ipsec.CreateDisabledRequest{ID: uuid.New(), SiteID: site, GatewayID: node, Name: "Disabled configuration", Tunnels: [2]ipsec.CreateTunnel{{ID: uuid.New(), PSK: "synthetic-create-SECRET-ONE"}, {ID: uuid.New(), PSK: "synthetic-create-SECRET-TWO"}}}
	return ctx, p, org, actor, sealer, req
}
func TestCreateDisabledAtomicRedactionAndIdentity(t *testing.T) {
	ctx, p, org, actor, sealer, req := createFixture(t)
	s := ipsec.NewConnectionStore(p)
	got, err := s.CreateDisabled(ctx, org, actor, sealer, req)
	if err != nil || got.ID != req.ID || got.DesiredRevision != 1 || got.DesiredIntent != "disabled" {
		t.Fatalf("create=%+v %v", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "sealed") {
		t.Fatal("response secret exposure")
	}
	for i, tun := range req.Tunnels {
		var sealed string
		var slot int
		if err := p.QueryRow(ctx, `SELECT t.slot,s.sealed_psk FROM ipsec_tunnels t JOIN ipsec_tunnel_secrets s ON s.tunnel_id=t.id WHERE t.id=$1`, tun.ID).Scan(&slot, &sealed); err != nil {
			t.Fatal(err)
		}
		if slot != i+1 || strings.Contains(sealed, "SECRET") {
			t.Fatal("bad slot or plaintext storage")
		}
		value, err := ipsec.OpenPSK(sealer, ipsec.PSKBinding{OrgID: org, ConnectionID: req.ID, TunnelID: tun.ID, Revision: 1}, sealed)
		if err != nil || value != tun.PSK {
			t.Fatalf("envelope binding failure: %v", err)
		}
	}
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("duplicate=%v", err)
	}
	var audits int
	var metadata string
	if err := p.QueryRow(ctx, `SELECT count(*),min(metadata::text) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='ipsec.connection_created' AND target_id=$3`, org, actor, req.ID.String()).Scan(&audits, &metadata); err != nil || audits != 1 {
		t.Fatalf("audit=%d %v", audits, err)
	}
	if strings.Contains(metadata, "SECRET") || strings.Contains(metadata, "sealed") || strings.Contains(metadata, "psk") {
		t.Fatal("audit exposed credentials")
	}
}
func TestCreateDisabledEligibility(t *testing.T) {
	cases := []struct{ name, q string }{
		{"opt-out", `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$2`},
		{"revoked", `UPDATE nodes SET revoked_at=now() WHERE id=$1`},
		{"inactive", `UPDATE nodes SET status='revoked' WHERE id=$1`},
		{"unenrolled", `UPDATE nodes SET cert_serial='' WHERE id=$1`},
		{"no-capability", `UPDATE nodes SET capabilities='{}' WHERE id=$1`},
		{"future-version", `UPDATE nodes SET capabilities='{"ipsec_config_version":2}' WHERE id=$1`},
		{"string-version", `UPDATE nodes SET capabilities='{"ipsec_config_version":"1"}' WHERE id=$1`},
		{"null-version", `UPDATE nodes SET capabilities='{"ipsec_config_version":null}' WHERE id=$1`},
		{"no-report", `UPDATE nodes SET policy_reported_at=NULL WHERE id=$1`},
		{"stale-report-fresh-poll", `UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds',last_seen_at=clock_timestamp() WHERE id=$1`},
		{"future-report", `UPDATE nodes SET policy_reported_at=clock_timestamp()+interval '1 minute' WHERE id=$1`},
		{"unbound", `UPDATE nodes SET site_id=NULL WHERE id=$1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, p, org, actor, sealer, req := createFixture(t)
			q := strings.ReplaceAll(tc.q, "$2", "$1")
			arg := req.GatewayID
			if tc.name == "opt-out" {
				arg = org
			}
			if _, err := p.Exec(ctx, q, arg); err != nil {
				t.Fatal(err)
			}
			if _, err := ipsec.NewConnectionStore(p).CreateDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
				t.Fatalf("gate=%v", err)
			}
			var n int
			if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections WHERE org_id=$1`, org).Scan(&n); err != nil || n != 0 {
				t.Fatalf("gate wrote=%d %v", n, err)
			}
		})
	}
}
func TestCreateDisabledFailureRollback(t *testing.T) {
	ctx, p, org, actor, sealer, req := createFixture(t)
	s := ipsec.NewConnectionStore(p)
	check := func() {
		t.Helper()
		var n int
		if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)+(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rollback residue=%d %v", n, err)
		}
	}
	if _, err := s.CreateDisabled(ctx, org, actor, nil, req); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("nil sealer=%v", err)
	}
	check()
	bad := req
	bad.Tunnels[1].PSK = "\n"
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, bad); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("bad second credential=%v", err)
	}
	check()
	bad = req
	bad.Tunnels[1].ID = bad.Tunnels[0].ID
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, bad); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("duplicate tunnel=%v", err)
	}
	check()
	bad = req
	bad.Name = " "
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, bad); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("blank name=%v", err)
	}
	check()
	if _, err := s.CreateDisabled(ctx, org, uuid.New(), sealer, req); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("audit failure=%v", err)
	}
	check()
	other := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'other',$2,'10.197.0.0/24')`, other, other.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDisabled(ctx, other, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("missing setting=%v", err)
	}
	check()
	if _, err := ipsec.NewSettingsStore(p).Configure(ctx, other, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDisabled(ctx, other, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("wrong org ownership=%v", err)
	}
	check()
}

func TestCreateDisabledSecondSecretFailureAndDuplicateConcurrency(t *testing.T) {
	ctx, p, org, actor, sealer, req := createFixture(t)
	s := ipsec.NewConnectionStore(p)
	if _, err := p.Exec(ctx, `CREATE FUNCTION reject_second_ipsec_secret() RETURNS trigger AS $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_tunnels WHERE id=NEW.tunnel_id AND slot=2) THEN RAISE EXCEPTION 'synthetic second-secret failure'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_second_ipsec_secret BEFORE INSERT ON ipsec_tunnel_secrets FOR EACH ROW EXECUTE FUNCTION reject_second_ipsec_secret()`); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := p.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, req); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("second secret failure=%v", err)
	}
	var residue int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)+(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created'),updated_at FROM organizations WHERE id=$1`, org).Scan(&residue, &after); err != nil || residue != 0 || !before.Equal(after) {
		t.Fatalf("rollback residue=%d orgchanged=%t %v", residue, !before.Equal(after), err)
	}
	if _, err := p.Exec(ctx, `DROP TRIGGER reject_second_ipsec_secret ON ipsec_tunnel_secrets; DROP FUNCTION reject_second_ipsec_secret()`); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := s.CreateDisabled(ctx, org, actor, sealer, req); out <- err }()
	}
	close(start)
	wg.Wait()
	close(out)
	success, conflict := 0, 0
	for err := range out {
		if err == nil {
			success++
		} else if errors.Is(err, ipsec.ErrConnectionConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created'`, org).Scan(&residue); err != nil || residue != 1 {
		t.Fatalf("audits=%d %v", residue, err)
	}
}

// No test in this package runs in parallel. Replace only the local nonce reader
// during the synchronous call, then restore it before inspecting the database.
type failingCreateNonce struct {
	remaining int
	failed    bool
}

func (r *failingCreateNonce) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		r.failed = true
		return 0, errors.New("synthetic-secret-random-failure")
	}
	n := min(len(p), r.remaining)
	clear(p[:n])
	r.remaining -= n
	return n, nil
}
func TestCreateDisabledEncryptionFailureRollback(t *testing.T) {
	ctx, p, org, actor, sealer, req := createFixture(t)
	reader := &failingCreateNonce{remaining: 12}
	var result ipsec.Connection
	var err error
	func() {
		previous := cryptorand.Reader
		cryptorand.Reader = reader
		defer func() { cryptorand.Reader = previous }()
		result, err = ipsec.NewConnectionStore(p).CreateDisabled(ctx, org, actor, sealer, req)
	}()
	if !reader.failed || !errors.Is(err, ipsec.ErrConnectionUnavailable) || result.ID != uuid.Nil {
		t.Fatalf("encryption failure result=%+v err=%v", result, err)
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("encryption error exposed marker")
	}
	var residue int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1)+(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&residue); err != nil || residue != 0 {
		t.Fatalf("encryption rollback residue=%d %v", residue, err)
	}
}

func TestCreateDisabledExistingSecondTunnelCollisionRollsBack(t *testing.T) {
	ctx, p, org, actor, sealer, req := createFixture(t)
	s := ipsec.NewConnectionStore(p)
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, req); err != nil {
		t.Fatal(err)
	}
	collision := req
	collision.ID = uuid.New()
	collision.Tunnels[0].ID = uuid.New()
	// Slot two deliberately reuses an immutable ID owned by the first connection.
	if _, err := s.CreateDisabled(ctx, org, actor, sealer, collision); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("second tunnel collision=%v", err)
	}
	var connections, tunnels, secrets, audits int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1),(SELECT count(*) FROM ipsec_tunnels WHERE org_id=$1),(SELECT count(*) FROM ipsec_tunnel_secrets WHERE org_id=$1),(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&connections, &tunnels, &secrets, &audits); err != nil || connections != 1 || tunnels != 2 || secrets != 2 || audits != 1 {
		t.Fatalf("collision changed totals=%d/%d/%d/%d %v", connections, tunnels, secrets, audits, err)
	}
	var residue int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE id=$1)+(SELECT count(*) FROM ipsec_tunnels WHERE id=$2 OR connection_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE tunnel_id=$2 OR connection_id=$1)+(SELECT count(*) FROM audit_logs WHERE org_id=$3 AND target_id=$4)`, collision.ID, collision.Tunnels[0].ID, org, collision.ID.String()).Scan(&residue); err != nil || residue != 0 {
		t.Fatalf("collision residue=%d %v", residue, err)
	}
	for _, tun := range req.Tunnels {
		var sealed string
		if err := p.QueryRow(ctx, `SELECT sealed_psk FROM ipsec_tunnel_secrets WHERE tunnel_id=$1 AND connection_id=$2`, tun.ID, req.ID).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		plaintext, err := ipsec.OpenPSK(sealer, ipsec.PSKBinding{OrgID: org, ConnectionID: req.ID, TunnelID: tun.ID, Revision: 1}, sealed)
		if err != nil || plaintext != tun.PSK {
			t.Fatalf("collision altered original envelope: %v", err)
		}
	}
}
