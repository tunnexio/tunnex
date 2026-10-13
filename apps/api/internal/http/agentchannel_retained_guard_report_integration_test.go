package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// The actual authenticated report handler persists bounded capability evidence.
// Fixtures use certificate listener state; no TLS handshake or native traffic is claimed.
func TestAgentRetainedGuardReportGatesRecreationWithoutLegacyStarvation(t *testing.T) {
	ctx, p := testpostgres.NewAtVersion(t, 220)
	org, actor, site, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(gateway[:])
	certSerial := hex.EncodeToString(serial.Bytes())
	for _, step := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'Retained report',$2,'10.99.0.0/24')`, []any{org, "retained-report-" + org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@retained-report.test"}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'owned site')`, []any{site, org}},
		{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{uuid.New(), site}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,cert_delivered) VALUES($1,$2,'reporter',$3,$4,true)`, []any{gateway, org, certSerial, site}},
	} {
		if _, e := p.Exec(ctx, step.q, step.a...); e != nil {
			t.Fatal(e)
		}
	}
	channel := NewAgentChannel(nodes.NewService(p, nil, nil), nil, nil, nil)
	report := func(fields string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="`+fields+`}`)).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
		rr := httptest.NewRecorder()
		channel.report(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("report %d %s", rr.Code, rr.Body.String())
		}
		var raw []byte
		if e := p.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, gateway).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		if nodes.Capabilities(raw).IPsecRetainedGuardVersion != want {
			t.Fatalf("actual report persisted %s", raw)
		}
	}
	const supported = `,"ipsec_config_version":1,"ipsec_retained_guard_version":1`
	report(supported, 1)
	sealer, e := crypto.NewSealer(bytes.Repeat([]byte{0x69}, 32))
	if e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), Grants: []ipsec.RuntimeGrant{{Source: in.Config.LocalPrefixes[0], Destination: in.Config.RemotePrefixes[0], Protocol: "any", RuleID: "fixture"}}}, nil
	})
	if _, e = ipsec.NewSettingsStore(p).Configure(ctx, org, actor, true, 0); e != nil {
		t.Fatal(e)
	}
	var input api.IPsecConfigurationCheckInput
	if e = json.Unmarshal([]byte(configurationCheckFixture), &input); e != nil {
		t.Fatal(e)
	}
	cfg, e := privateIPsecConfiguration(input)
	if e != nil {
		t.Fatal(e)
	}
	fresh := func(config ipsec.StaticConfig) ipsec.CreateProviderRequest {
		return ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: site, GatewayID: gateway, Name: "report recreation", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: config}
	}
	create := func(config ipsec.StaticConfig) ipsec.Connection {
		t.Helper()
		c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, fresh(config))
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	enable := func(c ipsec.Connection) ipsec.Connection {
		t.Helper()
		c, e := store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: gateway, CertificateSerial: certSerial}
	material := func(c ipsec.Connection) ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	old := enable(create(cfg))
	_ = material(old)
	old, e = store.Delete(ctx, org, actor, old.ID, old.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	cleanup, e := store.Cleanup(ctx, principal, old.ID, old.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Acknowledge(ctx, principal, old.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
		t.Fatal(e)
	}
	// A separate ordinary tunnel remains renewable while successor support changes.
	legacyCfg := cfg
	legacyCfg.RemotePrefixes = []string{"10.21.0.0/16"}
	legacyCfg.Tunnels = append([]ipsec.StaticTunnel(nil), cfg.Tunnels...)
	legacyCfg.Tunnels[0].OutsideAddress = "8.8.4.4"
	legacyCfg.Tunnels[0].InsideCIDR = "169.254.12.0/30"
	legacyCfg.Tunnels[0].CustomerInsideAddress = "169.254.12.2"
	legacyCfg.Tunnels[0].CloudInsideAddress = "169.254.12.1"
	legacyCfg.Tunnels[1].OutsideAddress = "1.0.0.1"
	legacyCfg.Tunnels[1].InsideCIDR = "169.254.12.4/30"
	legacyCfg.Tunnels[1].CustomerInsideAddress = "169.254.12.6"
	legacyCfg.Tunnels[1].CloudInsideAddress = "169.254.12.5"
	legacy := enable(create(legacyCfg))
	legacyMaterial := material(legacy)
	successor := create(cfg)
	for _, tc := range []struct {
		name, fields string
		legacyWorks  bool
	}{
		{"omitted", `,"ipsec_config_version":1`, true}, {"unknown", `,"ipsec_config_version":1,"ipsec_retained_guard_version":2`, true}, {"negative", `,"ipsec_config_version":1,"ipsec_retained_guard_version":-1`, true}, {"no IPsec", `,"ipsec_retained_guard_version":1`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report(tc.fields, 0)
			if _, e := store.CreateProviderDisabled(ctx, org, actor, sealer, fresh(cfg)); !errors.Is(e, ipsec.ErrConnectionConflict) && !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("unsupported recreation %v", e)
			}
			if _, e := store.SetIntent(ctx, org, actor, successor.ID, 1, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
				t.Fatalf("unsupported Enable %v", e)
			}
			if _, e := p.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, successor.ID); e == nil {
				t.Fatal("SQL bypassed unsupported Enable")
			}
			if tc.legacyWorks {
				if _, e := store.PermitLease(ctx, principal, legacy.ID, ipsec.RuntimeLeaseRequest{DeliveryID: legacyMaterial.ID, DesiredRevision: legacy.DesiredRevision, PolicyHash: legacyMaterial.Policy.Hash, Nonce: strings.Repeat("c", 64)}); e != nil {
					t.Fatal("unrelated legacy lease starved", e)
				}
			}
		})
	}
	report(supported, 1)
	successor = enable(successor)
	successorMaterial := material(successor)
	report(`,"ipsec_config_version":1`, 0)
	page, e := store.Pending(ctx, principal, nil, 100)
	if e != nil {
		t.Fatal(e)
	}
	foundLegacy := false
	for _, item := range page.Items {
		if item.ConnectionID == successor.ID {
			t.Fatal("unsupported successor exposed to old batch decoder")
		}
		if item.ConnectionID == legacy.ID {
			foundLegacy = true
		}
	}
	if !foundLegacy {
		t.Fatal("legacy pending delivery starved")
	}
	if _, e = store.Material(ctx, principal, successor.ID, successor.DesiredRevision, sealer); !errors.Is(e, ipsec.ErrConnectionIneligible) {
		t.Fatal("unsupported successor Material accepted", e)
	}
	if _, e = store.PermitLease(ctx, principal, successor.ID, ipsec.RuntimeLeaseRequest{DeliveryID: successorMaterial.ID, DesiredRevision: successor.DesiredRevision, PolicyHash: successorMaterial.Policy.Hash, Nonce: strings.Repeat("d", 64)}); !errors.Is(e, ipsec.ErrConnectionIneligible) {
		t.Fatal("unsupported successor lease accepted", e)
	}
	if _, e = store.PermitLease(ctx, principal, legacy.ID, ipsec.RuntimeLeaseRequest{DeliveryID: legacyMaterial.ID, DesiredRevision: legacy.DesiredRevision, PolicyHash: legacyMaterial.Policy.Hash, Nonce: strings.Repeat("e", 64)}); e != nil {
		t.Fatal("legacy lease starved", e)
	}
	report(supported, 1)
	page, e = store.Pending(ctx, principal, nil, 100)
	if e != nil {
		t.Fatal(e)
	}
	foundSuccessor := false
	for _, item := range page.Items {
		if item.ConnectionID == successor.ID {
			foundSuccessor = true
		}
	}
	if !foundSuccessor {
		t.Fatal("reported support failed to recover successor queue")
	}
}
