package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// This recorder verifies committed authority using a second database connection before any body byte.
type runtimeCommitRecorder struct {
	*httptest.ResponseRecorder
	before func()
	failed bool
}

func (w *runtimeCommitRecorder) Write(b []byte) (int, error) {
	if w.before != nil {
		f := w.before
		w.before = nil
		f()
	}
	if w.failed {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseRecorder.Write(b)
}
func TestAgentIPsecCommittedDeliveryBeforeBytes(t *testing.T) {
	testAgentIPsecCommittedDelivery(t, false)
}
func TestGCPClassicAgentIPsecStatusWire(t *testing.T) { testAgentIPsecCommittedDelivery(t, true) }
func TestAzureStandbyBGPAgentIPsecStatusWire(t *testing.T) {
	testAgentIPsecCommittedDelivery(t, false, true)
}
func testAgentIPsecCommittedDelivery(t *testing.T, classic bool, azure ...bool) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires guarded isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_runtime_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(c, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	u.Path = "/" + name
	if err := db.Up(u.String()); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor, site, gateway, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, s := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'provider HTTP',$2,'10.198.0.0/24')`, []any{org, org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@provider-http.test"}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'local')`, []any{site, org}},
		{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{uuid.New(), site}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, []any{gateway, org, "010203", site}},
	} {
		if _, err := pool.Exec(ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}

	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := ipsec.NewConnectionStore(pool)
	store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	if _, err = ipsec.NewSettingsStore(pool).Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	var input api.IPsecConfigurationCheckInput
	if err = json.Unmarshal([]byte(configurationCheckFixture), &input); err != nil {
		t.Fatal(err)
	}
	cfg, err := privateIPsecConfiguration(input)
	if err != nil {
		t.Fatal(err)
	}
	tunnelIDs := [2]uuid.UUID{uuid.New(), uuid.New()}
	count := 2
	if classic {
		count = 1
		cfg.ProfileID = ipsec.GCPClassicProfile
		cfg.Tunnels = cfg.Tunnels[:1]
		cfg.Tunnels[0].InsideCIDR = ""
		cfg.Tunnels[0].CustomerInsideAddress = ""
		cfg.Tunnels[0].CloudInsideAddress = ""
		tunnelIDs[1] = uuid.Nil
		if _, err = pool.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":1}'::jsonb WHERE id=$1`, gateway); err != nil {
			t.Fatal(err)
		}
	}
	azureBGP := len(azure) > 0 && azure[0]
	if azureBGP {
		count = 1
		cfg.ProfileID = ipsec.AzureActiveStandbyBGPProfile
		cfg.Mode = "ipv4-bgp"
		cfg.Azure = &ipsec.AzureContract{GatewaySKU: "VpnGw1AZ", VPNType: "RouteBased", IKEVersion: 2, CustomPolicy: "aes256-sha256-dh14-pfs2048"}
		cfg.BGP = &ipsec.BGPConfig{LocalASN: 64512, RemoteASN: 65515, RouterID: "10.10.0.1", MaximumPrefixes: 16}
		cfg.Tunnels = cfg.Tunnels[:1]
		cfg.Tunnels[0].InsideCIDR = "169.254.20.1/32"
		cfg.Tunnels[0].CustomerInsideAddress = "169.254.20.1"
		cfg.Tunnels[0].CloudInsideAddress = "169.254.21.2"
		tunnelIDs[1] = uuid.Nil
		channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
		req := httptest.NewRequest("POST", "/agent/report", strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","ipsec_config_version":1,"ipsec_bgp_version":1,"ipsec_azure_version":1}`)).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(0x010203)}}}
		rr := httptest.NewRecorder()
		channel.report(rr, req)
		if rr.Code != 204 {
			t.Fatal("Azure capability report rejected", rr.Code)
		}
	}
	c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, ipsec.CreateProviderRequest{ID: id, SiteID: site, GatewayID: gateway, Name: "runtime HTTP", TunnelIDs: tunnelIDs, Config: cfg})
	if err != nil {
		t.Fatal("create disabled provider", err)
	}
	c, err = store.SetIntent(ctx, org, actor, id, c.DesiredRevision, "enabled")
	if err != nil {
		t.Fatal("enable provider", err)
	}
	rule := uuid.New()
	if _, err = pool.Exec(ctx, `UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_site_id) VALUES($1,$2,'cidr','10.20.0.0/16','site',$3)`, rule, org, site); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	channel.SetIPsecRuntime(store, sealer)
	call := func(method, suffix, body string, w http.ResponseWriter) {
		t.Helper()
		r := httptest.NewRequest(method, "/agent/ipsec/connections/"+id.String()+suffix, strings.NewReader(body)).WithContext(ctx)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(0x010203)}}}
		channel.Handler().ServeHTTP(w, r)
	}
	marker := func() {
		t.Helper()
		var revision int64
		if e := pool.QueryRow(ctx, `SELECT last_potentially_delivered_revision FROM ipsec_runtime_state WHERE connection_id=$1`, id).Scan(&revision); e != nil || revision != c.DesiredRevision {
			t.Fatalf("material preceded commit: revision %d error %v", revision, e)
		}
	}
	raw, _ := json.Marshal(map[string]int64{"desired_revision": c.DesiredRevision})
	// Broken transport still leaves a durable cleanup obligation.
	failed := &runtimeCommitRecorder{ResponseRecorder: httptest.NewRecorder(), before: marker, failed: true}
	call("POST", "/material", string(raw), failed)
	if failed.before != nil {
		t.Fatalf("material not attempted: %d", failed.Code)
	}
	w := &runtimeCommitRecorder{ResponseRecorder: httptest.NewRecorder(), before: marker}
	call("POST", "/material", string(raw), w)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("material status %d", w.Code)
	}
	var material ipsec.RuntimeMaterial
	if e := json.Unmarshal(w.Body.Bytes(), &material); e != nil {
		t.Fatal(e)
	}
	if material.Secrets[0].PSK == "" || material.ID == uuid.Nil || material.Policy.Hash == "" {
		t.Fatal("incomplete material")
	}

	statusReport := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: material.DesiredRevision, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: material.Manifest.Tunnels[0].ID, Slot: 1, Status: "up", Selected: true}, {ID: material.Manifest.Tunnels[1].ID, Slot: 2, Status: "down"}}}
	if classic || azureBGP {
		version, count := 1, 1
		statusReport.TransportVersion = &version
		statusReport.TunnelCount = &count
		statusReport.Tunnels[1] = ipsec.RuntimeTunnelStatus{}
	}
	if azureBGP {
		statusReport.Tunnels[0].Selected = false
		statusReport.BGP = &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]ipsec.RuntimeBGPPeerStatus{{Slot: 1, State: "idle"}, {}}, Routes: []ipsec.RuntimeBGPRoute{}}
	}
	statusBytes, _ := json.Marshal(statusReport)
	statusReply := httptest.NewRecorder()
	call("POST", "/status", string(statusBytes), statusReply)
	if statusReply.Code != 204 || statusReply.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status report %d", statusReply.Code)
	}
	observed, e := store.ReadStatus(ctx, org, id)
	if e != nil || len(observed.Tunnels) != count || observed.ObservedAt == nil || observed.Tunnels[0].Status != "up" || (count == 2 && observed.Tunnels[1].Status != "down") {
		t.Fatal("status projection failed", e)
	}
	malformedStatus := strings.Replace(string(statusBytes), `"selected":false`, `"selected":false,"selected":true`, 1)
	deniedStatus := httptest.NewRecorder()
	call("POST", "/status", malformedStatus, deniedStatus)
	if deniedStatus.Code != 400 {
		t.Fatal("duplicate telemetry accepted")
	}
	missingSelected := strings.Replace(string(statusBytes), `,"selected":false`, "", 1)
	deniedStatus = httptest.NewRecorder()
	call("POST", "/status", missingSelected, deniedStatus)
	if deniedStatus.Code != 400 {
		t.Fatal("missing telemetry field accepted")
	}
	if classic {
		for _, mutate := range []func(*ipsec.RuntimeStatusReport){
			func(r *ipsec.RuntimeStatusReport) { r.TunnelCount = nil },
			func(r *ipsec.RuntimeStatusReport) { v := 2; r.TransportVersion = &v },
			func(r *ipsec.RuntimeStatusReport) { r.Tunnels[1].Status = "unknown" },
			func(r *ipsec.RuntimeStatusReport) { r.Tunnels[1].ID = uuid.New() },
		} {
			bad := statusReport
			mutate(&bad)
			raw, _ := json.Marshal(bad)
			reply := httptest.NewRecorder()
			call("POST", "/status", string(raw), reply)
			if reply.Code != 400 {
				t.Fatal("invalid Classic wire accepted", reply.Code)
			}
		}
	}
	if azureBGP {
		bad := statusReport
		clone := *bad.BGP
		bad.BGP = &clone
		bad.BGP.Peers[1].Slot = 2
		raw, _ := json.Marshal(bad)
		reply := httptest.NewRecorder()
		call("POST", "/status", string(raw), reply)
		if reply.Code != 400 {
			t.Fatal("nonzero inactive Azure peer accepted", reply.Code)
		}
		return
	}
	runtimeLeasePolicyRace(t, ctx, pool, store, org, gateway, id, rule, material)
	c, err = store.SetIntent(ctx, org, actor, id, c.DesiredRevision, "disabled")
	if err != nil {
		t.Fatal("disable provider", err)
	}
	if c.CleanupState != "pending" {
		t.Fatal("failed response lost cleanup obligation")
	}
	stale := httptest.NewRecorder()
	call("POST", "/material", string(raw), stale)
	if stale.Code != 409 {
		t.Fatalf("stale material status %d", stale.Code)
	}
	for _, secret := range material.Secrets {
		if secret.PSK != "" && (strings.Contains(logs.String(), secret.PSK) || strings.Contains(stale.Body.String(), secret.PSK)) {
			t.Fatal("secret logged or reflected")
		}
	}
}

// Observe an actual blocked policy writer while lease authority holds the same
// transaction lock. After the writer commits, the old hash cannot renew.
func runtimeLeasePolicyRace(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *ipsec.ConnectionStore, org, node, id, rule uuid.UUID, material ipsec.RuntimeMaterial) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	store.ConfigureRuntimePolicy(func(ctx context.Context, q *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		p, e := policy.CompileIPsecRuntimePolicy(ctx, q, in)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ipsec.RuntimePolicy{}, ctx.Err()
		}
		return p, e
	})
	defer store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: node, CertificateSerial: "010203"}
	request := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: material.DesiredRevision, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("a", 64)}
	leaseDone := make(chan error, 1)
	go func() { _, e := store.PermitLease(ctx, principal, id, request); leaseDone <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	conn, e := pool.Acquire(ctx)
	if e != nil {
		close(release)
		t.Fatal(e)
	}
	defer conn.Release()
	var pid int
	if e = conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
		close(release)
		t.Fatal(e)
	}
	writerDone := make(chan error, 1)
	go func() { _, e := conn.Exec(ctx, `DELETE FROM policy_rules WHERE id=$1`, rule); writerDone <- e }()
	deadline := time.Now().Add(5 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if e = pool.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); e != nil {
			break
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if e = <-leaseDone; e != nil {
		t.Fatal(e)
	}
	if e = <-writerDone; e != nil {
		t.Fatal(e)
	}
	if !blocked {
		t.Fatal("policy writer did not serialize with lease")
	}
	store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	if _, e = store.PermitLease(ctx, principal, id, request); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("revoked policy hash renewed: %v", e)
	}
}
