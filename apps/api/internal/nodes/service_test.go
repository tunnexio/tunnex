package nodes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

func TestWarmWireGuardCandidateNeverDuplicatesAllowedIPs(t *testing.T) {
	currentKey := "kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE="
	candidateKey := "WlEiCXJIkuDu09Ji0dvI1RwdkbLwkZ+qdR/M0r6/I94="
	peers := []Peer{{PublicKey: currentKey, AllowedIPs: []string{"10.99.0.7/32"}}}
	peers = appendWarmWireGuardCandidates(peers, map[string]struct{}{currentKey: {}}, []sqlc.ListPreparedAgentWireGuardPeersForNodeRow{{CandidatePublicKey: &candidateKey}})
	if len(peers) != 2 || len(peers[0].AllowedIPs) != 1 || len(peers[1].AllowedIPs) != 0 {
		t.Fatalf("warm stage duplicated crypto routes: %#v", peers)
	}
	peers = appendWarmWireGuardCandidates(peers, map[string]struct{}{currentKey: {}, candidateKey: {}}, []sqlc.ListPreparedAgentWireGuardPeersForNodeRow{{CandidatePublicKey: &candidateKey}})
	if len(peers) != 2 {
		t.Fatalf("duplicate candidate peer appended: %#v", peers)
	}
}

func TestHubWideningRetainsWarmWireGuardCandidate(t *testing.T) {
	currentKey := "kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE="
	candidateKey := "WlEiCXJIkuDu09Ji0dvI1RwdkbLwkZ+qdR/M0r6/I94="
	widened := []Peer{{PublicKey: currentKey, AllowedIPs: []string{"10.99.0.7/32"}}}
	peers := widenedPeersWithWarmCandidates(widened, []sqlc.ListPreparedAgentWireGuardPeersForNodeRow{{CandidatePublicKey: &candidateKey}})
	if len(peers) != 2 || peers[1].PublicKey != candidateKey || len(peers[1].AllowedIPs) != 0 {
		t.Fatalf("hub widening erased or routed the warm candidate: %#v", peers)
	}
}

func genCSR(t *testing.T, cn string) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func serialOf(t *testing.T, ca *agentca.CA, certPEM string) string {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	// The cert must chain to the CA.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert does not verify against CA: %v", err)
	}
	return hex.EncodeToString(cert.SerialNumber.Bytes())
}

func code(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

func TestNodeEnrollmentLifecycle(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	// The CA is deployment-global. Keep this fixture transaction-scoped so a
	// ciphertext sealed with its throwaway key cannot poison later tests.
	if _, err := tx.Exec(ctx, "DELETE FROM platform_secrets WHERE name = 'agent_ca'"); err != nil {
		t.Fatalf("clear test CA: %v", err)
	}

	org, actor := uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "n-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actor, "a@t", "A"); err != nil {
		t.Fatalf("actor: %v", err)
	}
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)
	ca, _, err := agentca.LoadOrCreate(ctx, q, sealer)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	// ⛔ A LICENCE THAT PERMITS, BECAUSE THE CEILING IS NOW DEPLOYMENT-WIDE AND THIS TEST IS NOT ABOUT IT.
	//
	// A nil manager means Community — one gateway ACROSS THE WHOLE DEPLOYMENT — and this suite shares a
	// database with every other test that ever enrolled one. It passed only while the count was per-org,
	// which is the defect the founder found: the ceiling was 5 × however many organizations existed.
	//
	// ⚠ The ceiling has its own tests (gateway_ceiling_test.go); giving this one an unlimited band keeps
	// the enrolment lifecycle testing enrolment rather than accidentally re-testing the band.
	svc := (&Service{q: q, ca: ca, sealer: sealer}).WithLicence(
		licence.NewTestManager("scale", time.Now().Add(time.Hour)))

	// Issue a name-pinned token and enroll.
	raw, err := svc.IssueJoinToken(ctx, actor, org, "gw-1", "")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	res, err := svc.Enroll(ctx, raw, genCSR(t, "gw-1"), "gw-1", "0.1.0")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	serial := serialOf(t, ca, res.CertPEM) // also verifies cert chains to CA

	// Audit correlation (S4.8/F3): the node.token_issued and node.enrolled rows
	// carry the SAME keyed token fingerprint, and neither carries the raw token.
	wantFP := sealer.Fingerprint([]byte(raw))
	for _, action := range []string{"node.token_issued", "node.enrolled"} {
		var metadata []byte
		if err := tx.QueryRow(ctx,
			"SELECT metadata FROM audit_logs WHERE org_id=$1 AND action=$2 ORDER BY created_at DESC LIMIT 1",
			org, action).Scan(&metadata); err != nil {
			t.Fatalf("audit row %s: %v", action, err)
		}
		var meta map[string]any
		if err := json.Unmarshal(metadata, &meta); err != nil {
			t.Fatalf("audit metadata %s: %v", action, err)
		}
		if fp, _ := meta["token_fingerprint"].(string); fp != wantFP {
			t.Fatalf("%s token_fingerprint: want %q, got %q (meta=%v)", action, wantFP, fp, meta)
		}
		if strings.Contains(string(metadata), raw) {
			t.Fatalf("%s metadata leaks the raw token", action)
		}
	}

	// Cert identity resolves to the node.
	node, err := svc.AuthenticateCert(ctx, serial)
	if err != nil || node.Name != "gw-1" {
		t.Fatalf("authenticate: node=%+v err=%v", node, err)
	}

	// Token is single-use.
	if _, err := svc.Enroll(ctx, raw, genCSR(t, "gw-1"), "gw-1", "0.1.0"); code(err) != "invalid_join_token" {
		t.Fatalf("token reuse: want invalid_join_token, got %v", err)
	}

	// Renewal of an active node issues a fresh cert (new serial).
	renewed, err := svc.Renew(ctx, node, genCSR(t, "gw-1"), "0.2.0")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	newSerial := serialOf(t, ca, renewed)
	if newSerial == serial {
		t.Fatal("renewal did not rotate the serial")
	}
	node, err = svc.AuthenticateCert(ctx, newSerial)
	if err != nil {
		t.Fatalf("authenticate renewed: %v", err)
	}

	// WG key reporting: a malformed key is rejected; a well-formed 32-byte base64
	// key is stored on the active node.
	if err := svc.ReportWGInfo(ctx, node, "not-a-key", "", false, false, AppliedPolicy{}); code(err) != "invalid_wg_key" {
		t.Fatalf("malformed key: want invalid_wg_key, got %v", err)
	}
	wgKeyBytes := make([]byte, 32)
	wgKeyBytes[0] = 1 // non-zero: an all-zero key is a degenerate point (rejected)
	wgKey := base64.StdEncoding.EncodeToString(wgKeyBytes)
	flowObservedAt := time.Now().UTC().Truncate(time.Microsecond)
	flowDeliveredAt := flowObservedAt.Add(time.Second)
	if err := svc.ReportWGInfo(ctx, node, wgKey, "1.2.3.4:51820", true, false, AppliedPolicy{DNSResolveRPCVersion: 1, FlowLogState: "active", FlowLogLastObservedAt: &flowObservedAt, FlowLogLastDeliveredAt: &flowDeliveredAt}); err != nil {
		t.Fatalf("report valid key: %v", err)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); stored.WgPublicKey != wgKey || stored.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("key/endpoint not persisted: %+v", stored)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); !Capabilities(stored.Capabilities).EgressNAT {
		t.Fatalf("egress_nat capability not stored: %s", stored.Capabilities)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); !Capabilities(stored.Capabilities).SupportsDNSResolveRPC(1) || Capabilities(stored.Capabilities).SupportsDNSResolveRPC(2) {
		t.Fatalf("dns RPC compatibility capability must retain its reported version: %s", stored.Capabilities)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); Capabilities(stored.Capabilities).FlowLogState != "active" || Capabilities(stored.Capabilities).FlowLogLastObservedAt == nil || Capabilities(stored.Capabilities).FlowLogLastDeliveredAt == nil {
		t.Fatalf("flow-log collector heartbeat must retain its bounded state and evidence times: %s", stored.Capabilities)
	}
	// A malformed endpoint (newline injection) is rejected.
	if err := svc.ReportWGInfo(ctx, node, wgKey, "1.2.3.4:51820\nInject = x", false, false, AppliedPolicy{}); code(err) != "invalid_endpoint" {
		t.Fatalf("injection endpoint: want invalid_endpoint, got %v", err)
	}
	// An empty endpoint report does NOT clobber the previously-stored good value.
	if err := svc.ReportWGInfo(ctx, node, wgKey, "", true, false, AppliedPolicy{}); err != nil {
		t.Fatalf("empty-endpoint report: %v", err)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); stored.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("empty report clobbered endpoint: got %q", stored.Endpoint)
	}
	if stored, _ := q.GetNodeByCertSerial(ctx, newSerial); Capabilities(stored.Capabilities).FlowLogState != "unknown" {
		t.Fatalf("missing or invalid collector state must fail closed to unknown: %s", stored.Capabilities)
	}

	// Revoke -> cert auth fails AND renewal is refused (the revocation mechanism).
	if err := svc.Revoke(ctx, actor, org, node.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.AuthenticateCert(ctx, newSerial); code(err) != "agent_revoked" {
		t.Fatalf("authenticate revoked: want agent_revoked, got %v", err)
	}
	revoked, _ := q.GetNodeByCertSerial(ctx, newSerial)
	if _, err := svc.Renew(ctx, revoked, genCSR(t, "gw-1"), "0.3.0"); code(err) != "agent_revoked" {
		t.Fatalf("renew revoked: want agent_revoked, got %v", err)
	}
	// Reporting a key for a revoked node is a zero-row update -> surfaced as a
	// conflict, not a silent 204/no-op.
	if err := svc.ReportWGInfo(ctx, revoked, wgKey, "1.2.3.4:51820", false, false, AppliedPolicy{}); code(err) != "node_not_active" {
		t.Fatalf("report on revoked: want node_not_active, got %v", err)
	}

	// Versioned handshake.
	ds, err := svc.DesiredState(ctx, revoked)
	if err != nil || ds.ProtocolVersion != ProtocolVersion {
		t.Fatalf("desired-state version: %+v err=%v", ds, err)
	}
}

// TestDesiredStateOVPNRosterNotPeer (S9.1 Slice 4c) locks the roster channel + the WG-peer exclusion:
// on a gateway hosting BOTH a WireGuard device and an OpenVPN device, DesiredState.Peers carries the
// WG peer but NOT the OVPN device (it has no WG key), while DesiredState.OVPNClients carries the OVPN
// device's CN(=id)+/32 but NOT the WG device. The OVPN /32 reaches the agent through the roster (and,
// under enforcing, the compiled Policy) exactly as a WG device's does — B1's data half on the wire.
func TestDesiredStateOVPNRosterNotPeer(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)

	org, user, nodeID := uuid.New(), uuid.New(), uuid.New()
	mustExec := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("exec %q: %v", sql, e)
		}
	}
	mustExec("INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "n-"+org.String())
	mustExec("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", user, "u-"+user.String()+"@t")
	mustExec("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user)
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','gw.example.com:51820')",
		nodeID, org, "s-"+nodeID.String())
	// a WireGuard device (has a pubkey) + an OpenVPN device (no pubkey, transport openvpn).
	wgDev, ovDev := uuid.New(), uuid.New()
	mustExec("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,transport) VALUES ($1, $2, $3, $4, 'wg', 'bAT4o9cZhWwloteFz1RA+SbUVO/MaVA6+jF/B1+atfM=', '10.99.0.5', 'active', 'wireguard')",
		wgDev, org, user, nodeID)
	mustExec("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,transport) VALUES ($1, $2, $3, $4, 'ovpn', '', '10.99.0.6', 'active', 'openvpn')",
		ovDev, org, user, nodeID)

	node, err := q.GetNodeByCertSerial(ctx, "s-"+nodeID.String())
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	svc := &Service{q: q}
	ds, err := svc.DesiredState(ctx, node)
	if err != nil {
		t.Fatalf("DesiredState: %v", err)
	}

	// WG peer present, OVPN NOT a peer (no key).
	var wgPeer, ovPeer bool
	for _, p := range ds.Peers {
		if p.PublicKey == "bAT4o9cZhWwloteFz1RA+SbUVO/MaVA6+jF/B1+atfM=" {
			wgPeer = true
		}
		if p.PublicKey == "" {
			ovPeer = true
		}
	}
	if !wgPeer {
		t.Fatalf("the WG device must be a peer; peers=%+v", ds.Peers)
	}
	if ovPeer {
		t.Fatal("an OpenVPN device (no WG key) must NOT appear as a WireGuard peer")
	}
	// OVPN roster carries the OVPN device (CN=id, /32), NOT the WG device.
	if len(ds.OVPNClients) != 1 {
		t.Fatalf("roster must carry exactly the 1 OVPN device, got %+v", ds.OVPNClients)
	}
	c := ds.OVPNClients[0]
	if c.CommonName != ovDev.String() || c.IP != "10.99.0.6" {
		t.Fatalf("roster entry must be the OVPN device's id+/32; got %+v", c)
	}
}

// TestDesiredStateOVPNEnabledTracksOrgOptIn (S9.1 4d) locks two opt-in reds at the CP: org-OFF →
// DesiredState.OVPNEnabled false (the agent then idles → ZERO OVPN artifacts, the zero-config golden);
// and a disable→enable→disable round-trip flips it cleanly.
func TestDesiredStateOVPNEnabledTracksOrgOptIn(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	org, nodeID := uuid.New(), uuid.New()
	if _, e := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "n-"+org.String()); e != nil {
		t.Fatalf("org: %v", e)
	}
	if _, e := tx.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','gw:51820')", nodeID, org, "s-"+nodeID.String()); e != nil {
		t.Fatalf("node: %v", e)
	}
	node, _ := q.GetNodeByCertSerial(ctx, "s-"+nodeID.String())
	svc := &Service{q: q}

	// org OFF (default) → OVPNEnabled false → agent idles → zero artifacts.
	if ds, _ := svc.DesiredState(ctx, node); ds.OVPNEnabled {
		t.Fatal("org opt-in OFF must yield DesiredState.OVPNEnabled=false (zero OVPN artifacts)")
	}
	// enable → true.
	if _, e := q.SetOrgOVPNEnabled(ctx, sqlc.SetOrgOVPNEnabledParams{ID: org, OvpnEnabled: true}); e != nil {
		t.Fatalf("enable: %v", e)
	}
	if ds, _ := svc.DesiredState(ctx, node); !ds.OVPNEnabled {
		t.Fatal("org opt-in ON must yield OVPNEnabled=true")
	}
	// disable → false again (round-trip clean).
	if _, e := q.SetOrgOVPNEnabled(ctx, sqlc.SetOrgOVPNEnabledParams{ID: org, OvpnEnabled: false}); e != nil {
		t.Fatalf("disable: %v", e)
	}
	if ds, _ := svc.DesiredState(ctx, node); ds.OVPNEnabled {
		t.Fatal("disable must return OVPNEnabled=false (round-trip)")
	}
}
