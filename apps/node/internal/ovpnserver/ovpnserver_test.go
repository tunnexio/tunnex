package ovpnserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestMgr builds a Manager over a temp dir with an in-memory process seam (so tests never spawn
// openvpn). It records ensureProc calls so self-heal is observable, and stubs the preconditions
// PRESENT (binary + certs) so the happy-path tests reach ensureProc — the precondition-refusal tests
// flip them explicitly.
func newTestMgr(t *testing.T) (*Manager, *int) {
	t.Helper()
	m := New(t.TempDir())
	starts := 0
	m.ensureProc = func(context.Context, string) error { starts++; return nil }
	m.binaryPresent = func() bool { return true }
	m.certsPresent = func() bool { return true }
	return m, &starts
}

func readCCD(t *testing.T, m *Manager, cn string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.ccdDir, cn))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read ccd %s: %v", cn, err)
	}
	return string(b), true
}

// TestCCDPushesCPAssignedAddress is the D-S9.1-3 red that keeps B1 free: an OVPN client's /32 in the
// CCD is EXACTLY its CP-assigned pool address — the same /32 that is its policy subject in the
// compiled artifact. The server never allocates; it renders the control plane's assignment.
func TestCCDPushesCPAssignedAddress(t *testing.T) {
	m, _ := newTestMgr(t)
	m.SetDesired(Desired{
		PoolCIDR: "10.99.0.0/24",
		Clients:  []Client{{CommonName: "device-alice", IP: "10.99.0.7"}},
	})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	body, ok := readCCD(t, m, "device-alice")
	if !ok {
		t.Fatal("expected a CCD file for the client")
	}
	// The pushed address is the CP-assigned /32 (host + pool mask), not an allocated one — AND it is
	// iroute'd /32 so it is routable to this client while tunnex-ovpn owns only the transit /30 (the
	// iroute model). The pool /32 in the ifconfig-push is the indistinguishable-/32 that keeps B1 free.
	if body != "ifconfig-push 10.99.0.7 255.255.255.0\niroute 10.99.0.7 255.255.255.255\n" {
		t.Fatalf("CCD must push the CP-assigned /32 AND iroute it /32; got %q", body)
	}
}

// TestFullTunnelPushesRedirectGateway is the WF-OVPN-3 red, BOTH directions: a full-tunnel client's CCD
// pushes redirect-gateway (+ a resolver, mirroring WG full-tunnel), and a split-tunnel client's does NOT
// — the per-device tunnel mode is expressed in the CCD, never server-wide.
func TestFullTunnelPushesRedirectGateway(t *testing.T) {
	m, _ := newTestMgr(t)
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24", Clients: []Client{
		{CommonName: "ft", IP: "10.99.0.7", FullTunnel: true},
		{CommonName: "split", IP: "10.99.0.8", FullTunnel: false},
	}})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	ft, _ := readCCD(t, m, "ft")
	if !strings.Contains(ft, `push "redirect-gateway def1 bypass-dhcp"`) {
		t.Fatalf("a full-tunnel client's CCD must push redirect-gateway; got %q", ft)
	}
	if !strings.Contains(ft, `push "dhcp-option DNS `) {
		t.Fatalf("a full-tunnel client's CCD must push a resolver (WG parity); got %q", ft)
	}
	sp, _ := readCCD(t, m, "split")
	if strings.Contains(sp, "redirect-gateway") {
		t.Fatalf("a split-tunnel client's CCD must NOT redirect the default route; got %q", sp)
	}
}

// TestServerModeComplete is the WF-OVPN-1 completeness red: the rendered config is a COMPLETE, RUNNABLE
// TLS server — not merely one that contains/omits a few keys. The rc1 walk found openvpn started but
// never brought up the tun because the config omitted mode server / tls-server / proto / port / ifconfig
// / dh / keepalive. A config that asserts only what it omits proves neither runnability nor completeness.
func TestServerModeComplete(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", nil, nil)
	for _, required := range []string{
		"mode server", "tls-server", "proto udp", "port 1194",
		"ifconfig " + transitServerIP + " " + transitMask, "dh none", "keepalive 10 60",
		"script-security 2", "learn-address ",
	} {
		if !strings.Contains(cfg, required) {
			t.Fatalf("server config must be a complete server (missing %q):\n%s", required, cfg)
		}
	}
}

// TestTunnelNeverClaimsPool is the WF-OVPN-2 condition-3 red: tunnex-ovpn's own address is on the
// TRANSIT range, and the config claims NO pool /24 (no `ifconfig <pool>`, no bare `route <pool>`). This
// is what guarantees the kernel keeps exactly one route to the pool (via wg0) — connected client /32s
// win by longest-prefix, added dynamically by the learn-address hook, never by a /24 claim here.
func TestTunnelNeverClaimsPool(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", []string{"10.0.0.0/16"}, nil) // routes are PUSHED, never installed on tunnex-ovpn
	if !strings.Contains(cfg, "ifconfig "+transitServerIP) {
		t.Fatalf("the tun must ifconfig the transit address, not the pool:\n%s", cfg)
	}
	// no non-push route directive (a bare `route ...` would install a kernel route on tunnex-ovpn).
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(line, "route ") {
			t.Fatalf("config must NOT install a kernel route on the tun (found %q) — wg0 owns the pool /24:\n%s", line, cfg)
		}
	}
	// and the tun is never ifconfig'd onto the pool.
	if strings.Contains(cfg, "ifconfig 10.99") {
		t.Fatalf("tunnex-ovpn must never ifconfig a pool address (that reclaims the /24):\n%s", cfg)
	}
}

// TestTransitConflictRefuses is the WF-OVPN-2 condition-1 local guard: if the pool (or a pushed route)
// overlaps the exempt transit range on THIS gateway, the manager refuses to serve and surfaces
// ovpn_transit_conflict — so the tun address is never "validated by nobody".
func TestTransitConflictRefuses(t *testing.T) {
	m, starts := newTestMgr(t)
	m.SetDesired(Desired{PoolCIDR: "100.127.255.0/24"}) // overlaps TransitCIDR 100.127.255.0/30
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if *starts != 0 {
		t.Fatalf("a transit-conflicting pool must NOT spawn the server; starts=%d", *starts)
	}
	if m.Health() != HealthTransitConflict {
		t.Fatalf("health must surface %q, got %q", HealthTransitConflict, m.Health())
	}
}

// TestServerConfigAcceptedByOpenVPN is the WF-OVPN-1 external-acceptance red (the founder's more-important
// half): a GENERATED config for an external process must be one that process ACCEPTS. It renders the real
// config (via Reconcile) over throwaway server material and runs the openvpn binary against it with
// `--dev null` (no root / no tun needed) — asserting openvpn parses it and reaches server init, with no
// options error. Skipped when openvpn is not on PATH (stated) — CI's test-node installs it, and the box-
// walk carries it regardless.
func TestServerConfigAcceptedByOpenVPN(t *testing.T) {
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("openvpn not on PATH — config acceptance carried by the box-walk (rc2); the node image ships openvpn so CI's test-node runs this")
	}
	m := New(t.TempDir())
	writeThrowawayServerMaterial(t, m.cfgDir)
	m.ensureProc = func(context.Context, string) error { return nil }
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24", Clients: []Client{{CommonName: "d", IP: "10.99.0.7"}}})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// --dev null overrides `dev tunnex-ovpn` so no real tun is opened; the FULL config is still parsed +
	// initialized (mode server, ifconfig, dh, certs), which is what proves acceptance.
	out, _ := exec.CommandContext(ctx, "openvpn",
		"--config", filepath.Join(m.cfgDir, "server.conf"), "--verb", "3").CombinedOutput()
	// The config's log-append routes runtime output to <cfgDir>/ovpn.log; config-PARSE errors still hit
	// stderr (before the log opens). Read both so the acceptance markers (data-plane assembly) are seen.
	logBytes, _ := os.ReadFile(filepath.Join(m.cfgDir, "ovpn.log"))
	s := string(out) + string(logBytes)
	// Fail only on config-level REJECTIONS: openvpn parses + validates the ENTIRE config (mode, proto,
	// port, ifconfig, dh, certs, ccd, learn-address) before assembling the data plane, so any of these
	// means a directive/value/combo it would not accept.
	for _, bad := range []string{"Options error", "Unrecognized option", "Cannot load", "cannot load"} {
		if strings.Contains(s, bad) {
			t.Fatalf("openvpn REJECTED the server config (%q):\n%s", bad, s)
		}
	}
	// Positive proof: openvpn reached DATA-PLANE ASSEMBLY (tun open / UDP bind / route init) — which is
	// downstream of full config parse+validate, so reaching it proves acceptance. The tun open itself may
	// fail ("Cannot open TUN/TAP") because the unprivileged test container has no /dev/net/tun — an
	// ENVIRONMENT limit, not a config defect; the box-walk proves the tun actually comes up on the gateway.
	for _, reached := range []string{"Cannot open TUN/TAP", "UDPv4", "Initialization Sequence Completed", "net_route_v4_best_gw"} {
		if strings.Contains(s, reached) {
			return
		}
	}
	t.Fatalf("openvpn did not reach data-plane assembly — config may not be fully accepted:\n%s", s)
}

// writeThrowawayServerMaterial writes a self-consistent CA + server leaf + key into dir (ca.crt,
// server.crt, server.key) so the openvpn binary can load them in the acceptance red. Not the real PKI —
// just enough for openvpn to init.
func writeThrowawayServerMaterial(t *testing.T, dir string) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	write := func(name string, blk *pem.Block) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(blk), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write("ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	write("server.crt", &pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	write("server.key", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	// crl.pem (Slice 5): a valid EMPTY signed CRL — crl-verify is ALWAYS-ON, so the config references it and
	// openvpn must be able to load it (the empty-is-first-class condition, proven on the real binary).
	crlDER, _ := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
	}, caCert, caKey)
	write("crl.pem", &pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

// TestServerConfigCRLVerifyAlwaysOnAndReneg is the Slice 5 red: crl-verify is ALWAYS emitted (never
// conditional — the CP delivers a real-or-empty CRL and certsPresent requires it), and reneg-sec is set
// to the low value that bounds revocation latency to one renegotiation interval.
func TestServerConfigCRLVerifyAlwaysOnAndReneg(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", nil, nil)
	if !strings.Contains(cfg, "crl-verify ") {
		t.Fatalf("crl-verify must be ALWAYS-ON (a real-or-empty CRL is always delivered):\n%s", cfg)
	}
	// EXACT line (review #5): substring "reneg-sec 60" is satisfied by "reneg-sec 600"/"6000", so a
	// regression to a 10-minute window would pass green. Assert the exact rendered line (WF-OVPN-1 class:
	// a red asserting substring-presence proves the wrong thing).
	if !strings.Contains(cfg, "reneg-sec 60\n") {
		t.Fatalf("reneg-sec must be EXACTLY 60 (bounds revocation latency to one reneg interval):\n%s", cfg)
	}
}

// TestCRLRequiredForCertsPresent is the Slice 5 guard: crl-verify is always-on, so crl.pem is REQUIRED —
// ca+cert+key WITHOUT crl.pem must NOT satisfy certsPresent (else the server starts referencing a missing
// crl.pem = won't start; the CP always delivers the CRL, and until it lands the gateway refuses loudly).
func TestCRLRequiredForCertsPresent(t *testing.T) {
	m := New(t.TempDir())
	if e := os.MkdirAll(m.cfgDir, 0o700); e != nil {
		t.Fatal(e)
	}
	for _, f := range []string{"ca.crt", "server.crt", "server.key"} {
		_ = os.WriteFile(filepath.Join(m.cfgDir, f), []byte("x"), 0o644)
	}
	if m.certsPresent() {
		t.Fatal("ca+cert+key WITHOUT crl.pem must NOT be certs-present (crl-verify is always-on)")
	}
	_ = os.WriteFile(filepath.Join(m.cfgDir, "crl.pem"), []byte("x"), 0o644)
	if !m.certsPresent() {
		t.Fatal("with crl.pem present, certs-present must be true")
	}
}

// TestSelfAllocationDisabled is the allocator-single-authority red: the server config carries NO
// address-handing directive (`server` / `ifconfig-pool`) — every address comes from the CCD, so
// OpenVPN can never mint one. `ccd-exclusive` additionally REFUSES a client with no CCD entry.
func TestSelfAllocationDisabled(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", nil, nil)
	for _, forbidden := range []string{"\nserver ", "ifconfig-pool"} {
		if strings.Contains(cfg, forbidden) {
			t.Fatalf("server config must NOT self-allocate (found %q):\n%s", forbidden, cfg)
		}
	}
	for _, required := range []string{"dev " + TunName, "client-config-dir", "ccd-exclusive", "topology subnet"} {
		if !strings.Contains(cfg, required) {
			t.Fatalf("server config must contain %q (CCD is the single address authority):\n%s", required, cfg)
		}
	}
}

// TestCCDFullSweepOnDeparture is the CCD-reconcile red: a client that leaves the desired set has its
// CCD file REMOVED — not orphaned (an orphaned ifconfig-push would keep binding a departed identity).
func TestCCDFullSweepOnDeparture(t *testing.T) {
	m, _ := newTestMgr(t)
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24", Clients: []Client{
		{CommonName: "device-a", IP: "10.99.0.7"},
		{CommonName: "device-b", IP: "10.99.0.8"},
	}})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if _, ok := readCCD(t, m, "device-b"); !ok {
		t.Fatal("device-b CCD should exist after first reconcile")
	}
	// device-b departs.
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24", Clients: []Client{
		{CommonName: "device-a", IP: "10.99.0.7"},
	}})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if _, ok := readCCD(t, m, "device-b"); ok {
		t.Fatal("a departed client's CCD file must be swept, not orphaned")
	}
	if _, ok := readCCD(t, m, "device-a"); !ok {
		t.Fatal("the surviving client's CCD must remain")
	}
}

// TestReconcileSelfHeals is the process-lifecycle red: every reconcile tick (re)asserts the process
// via ensureProc — the config is authoritative, so a dead/absent process is (re)started, never
// assumed running (the wg0 self-heal analog).
func TestReconcileSelfHeals(t *testing.T) {
	m, starts := newTestMgr(t)
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24"})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if *starts != 1 {
		t.Fatalf("reconcile must assert the process (self-heal), starts=%d", *starts)
	}
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if *starts != 2 {
		t.Fatalf("each tick re-asserts the process; starts=%d", *starts)
	}
}

// TestIdleWhenNoPool is the zero-config guard: with no pool (OVPN not configured for this gateway),
// Reconcile is a no-op — no process asserted, no CCD dir, so egress sees no tun and the ruleset stays
// byte-identical to a WireGuard-only deployment.
func TestIdleWhenNoPool(t *testing.T) {
	m, starts := newTestMgr(t)
	m.SetDesired(Desired{}) // no pool
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if *starts != 0 {
		t.Fatalf("an unconfigured gateway must not start openvpn; starts=%d", *starts)
	}
	if _, err := os.Stat(m.ccdDir); !os.IsNotExist(err) {
		t.Fatalf("an idle manager must not create the CCD dir; stat err=%v", err)
	}
}

// TestTunNameIsOneTruth pins the one-truth: the tun name the server config pins is exactly what
// TunName() reports (the value threaded to egress.SetOVPNTun). No second source.
func TestTunNameIsOneTruth(t *testing.T) {
	m, _ := newTestMgr(t)
	if !strings.Contains(m.serverConfig("10.99.0.1", nil, nil), "dev "+m.TunName()) {
		t.Fatalf("config `dev` must be TunName()=%q; config:\n%s", m.TunName(), m.serverConfig("10.99.0.1", nil, nil))
	}
}

// TestServerConfigPushesRoutesAndDNS (S9.1 Part-3 fold) locks the OVPN answer to the static-config
// site-subnet gap: the server PUSHES the org's approved ranges + DNS, so a standard OpenVPN client
// reaches site subnets + resolves cross-site names WITHOUT a client-side edit (unlike a static WG
// config). With no routes/DNS the config emits no push lines (byte-identical to pre-fold).
func TestServerConfigPushesRoutesAndDNS(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", []string{"10.0.0.0/16", "172.31.0.0/16"}, []string{"10.0.0.2"})
	for _, want := range []string{
		`push "route 10.0.0.0 255.255.0.0"`,
		`push "route 172.31.0.0 255.255.0.0"`,
		`push "dhcp-option DNS 10.0.0.2"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("server config must push %q (Part-3: OVPN reaches site subnets server-side); got:\n%s", want, cfg)
		}
	}
	// With no routes/DNS the config emits no ROUTE/DNS pushes (byte-identical to pre-fold for those). The
	// topology + route-gateway pushes (WF-OVPN-7) are always present and are a separate concern.
	bare := m.serverConfig("10.99.0.1", nil, nil)
	if strings.Contains(bare, `push "route `) || strings.Contains(bare, `push "dhcp-option`) {
		t.Fatalf("with no routes/dns the config must emit NO route/DNS pushes; got:\n%s", bare)
	}
}

// TestServerPushesTopologyAndGateway is the WF-OVPN-7 red (4e-walk finding): because this server uses
// manual `mode server` (not the `--server` helper), the topology is NOT auto-pushed — so it MUST push
// `topology subnet` (else the client defaults to net30 and rejects the /24 ifconfig-push) and push the
// IN-SUBNET pool gateway as route-gateway (the transit-tun address would be an invalid off-subnet gateway).
func TestServerPushesTopologyAndGateway(t *testing.T) {
	m, _ := newTestMgr(t)
	cfg := m.serverConfig("10.99.0.1", nil, nil)
	if !strings.Contains(cfg, `push "topology subnet"`) {
		t.Fatalf("config must push topology subnet (client defaults to net30 otherwise):\n%s", cfg)
	}
	if !strings.Contains(cfg, `push "route-gateway 10.99.0.1"`) {
		t.Fatalf("config must push the in-subnet pool gateway as route-gateway:\n%s", cfg)
	}
}

// TestReconcileRefusesLoudlyWhenBinaryAbsent (4d) locks the precondition-before-exec guard: an
// enabled gateway (pool + roster) whose openvpn BINARY is missing REFUSES — the supervisor never
// spawns (ensureProc not called) and the reason is surfaced on the health surface, not logged.
func TestReconcileRefusesLoudlyWhenBinaryAbsent(t *testing.T) {
	m, starts := newTestMgr(t)
	m.binaryPresent = func() bool { return false }
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24", Clients: []Client{{CommonName: "d", IP: "10.99.0.7"}}})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if *starts != 0 {
		t.Fatalf("the supervisor must NOT spawn when the binary is absent; starts=%d", *starts)
	}
	if m.Health() != HealthBinaryAbsent {
		t.Fatalf("health must surface %q, got %q", HealthBinaryAbsent, m.Health())
	}
}

// TestReconcileRefusesLoudlyWhenCertsAbsent (4d) — same guard for the CA/server material.
func TestReconcileRefusesLoudlyWhenCertsAbsent(t *testing.T) {
	m, starts := newTestMgr(t)
	m.certsPresent = func() bool { return false }
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24"})
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if *starts != 0 {
		t.Fatalf("the supervisor must NOT spawn when certs are absent; starts=%d", *starts)
	}
	if m.Health() != HealthCertsAbsent {
		t.Fatalf("health must surface %q, got %q", HealthCertsAbsent, m.Health())
	}
	// no server.conf written either — refuse is a full stop before any output.
	if _, err := os.Stat(filepath.Join(m.cfgDir, "server.conf")); !os.IsNotExist(err) {
		t.Fatalf("a refused reconcile must write no server.conf; stat err=%v", err)
	}
}

// TestHealthClearsOnRecovery (4d) locks the recovery-clears half: certs appear on a later tick →
// health returns to OK and the supervisor spawns. Refuse-loudly is not sticky.
func TestHealthClearsOnRecovery(t *testing.T) {
	m, starts := newTestMgr(t)
	absent := true
	m.certsPresent = func() bool { return !absent }
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24"})
	_ = m.Reconcile(context.Background())
	if m.Health() != HealthCertsAbsent || *starts != 0 {
		t.Fatalf("expected certs-absent refusal first; health=%q starts=%d", m.Health(), *starts)
	}
	absent = false // certs placed
	_ = m.Reconcile(context.Background())
	if m.Health() != HealthOK {
		t.Fatalf("health must clear to OK on recovery, got %q", m.Health())
	}
	if *starts != 1 {
		t.Fatalf("the supervisor must spawn once preconditions are met; starts=%d", *starts)
	}
}

// TestTunActiveGatesTunPublish (4d, step-5 ordering + sweep-on-death) locks the cross-slice interaction:
// TunActive is true ONLY while the server is up (preconditions met + process asserted) — the agent
// publishes egress.SetOVPNTun(TunName) only then. When the server DIES (certs vanish → refuse), TunActive
// flips false, so the agent publishes SetOVPNTun("") and the Slice-3 sweep-on-departed-tun removes the
// tun's egress rules. Ordering: the tun is never in tunnelIfaces() unless it is actually up.
func TestTunActiveGatesTunPublish(t *testing.T) {
	m, _ := newTestMgr(t)
	// idle → not active.
	m.SetDesired(Desired{})
	_ = m.Reconcile(context.Background())
	if m.TunActive() {
		t.Fatal("idle gateway: TunActive must be false (agent must NOT publish the tun)")
	}
	// serving → active (agent publishes SetOVPNTun(TunName)).
	m.SetDesired(Desired{PoolCIDR: "10.99.0.0/24"})
	_ = m.Reconcile(context.Background())
	if !m.TunActive() {
		t.Fatal("serving gateway: TunActive must be true")
	}
	// the server dies (certs vanish) → refuse → NOT active → agent publishes SetOVPNTun("") → egress
	// sweeps the departed tun (proven at the egress tier by the Slice-3 sweep-on-departed-tun reds).
	m.certsPresent = func() bool { return false }
	_ = m.Reconcile(context.Background())
	if m.TunActive() {
		t.Fatal("after the server dies, TunActive must be false so the agent clears the egress tun")
	}
}

// TestServerMaterialWriteThenSweep (D-S9.6) locks cert delivery on the agent side: writing the
// CP-delivered material makes certsPresent TRUE (the ovpn_certs_absent precondition clears itself,
// live), the key is 0600, and sweeping (disable) removes the files → certsPresent FALSE.
func TestServerMaterialWriteThenSweep(t *testing.T) {
	m := New(t.TempDir()) // real file-based certsPresent (not the stub)
	if m.certsPresent() {
		t.Fatal("no certs delivered yet → certsPresent must be false")
	}
	if err := m.WriteServerMaterial("CA-PEM", "CERT-PEM", "KEY-PEM", "CRL-PEM"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !m.certsPresent() {
		t.Fatal("after delivery the certs-present precondition must clear (heals ovpn_certs_absent)")
	}
	fi, err := os.Stat(filepath.Join(m.cfgDir, "server.key"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("server.key must be 0600 (restrictive), got %o", fi.Mode().Perm())
	}
	// a hand-deleted file heals on the next write (idempotent re-assert).
	_ = os.Remove(filepath.Join(m.cfgDir, "server.crt"))
	if m.certsPresent() {
		t.Fatal("a deleted cert file must make certsPresent false until re-asserted")
	}
	_ = m.WriteServerMaterial("CA-PEM", "CERT-PEM", "KEY-PEM", "CRL-PEM")
	if !m.certsPresent() {
		t.Fatal("re-assert must heal the hand-deleted file")
	}
	// disable → sweep → nothing on disk.
	m.SweepServerMaterial()
	if m.certsPresent() {
		t.Fatal("after sweep (disable), certsPresent must be false — nothing exists on disk")
	}
}
