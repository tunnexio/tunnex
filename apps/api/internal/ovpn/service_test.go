package ovpn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
)

// TestGetCRLLazyInitsEmpty is the Slice 5c red (empty-is-first-class): an org that has NEVER revoked still
// gets a VALID, signed, EMPTY CRL from GetCRL — lazily generated once — so a gateway's crl-verify (always-on)
// never points at a missing file (the WF-OVPN-1 lesson).
func TestGetCRLLazyInitsEmpty(t *testing.T) {
	svc, ctx, orgID, _, _ := setup(t)
	pemStr, err := svc.GetCRL(ctx, orgID) // org has zero revocations
	if err != nil {
		t.Fatalf("get crl: %v", err)
	}
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		t.Fatal("GetCRL must return a valid CRL PEM, never empty (crl-verify is always-on)")
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("a never-revoked org's CRL must be EMPTY; got %d entries", len(crl.RevokedCertificateEntries))
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Fatal("even the empty CRL must carry a nextUpdate (never-expired discipline)")
	}
}

// TestRebuildCRLPutsRevokedSerialOnOrgCRL is the Slice 5b red: revoking a device's OVPN cert + RebuildCRL
// stores a signed org CRL carrying that serial, and the per-org CRL number is MONOTONIC across rebuilds.
func TestRebuildCRLPutsRevokedSerialOnOrgCRL(t *testing.T) {
	svc, ctx, orgID, deviceID, _ := setup(t)
	p, err := svc.Issue(ctx, orgID, deviceID, "cn")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.q.RevokeOVPNClientCertsForDevice(ctx, deviceID); err != nil {
		t.Fatalf("mark revoked: %v", err)
	}
	if err := svc.RebuildCRL(ctx, orgID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	row, err := svc.q.GetOVPNCRLForOrg(ctx, orgID)
	if err != nil {
		t.Fatalf("get crl: %v", err)
	}
	blk, _ := pem.Decode(row.CrlPem)
	if blk == nil {
		t.Fatal("stored CRL is not valid PEM")
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	sn := new(big.Int)
	b, _ := hex.DecodeString(p.Serial)
	sn.SetBytes(b)
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(sn) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("the revoked cert's serial must be on the org CRL")
	}

	// Monotonic per-org number: a second rebuild strictly increases it.
	n1 := row.Number
	if err := svc.RebuildCRL(ctx, orgID); err != nil {
		t.Fatalf("rebuild 2: %v", err)
	}
	row2, _ := svc.q.GetOVPNCRLForOrg(ctx, orgID)
	if row2.Number <= n1 {
		t.Fatalf("per-org CRL number must be monotonic; got %d then %d", n1, row2.Number)
	}
}

// setup opens a rolled-back tx against the test DB (skips when unset), plus a CA loaded through the
// real LoadOrCreate path — so this test also covers the DB storage round-trip (D-S9.1-1).
func setup(t *testing.T) (*Service, context.Context, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	q := sqlc.New(tx)

	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	// Lazy CA loader (D-S9.5-OPTIN(a)) — LoadOrCreate on first use.
	loadCA := func(ctx context.Context) (*ovpnca.CA, error) {
		c, _, e := ovpnca.LoadOrCreate(ctx, q, sealer)
		return c, e
	}

	// Minimal fixture: an org, a user, a node, a device to bind the cert to (FKs are enforced).
	orgID := mustOrg(t, ctx, q)
	userID := mustUser(t, ctx, q, orgID)
	nodeID := mustNode(t, ctx, q, orgID)
	deviceID := mustDevice(t, ctx, q, orgID, userID, nodeID)
	return NewService(q, loadCA, sealer), ctx, orgID, deviceID, userID
}

// TestIssueRecordsSerialNotKey is the B2 + D-S9.2-1 red: Issue persists the cert IDENTITY (serial,
// expiry, device binding) so the Slice 5 CRL sweep has its source — and the row carries NO private
// key column at all (the key is ephemeral, returned to the caller only).
func TestIssueRecordsSerialNotKey(t *testing.T) {
	svc, ctx, orgID, deviceID, _ := setup(t)

	p, err := svc.Issue(ctx, orgID, deviceID, "device-"+deviceID.String())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if p.PrivateKeyPEM == "" {
		t.Fatal("caller must receive the ephemeral private key for one-time delivery")
	}

	// The recorded cert identity is findable by the CRL source read, with the returned serial.
	active, err := svc.q.ListActiveOVPNClientCertsByOrg(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("want 1 recorded cert, got %d", len(active))
	}
	row := active[0]
	if row.Serial != p.Serial {
		t.Fatalf("recorded serial %q != issued %q", row.Serial, p.Serial)
	}
	if row.DeviceID != deviceID {
		t.Fatalf("recorded device %v != %v", row.DeviceID, deviceID)
	}
	if row.RevokedAt.Valid {
		t.Fatal("a freshly issued cert must not be revoked")
	}
	if !row.NotAfter.After(row.IssuedAt) {
		t.Fatal("not_after must be after issued_at (long-lived leaf)")
	}
}

// --- minimal FK fixtures (kept local so the test is self-contained) ---

func mustOrg(t *testing.T, ctx context.Context, q *sqlc.Queries) uuid.UUID {
	t.Helper()
	o, err := q.CreateOrganization(ctx, sqlc.CreateOrganizationParams{Name: "ovpn-test", Slug: "ovpn-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	return o.ID
}

func mustUser(t *testing.T, ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString()[:8] + "@ovpn.test", Name: "t"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	return u.ID
}

func mustNode(t *testing.T, ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	n, err := q.CreateNode(ctx, sqlc.CreateNodeParams{OrgID: orgID, Name: "gw-" + uuid.NewString()[:8], CertSerial: uuid.NewString(), AgentVersion: "test"})
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	return n.ID
}

func mustDevice(t *testing.T, ctx context.Context, q *sqlc.Queries, orgID, userID, nodeID uuid.UUID) uuid.UUID {
	t.Helper()
	d, err := q.CreateDevice(ctx, sqlc.CreateDeviceParams{
		Kind:  "human", // explicit: the COALESCE default covers a forgetful caller, tests should still say what they mean
		OrgID: orgID, UserID: userID, NodeID: nodeID, Name: "ovpn-dev", PublicKey: "+DeSO+POkGDPyK451u3mgL1y719ZUGSdtncSL1FeQGI=", Status: "active",
		Transport: "openvpn",
	})
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	return d.ID
}

// TestExportProfileAssemblesAndFingerprints (S9.1 Slice 4b-wiring) locks the export orchestration:
// ExportProfile issues + records the cert, assembles an importable .ovpn, and returns the SERIAL as
// the fingerprint — the keyed identity the caller audits, never the material.
func TestExportProfileAssemblesAndFingerprints(t *testing.T) {
	svc, ctx, orgID, deviceID, userID := setup(t)
	profile, fingerprint, err := svc.ExportProfile(ctx, orgID, userID, deviceID, []string{"gw.example.com"}, 1194)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// the fingerprint is the RECORDED cert serial (the audit's keyed identity).
	active, err := svc.q.ListActiveOVPNClientCertsByOrg(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 || active[0].Serial != fingerprint {
		t.Fatalf("fingerprint must be the recorded cert serial; got %q, rows=%d", fingerprint, len(active))
	}
	// importable profile: client directives + remote + inline material.
	for _, want := range []string{"client\n", "remote gw.example.com 1194\n", "remote-cert-tls server\n", "<ca>\n", "<cert>\n", "<key>\n"} {
		if !strings.Contains(profile, want) {
			t.Fatalf("profile missing %q; got:\n%s", want, profile)
		}
	}
	// the fingerprint is NEVER the material.
	if strings.Contains(fingerprint, "PRIVATE KEY") || strings.Contains(fingerprint, "BEGIN") {
		t.Fatalf("fingerprint must be the serial, never the material; got %q", fingerprint)
	}
}

// TestDisableDoesNotRevokeCerts (S9.1 D-S9.5-OPTIN d) locks the disable≠revocation rule: flipping the
// org's OpenVPN opt-in OFF is a plain org update — it does NOT touch issued client certs. A re-enable
// restores service with the same certs.
func TestDisableDoesNotRevokeCerts(t *testing.T) {
	svc, ctx, orgID, deviceID, _ := setup(t)
	if _, err := svc.Issue(ctx, orgID, deviceID, "cn"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// disable OpenVPN for the org.
	if _, err := svc.q.SetOrgOVPNEnabled(ctx, sqlc.SetOrgOVPNEnabledParams{ID: orgID, OvpnEnabled: false}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// the issued cert SURVIVES — disable is not revocation.
	active, err := svc.q.ListActiveOVPNClientCertsByOrg(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("disabling OpenVPN must NOT revoke issued certs (disable != revocation); active=%d", len(active))
	}
}

// TestEnsureServerCertMintOnceReDeliver (D-S9.6) locks mint-once + idempotent re-delivery: the first
// call MINTS + records the server cert (sealed key), and every later call re-delivers the SAME material
// (never a fresh mint) — so redelivery on every reconcile is stable.
func TestEnsureServerCertMintOnceReDeliver(t *testing.T) {
	svc, ctx, orgID, _, _ := setup(t)
	nodeID := mustNode(t, ctx, svc.q, orgID)

	ca1, cert1, key1, err := svc.EnsureServerCert(ctx, orgID, nodeID, "gw")
	if err != nil {
		t.Fatalf("ensure 1: %v", err)
	}
	if cert1 == "" || key1 == "" || ca1 == "" {
		t.Fatal("first call must deliver CA + server cert + server key")
	}
	ca2, cert2, key2, err := svc.EnsureServerCert(ctx, orgID, nodeID, "gw")
	if err != nil {
		t.Fatalf("ensure 2: %v", err)
	}
	if cert1 != cert2 || key1 != key2 || ca1 != ca2 {
		t.Fatal("re-delivery must return the SAME material (mint-once), not a fresh mint")
	}
	// exactly one recorded row for the node.
	if row, e := svc.q.GetOVPNServerCertForNode(ctx, nodeID); e != nil || row.CertPem != cert1 {
		t.Fatalf("the mint must be recorded once; err=%v", e)
	}
}
