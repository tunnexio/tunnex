package devices

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpn"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
)

// TestRevokeOVPNDeviceIsThreePartSweep is the Slice 5d red: ONE devices.Revoke of an OpenVPN device
// delivers the same three-part guarantee the WireGuard path proves live —
//  1. the live SESSION dies: the cert serial lands on the org CRL (crl-verify kills it at the next reneg),
//  2. it cannot RECONNECT: the device leaves the OVPN roster (no CCD → ccd-exclusive refuses),
//  3. its ADDRESS returns to the pool — RE-ALLOCATABLE, which is not the same as cleared (amended, S13.1 D5).
//
// Through the real devices.Revoke with the shared RebuildCRL seam wired — proving all three happen together.
func TestRevokeOVPNDeviceIsThreePartSweep(t *testing.T) {
	ctx, tx := txOrSkip(t)
	q := sqlc.New(tx)
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed: %v", e)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "ro-"+org.String()[:8])
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", user, user.String()+"@t")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'k','e:51820')", node, org, "cs-"+node.String()[:8])
	// An OVPN device (keyless, transport openvpn) holding a pool /32.
	dev := uuid.New()
	ex("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,transport) VALUES ($1,$2,$3,$4,'ovpn',''::text,'10.99.0.6','openvpn')",
		dev, org, user, node)

	// The ovpn service (CA loaded through the real sealed path) + an issued client cert for the device.
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	ovpnSvc := ovpn.NewService(q, func(ctx context.Context) (*ovpnca.CA, error) {
		c, _, e := ovpnca.LoadOrCreate(ctx, q, sealer)
		return c, e
	}, sealer)
	cert, err := ovpnSvc.Issue(ctx, org, dev, "device-"+dev.String())
	if err != nil {
		t.Fatalf("issue ovpn cert: %v", err)
	}

	// The device service on the same tx, with the SHARED CRL rebuild seam wired.
	svc := &Service{q: q, logger: slog.Default()}
	svc.SetRebuildCRL(ovpnSvc.RebuildCRL)

	if err := svc.Revoke(ctx, org, user, dev); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// (1) SESSION DIES — the serial is on the org CRL.
	crlPEM, err := ovpnSvc.GetCRL(ctx, org)
	if err != nil {
		t.Fatalf("get crl: %v", err)
	}
	blk, _ := pem.Decode([]byte(crlPEM))
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	sn := new(big.Int)
	b, _ := hex.DecodeString(cert.Serial)
	sn.SetBytes(b)
	onCRL := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(sn) == 0 {
			onCRL = true
		}
	}
	if !onCRL {
		t.Fatal("(1) revoked OVPN cert's serial must be on the org CRL (session dies at next reneg)")
	}

	// (2) CANNOT RECONNECT — the device is gone from the OVPN roster (no CCD → ccd-exclusive).
	roster, err := q.ListActiveOVPNDevicesForNode(ctx, node)
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	for _, r := range roster {
		if r.ID == dev {
			t.Fatal("(2) a revoked OVPN device must leave the roster (no CCD → cannot reconnect)")
		}
	}

	// (3) ADDRESS RE-ALLOCATABLE — asserted against the allocation oracle, not against the row.
	//
	// AMENDED (S13.1 D5): this required assigned_ip to be NULL. The address was never freed BY nulling it — it is
	// free the instant status leaves ('active','pending'), because that is the predicate on both
	// devices_org_ip_key and ListActiveDeviceAllocations. Nulling destroyed the record of what the user held, which
	// is what made a cascade-revoked device unrestorable to its own address (Wall 6). The parity claim this test
	// exists for is unchanged — OVPN revocation frees the address exactly as WireGuard does — but it is now
	// asserted as re-allocatability rather than as a NULL column.
	row, err := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: dev, OrgID: org})
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if row.AssignedIp == nil {
		t.Fatal("(3) a revoked device must KEEP its assigned_ip as the record of what the revocation took")
	}
	allocs, aerr := q.ListActiveDeviceAllocations(ctx, org)
	if aerr != nil {
		t.Fatalf("oracle: %v", aerr)
	}
	for _, al := range allocs {
		if al.AssignedIp != nil && *al.AssignedIp == *row.AssignedIp {
			t.Fatalf("(3) a revoked OVPN device's address must not read as a LIVE allocation — the pool must be "+
				"free to hand %s out again", *row.AssignedIp)
		}
	}
}
