package ipsec_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func TestStatusAuthenticCertificateRenewalPreservesDelivery(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		t.Run(map[bool]string{false: "static", true: "bgp"}[dynamic], func(t *testing.T) {
			ctx, p, org, actor, sealer, req := providerFixture(t)
			if e := db.MigrateTo(p.Config().ConnString(), 217); e != nil {
				t.Fatal(e)
			}
			ca, _, e := agentca.LoadOrCreate(ctx, sqlc.New(p), sealer)
			if e != nil {
				t.Fatal(e)
			}
			svc := nodes.NewService(p, ca, sealer)
			csr := func() string {
				k, e := rsa.GenerateKey(rand.Reader, 2048)
				if e != nil {
					t.Fatal(e)
				}
				b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "create gateway"}}, k)
				if e != nil {
					t.Fatal(e)
				}
				return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}))
			}
			renew := func() ipsec.RuntimePrincipal {
				n, e := sqlc.New(p).GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: req.GatewayID, OrgID: org})
				if e != nil {
					t.Fatal(e)
				}
				cert, e := svc.Renew(ctx, n, csr(), "renewal-regression")
				if e != nil {
					t.Fatal(e)
				}
				block, _ := pem.Decode([]byte(cert))
				parsed, e := x509.ParseCertificate(block.Bytes)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = parsed.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
					t.Fatal(e)
				}
				serial := hex.EncodeToString(parsed.SerialNumber.Bytes())
				auth, e := svc.AuthenticateCert(ctx, serial)
				if e != nil || auth.ID != req.GatewayID {
					t.Fatal("real renewed certificate authentication", e)
				}
				return ipsec.RuntimePrincipal{OrgID: org, NodeID: auth.ID, CertificateSerial: serial}
			}
			initial := renew()
			if dynamic {
				req.Config = bgpConfigFixture()
				if _, e = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID); e != nil {
					t.Fatal(e)
				}
			}
			s := ipsec.NewConnectionStore(p)
			s.ConfigureRuntimePolicy(runtimeCompiler)
			c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
			if e != nil {
				t.Fatal(e)
			}
			c, e = s.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
			if e != nil {
				t.Fatal(e)
			}
			m, e := s.Material(ctx, initial, c.ID, c.DesiredRevision, sealer)
			if e != nil {
				t.Fatal(e)
			}
			immutable := func() string {
				var raw string
				if e := p.QueryRow(ctx, `SELECT row_to_json(d)::text FROM ipsec_runtime_deliveries d WHERE id=$1`, m.ID).Scan(&raw); e != nil {
					t.Fatal(e)
				}
				return raw
			}
			before := immutable()
			r := ipsec.RuntimeStatusReport{DeliveryID: m.ID, DesiredRevision: c.DesiredRevision, ConfigurationRevision: 1}
			for i := range r.Tunnels {
				r.Tunnels[i] = ipsec.RuntimeTunnelStatus{ID: m.Manifest.Tunnels[i].ID, Slot: i + 1, Status: "up", Selected: !dynamic && i == 0}
			}
			if dynamic {
				r.BGP = &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]ipsec.RuntimeBGPPeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}, Routes: []ipsec.RuntimeBGPRoute{{Prefix: req.Config.RemotePrefixes[0], Slot: 1}}}
			}
			if e = s.ReportStatus(ctx, initial, c.ID, r); e != nil {
				t.Fatal(e)
			}
			if dynamic {
				var oldRow, upgradedRow string
				if e = p.QueryRow(ctx, `SELECT row_to_json(s)::text FROM ipsec_bgp_status s WHERE connection_id=$1`, c.ID).Scan(&oldRow); e != nil {
					t.Fatal(e)
				}
				if e = db.MigrateTo(p.Config().ConnString(), 218); e != nil {
					t.Fatal(e)
				}
				if e = p.QueryRow(ctx, `SELECT row_to_json(s)::text FROM ipsec_bgp_status s WHERE connection_id=$1`, c.ID).Scan(&upgradedRow); e != nil || oldRow != upgradedRow || immutable() != before {
					t.Fatal("upgrade rewrote original observations/delivery", e)
				}
				// The old API's certificate-bound lookup remains usable before renewal.
				var exactOld bool
				if e = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_runtime_deliveries WHERE id=$1 AND node_id=$2 AND certificate_serial=$3 AND configuration_revision=1 AND kind='apply')`, m.ID, initial.NodeID, initial.CertificateSerial).Scan(&exactOld); e != nil || !exactOld {
					t.Fatal("old writer lookup incompatible after upgrade", e)
				}
				if e = s.ReportStatus(ctx, initial, c.ID, r); e != nil {
					t.Fatal("old writer incompatible after upgrade", e)
				}
				if e = db.MigrateTo(p.Config().ConnString(), 217); e != nil {
					t.Fatal("safe downgrade failed without rotated reports", e)
				}
			}
			current := renew()
			if current.CertificateSerial == initial.CertificateSerial {
				t.Fatal("renew did not rotate")
			}
			out, e := s.ReadStatus(ctx, org, c.ID)
			if e != nil || out.Tunnels[0].Status != "unknown" {
				t.Fatal("old certificate observation remained fresh", e)
			}
			if e = s.ReportStatus(ctx, initial, c.ID, r); !errors.Is(e, ipsec.ErrRuntimeUnauthorized) {
				t.Fatal("old principal accepted", e)
			}
			if dynamic {
				r.BGP.Sequence++
				if e = s.ReportStatus(ctx, current, c.ID, r); !errors.Is(e, ipsec.ErrConnectionUnavailable) {
					t.Fatal("old trigger unexpectedly accepted rotated writer", e)
				}
				r.BGP.Sequence--
			}
			if immutable() != before {
				t.Fatal("pre-upgrade delivery changed")
			}
			if e = db.MigrateTo(p.Config().ConnString(), 218); e != nil {
				t.Fatal(e)
			}
			if immutable() != before {
				t.Fatal("upgrade changed immutable delivery")
			}
			if dynamic {
				if e = s.ReportStatus(ctx, current, c.ID, r); e != nil {
					t.Fatal(e)
				}
				out, e = s.ReadStatus(ctx, org, c.ID)
				if e != nil || out.Tunnels[0].Status != "unknown" {
					t.Fatal("identical retry extended freshness", e)
				}
				r.BGP.Sequence++
			}
			if e = s.ReportStatus(ctx, current, c.ID, r); e != nil {
				t.Fatal("current authentic certificate cannot report original delivery", e)
			}
			out, e = s.ReadStatus(ctx, org, c.ID)
			if e != nil || out.Tunnels[0].Status != "up" || (dynamic && out.BGP == nil) {
				t.Fatal("renewed observation not fresh", e)
			}
			if dynamic {
				stale := r
				copyBGP := *r.BGP
				copyBGP.Sequence--
				stale.BGP = &copyBGP
				if e = s.ReportStatus(ctx, current, c.ID, stale); !errors.Is(e, ipsec.ErrConnectionConflict) {
					t.Fatal("stale observation accepted after renewal", e)
				}
			}
			if dynamic {
				// Direct SQL cannot bypass the current enrollment or immutable delivery tuple.
				for _, q := range []string{
					`UPDATE ipsec_bgp_status SET certificate_serial='foreign' WHERE connection_id=$1`,
					`UPDATE ipsec_bgp_status SET certificate_serial=$2 WHERE connection_id=$1`,
					`UPDATE ipsec_bgp_status SET node_id='00000000-0000-0000-0000-000000000001' WHERE connection_id=$1`,
					`UPDATE ipsec_bgp_status SET desired_revision=desired_revision+1 WHERE connection_id=$1`,
					`UPDATE ipsec_bgp_status SET configuration_revision=configuration_revision+1 WHERE connection_id=$1`,
				} {
					args := []any{c.ID}
					if strings.Contains(q, "$2") {
						args = append(args, initial.CertificateSerial)
					}
					if _, e = p.Exec(ctx, q, args...); e == nil {
						t.Fatal("direct SQL foreign status accepted", q)
					}
				}
				down, e := os.ReadFile("../../db/migrations/0218_ipsec_status_certificate_renewal.down.sql")
				if e != nil {
					t.Fatal(e)
				}
				tx, e := p.Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				_, e = tx.Exec(ctx, string(down))
				_ = tx.Rollback(ctx)
				if e == nil || !strings.Contains(e.Error(), "rotated-certificate observations") {
					t.Fatal("unsafe downgrade not refused", e)
				}
			}
			for _, bad := range []ipsec.RuntimePrincipal{{OrgID: uuid.New(), NodeID: current.NodeID, CertificateSerial: current.CertificateSerial}, {OrgID: org, NodeID: uuid.New(), CertificateSerial: current.CertificateSerial}, {OrgID: org, NodeID: current.NodeID, CertificateSerial: "foreign"}} {
				if e = s.ReportStatus(ctx, bad, c.ID, r); e == nil {
					t.Fatal("foreign principal accepted")
				}
			}
			bad := r
			bad.DesiredRevision++
			if e = s.ReportStatus(ctx, current, c.ID, bad); e == nil {
				t.Fatal("wrong revision accepted")
			}
			bad = r
			bad.ConfigurationRevision++
			if e = s.ReportStatus(ctx, current, c.ID, bad); e == nil {
				t.Fatal("wrong configuration accepted")
			}
			if _, e = s.PermitLease(ctx, current, c.ID, ipsec.RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: c.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: strings.Repeat("b", 64)}); e != nil {
				t.Fatal("current certificate permit refused", e)
			}
			if immutable() != before {
				t.Fatal("immutable delivery changed")
			}
			if _, e = p.Exec(ctx, `UPDATE nodes SET revoked_at=clock_timestamp() WHERE id=$1`, req.GatewayID); e != nil {
				t.Fatal(e)
			}
			if e = s.ReportStatus(ctx, current, c.ID, r); !errors.Is(e, ipsec.ErrRuntimeUnauthorized) {
				t.Fatal("revoked principal accepted", e)
			}
			out, e = s.ReadStatus(ctx, org, c.ID)
			if e != nil || out.Tunnels[0].Status != "unknown" {
				t.Fatal("revoked observation fresh", e)
			}
		})
	}
}
