package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Exercise the real decoder, certificate-derived node lookup, service mapping
// and stored capabilities. This is not a TLS handshake test: the handler sees
// the certificate state normally supplied by its mTLS listener.
func TestAgentReportPreservesUnavailableHealthPostgresContract(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	orgID, nodeID, otherNodeID := uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(nodeID[:])
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr)
		VALUES ($1,'report health',$2,'10.99.0.0/24')`, orgID, "report-health-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,cert_delivered)
		VALUES ($1,$2,'reporting node',$3,true), ($4,$2,'untouched node',$5,true)`,
		nodeID, orgID, hex.EncodeToString(serial.Bytes()), otherNodeID, "other-"+otherNodeID.String()); err != nil {
		t.Fatal(err)
	}
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	for _, tc := range []struct {
		name                 string
		fields               string
		conntrack, endpoints bool
	}{
		{"both unavailable", `,"conntrack_flush_unavailable":true,"k8s_endpoints_unavailable":true`, true, true},
		{"both recovered", `,"conntrack_flush_unavailable":false,"k8s_endpoints_unavailable":false`, false, false},
		{"only endpoints", `,"conntrack_flush_unavailable":false,"k8s_endpoints_unavailable":true`, false, true},
		{"only conntrack", `,"conntrack_flush_unavailable":true,"k8s_endpoints_unavailable":false`, true, false},
		{"older agent missing fields", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Body identity is deliberately wrong: only the certificate selects
			// which node's capabilities may change.
			body := `{"public_key":"` + publicKey + `","node_id":"` + otherNodeID.String() + `"` + tc.fields + `}`
			req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(body)).WithContext(ctx)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
			rr := httptest.NewRecorder()
			channel.report(rr, req)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("report status=%d: %s", rr.Code, rr.Body.String())
			}
			var encoded []byte
			if err := pool.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, nodeID).Scan(&encoded); err != nil {
				t.Fatal(err)
			}
			var caps map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &caps); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]bool{"conntrack_flush_unavailable": tc.conntrack, "k8s_endpoints_unavailable": tc.endpoints} {
				var got bool
				raw, exists := caps[key]
				if !exists || json.Unmarshal(raw, &got) != nil || got != want {
					t.Fatalf("capability %s=%s, want explicit %t", key, raw, want)
				}
			}
			var untouched bool
			if err := pool.QueryRow(ctx, `SELECT NOT (capabilities ? 'k8s_endpoints_unavailable')
				AND NOT (capabilities ? 'conntrack_flush_unavailable') FROM nodes WHERE id=$1`, otherNodeID).Scan(&untouched); err != nil || !untouched {
				t.Fatalf("body-selected node changed: untouched=%t err=%v", untouched, err)
			}
		})
	}
}
