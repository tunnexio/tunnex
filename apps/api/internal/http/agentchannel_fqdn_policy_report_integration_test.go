package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Exercise the authenticated report decoder and persisted capability, rather
// than inferring support from the node service's internal report DTO.
func TestAgentIPsecFQDNPolicyReportPersistsExactNumericCapability(t *testing.T) {
	ctx, p := testpostgres.NewAtVersion(t, 220)
	org, site, gateway := uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(gateway[:])
	certSerial := hex.EncodeToString(serial.Bytes())
	for _, step := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'FQDN report',$2,'10.99.0.0/24')`, []any{org, "fqdn-report-" + org.String()}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'owned site')`, []any{site, org}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,cert_delivered) VALUES($1,$2,'reporter',$3,$4,true)`, []any{gateway, org, certSerial, site}},
	} {
		if _, e := p.Exec(ctx, step.q, step.a...); e != nil {
			t.Fatal(e)
		}
	}
	channel := NewAgentChannel(nodes.NewService(p, nil, nil), nil, nil, nil)
	readCapability := func() int {
		t.Helper()
		var raw []byte
		if e := p.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, gateway).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		return nodes.Capabilities(raw).IPsecFQDNPolicyVersion
	}
	for _, tc := range []struct {
		name, fields string
		status, want int
	}{
		{"supported", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":1`, http.StatusNoContent, 1},
		{"string rejected preserves prior", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":"1"`, http.StatusBadRequest, 1},
		{"bool rejected preserves prior", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":true`, http.StatusBadRequest, 1},
		{"omitted clears stale support", `,"ipsec_config_version":1`, http.StatusNoContent, 0},
		{"supported v2", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":2`, http.StatusNoContent, 2},
		{"unknown version", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":3`, http.StatusNoContent, 0},
		{"negative version", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":-1`, http.StatusNoContent, 0},
		{"missing IPsec support", `,"ipsec_fqdn_policy_version":1`, http.StatusNoContent, 0},
		{"recovers exact support", `,"ipsec_config_version":1,"ipsec_fqdn_policy_version":1`, http.StatusNoContent, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="`+tc.fields+`}`)).WithContext(ctx)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
			rr := httptest.NewRecorder()
			channel.report(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("report status=%d want=%d body=%s", rr.Code, tc.status, rr.Body.String())
			}
			if got := readCapability(); got != tc.want {
				t.Fatalf("persisted capability=%d want=%d", got, tc.want)
			}
		})
	}
}
