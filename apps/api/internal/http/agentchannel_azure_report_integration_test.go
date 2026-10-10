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
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Exercise certificate-derived report identity, persistence, typed readback and
// eligibility. Listener certificate state is a fixture, not a TLS handshake.
func TestAgentAzureReportCapabilityPropagation(t *testing.T) {
	ctx, p := testpostgres.NewAtVersion(t, 225)
	org, actor, site, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(gateway[:])
	for _, step := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'Azure report',$2,'10.99.0.0/24')`, []any{org, "azure-report-" + org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@azure-report.test"}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'owned site')`, []any{site, org}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,cert_delivered) VALUES($1,$2,'reporter',$3,$4,true)`, []any{gateway, org, hex.EncodeToString(serial.Bytes()), site}},
	} {
		if _, err := p.Exec(ctx, step.q, step.a...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ipsec.NewSettingsStore(p).Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	channel := NewAgentChannel(nodes.NewService(p, nil, nil), nil, nil, nil)
	for _, tc := range []struct {
		name, fields    string
		azure, bgp, gcp bool
	}{
		{"supported", `,"ipsec_config_version":1,"ipsec_azure_version":1,"ipsec_bgp_version":1,"ipsec_gcp_classic_version":1,"ipsec_gcp_ha_version":1`, true, true, true},
		{"static only", `,"ipsec_config_version":1,"ipsec_azure_version":1`, true, false, false},
		{"omitted", `,"ipsec_config_version":1,"ipsec_bgp_version":1`, false, false, false},
		{"future", `,"ipsec_config_version":1,"ipsec_azure_version":2,"ipsec_bgp_version":1`, false, false, false},
		{"negative", `,"ipsec_config_version":1,"ipsec_azure_version":-1`, false, false, false},
		{"base unsupported", `,"ipsec_config_version":2,"ipsec_azure_version":1,"ipsec_bgp_version":1`, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="`+tc.fields+`}`)).WithContext(ctx)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
			rr := httptest.NewRecorder()
			channel.report(rr, req)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("report status %d", rr.Code)
			}
			var raw []byte
			if err := p.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, gateway).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			caps := nodes.Capabilities(raw)
			if (caps.IPsecAzureVersion == 1) != tc.azure || (caps.IPsecGCPClassicVersion == 1) != tc.gcp || (caps.IPsecGCPHAVersion == 1) != tc.gcp {
				t.Fatalf("capability propagation: %+v", caps)
			}
			eligible, err := ipsec.NewConnectionStore(p).ReadEligibility(ctx, org, site, gateway)
			if err != nil {
				t.Fatal(err)
			}
			if eligible.AzureStatic == nil || eligible.AzureBGP == nil || eligible.AzureStatic.Eligible != tc.azure || eligible.AzureBGP.Eligible != tc.bgp {
				t.Fatalf("eligibility %+v", eligible)
			}
		})
	}
}
