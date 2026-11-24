package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/serveraccess"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

// SA-UI-1: a following gateway learns installation AND organization Server Access over mTLS.
func TestServerAccessCapabilityAgentEndpoint(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, admin, gateway, client := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := func(id uuid.UUID) *big.Int { return new(big.Int).SetBytes(id[:]) }
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'SA capability',$2,'10.93.0.0/24')`, []any{org, "sa-cap-" + org.String()}},
		{`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, []any{admin, admin.String() + "@example.invalid"}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,status,enrolled_kind,cert_delivered) VALUES($1,$2,'gw',$3,'active','gateway',true),($4,$2,'not-gw',$5,'active','agent',true)`, []any{gateway, org, hex.EncodeToString(serial(gateway).Bytes()), client, hex.EncodeToString(serial(client).Bytes())}},
	} {
		if _, err := pool.Exec(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	svc := serveraccess.New(pool, nil, nil, true)
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	channel.SetServerAccess(svc)
	ask := func(node uuid.UUID) (int, terminalwire.Capability) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/agent/server-access/capability", nil).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial(node)}}}
		rr := httptest.NewRecorder()
		channel.Handler().ServeHTTP(rr, req)
		var out terminalwire.Capability
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code, out
	}
	if code, _ := ask(client); code != http.StatusForbidden {
		t.Fatalf("non-gateway node status = %d", code)
	}
	if code, out := ask(gateway); code != http.StatusOK || out.Enabled {
		t.Fatalf("installation on, organization not opted in = %d %+v", code, out)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO server_access_settings(org_id,enabled,ca_private_sealed,ca_public) VALUES($1,true,'unused','unused')`, org); err != nil {
		t.Fatal(err)
	}
	if code, out := ask(gateway); code != http.StatusOK || !out.Enabled {
		t.Fatalf("installation on, organization on = %d %+v", code, out)
	}
	if _, _, err := svc.SaveInstallation(ctx, admin, serveraccess.InstallationUpdate{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if code, out := ask(gateway); code != http.StatusOK || out.Enabled {
		t.Fatalf("installation off = %d %+v", code, out)
	}
}
