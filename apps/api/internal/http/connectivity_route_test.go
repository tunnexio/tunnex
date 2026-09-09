package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/connectivity"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func TestConnectivityRoutesPostgres(t *testing.T) {
	pool := gateTestPool(t)
	ctx := context.Background()
	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'nat-route',$2)`, org, "nat-route-"+org.String())
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, user, user.String()+"@example.invalid")
	t.Cleanup(func() {
		exec(`DELETE FROM organizations WHERE id=$1`, org)
		exec(`DELETE FROM users WHERE id=$1`, user)
	})
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	serial := new(big.Int).SetBytes(node[:])
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'nat-route',$3)`, node, org, hex.EncodeToString(serial.Bytes()))
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,$4,'nat-route',$5,'10.99.0.2')`, device, org, user, node, strings.Repeat("A", 43)+"=")
	exec(`INSERT INTO connectivity_profiles(org_id,enabled) VALUES($1,true)`, org)
	principal := &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{System: sqlc.New(pool), Orgs: tenancy.NewService(pool), Connectivity: connectivity.NewStore(pool), AuthFn: func(*http.Request) *authctx.Principal { return principal }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tunnex-CSRF", "1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: want %d, got %d: %s", method, want, w.Code, w.Body.String())
		}
		return w
	}
	base := fmt.Sprintf("/api/v1/organizations/%s/devices/%s/connectivity-sessions", org, device)
	var m api.ConnectivityMailbox
	if err := json.Unmarshal(call("POST", base, "", 201).Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("%s/%s?generation=%d", base, m.SessionId, m.Generation)
	call("GET", path, "", 200)
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, slog.Default())
	channel.SetConnectivityStore(connectivity.NewStore(pool))
	mtlsCall := func(certSerial *big.Int, method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if certSerial != nil {
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: certSerial}}}
		}
		w := httptest.NewRecorder()
		channel.Handler().ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("gateway %s want %d got %d: %s", method, want, w.Code, w.Body.String())
		}
		return w
	}
	agentPath := fmt.Sprintf("/agent/connectivity-sessions/%s/%s?generation=%d", device, m.SessionId, m.Generation)
	mtlsCall(nil, "GET", agentPath, "", 401)
	mtlsCall(big.NewInt(42), "GET", agentPath, "", 401)
	mtlsCall(serial, "GET", agentPath, "", 200)
	page := mtlsCall(serial, "GET", "/agent/connectivity-sessions", "", 200)
	if !strings.Contains(page.Body.String(), m.SessionId.String()) {
		t.Fatal("gateway pending omitted owned session")
	}
	otherNode := uuid.New()
	otherSerial := new(big.Int).SetBytes(otherNode[:])
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'other-nat-route',$3)`, otherNode, org, hex.EncodeToString(otherSerial.Bytes()))
	mtlsCall(otherSerial, "GET", agentPath, "", 403)
	mtlsCall(serial, "PUT", agentPath, `{"sequence":1,"payload":"{}","gateway_id":"spoof"}`, 400)
	mtlsCall(serial, "PUT", agentPath, `{"sequence":1,"payload":"{\"answer\":true}"}`, 200)
	mtlsCall(serial, "PUT", agentPath, `{"sequence":1,"payload":"{}"}`, 403)
	call("PUT", path, `{"sequence":1,"payload":"{\"complete\":true}"}`, 200)
	call("PUT", path, `{"sequence":1,"payload":"{}"}`, 403)
	call("PUT", path, `{"sequence":2,"payload":"[]"}`, 400)
	principal.UserID = uuid.New() // same claimed role is NOT device ownership
	call("GET", path, "", 403)
	principal.UserID = user
	principal.Roles[org] = rbac.RoleOperator
	call("POST", base, "", 403)
	principal.Roles[org] = rbac.RoleMember
	call("DELETE", path, "", 204)
	call("GET", path, "", 403)
	principal = nil
	call("GET", path, "", 401)
}
