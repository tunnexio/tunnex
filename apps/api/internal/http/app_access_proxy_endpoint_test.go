package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AA-EN-1 E5: the endpoint configuration is validated once; a bad value never
// reaches a gateway, it disables delivery instead.
func TestNewAppProxyEndpointValidation(t *testing.T) {
	for _, tc := range []struct {
		port, host string
		locked     bool
		want       AppProxyEndpoint
		bad        bool
	}{
		{port: "", want: AppProxyEndpoint{}},
		{port: "8444", want: AppProxyEndpoint{Port: 8444}},
		{port: "8444", host: "10.70.0.2", want: AppProxyEndpoint{Port: 8444, Host: "10.70.0.2"}},
		{port: "8444", host: "cp.internal.example", want: AppProxyEndpoint{Port: 8444, Host: "cp.internal.example"}},
		{port: "8444", host: "fd00::2", want: AppProxyEndpoint{Port: 8444, Host: "fd00::2"}},
		{port: "8444", locked: true, want: AppProxyEndpoint{Port: 8444, Locked: true}},
		{port: "0", bad: true},
		{port: "65536", bad: true},
		{port: "84a4", bad: true},
		{port: "8444", host: "10.70.0.2:8444", bad: true},
		{port: "8444", host: "https://cp.example", bad: true},
		{port: "8444", host: "user@cp.example", bad: true},
		{port: "8444", host: "cp.example/path", bad: true},
		{port: "8444", host: "[fd00::2]", bad: true},
		{port: "8444", host: "-bad.example", bad: true},
		{port: "8444", host: "bad..example", bad: true},
		{port: "", host: "10.70.0.2", bad: true},
	} {
		got, err := NewAppProxyEndpoint(tc.port, tc.host, tc.locked)
		if tc.bad {
			if err == nil {
				t.Errorf("port=%q host=%q accepted: %+v", tc.port, tc.host, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("port=%q host=%q = %+v, %v; want %+v", tc.port, tc.host, got, err, tc.want)
		}
	}
}

// The enabled truth table: installation (port configured) x operator lock x
// entitlement x organization feature. Each one alone turns delivery off.
func TestAppProxyEndpointDecision(t *testing.T) {
	org := uuid.New()
	on := func(context.Context, uuid.UUID) (bool, error) { return true, nil }
	off := func(context.Context, uuid.UUID) (bool, error) { return false, nil }
	broken := func(context.Context, uuid.UUID) (bool, error) { return false, errors.New("db down") }
	for _, tc := range []struct {
		name     string
		endpoint AppProxyEndpoint
		entitled bool
		orgOn    func(context.Context, uuid.UUID) (bool, error)
		want     appProxyEndpointWire
		err      bool
	}{
		{"not installed", AppProxyEndpoint{}, true, on, appProxyEndpointWire{}, false},
		{"locked", AppProxyEndpoint{Port: 8444, Locked: true}, true, on, appProxyEndpointWire{}, false},
		{"not entitled", AppProxyEndpoint{Port: 8444}, false, on, appProxyEndpointWire{}, false},
		{"organization off", AppProxyEndpoint{Port: 8444}, true, off, appProxyEndpointWire{}, false},
		{"no organization reader", AppProxyEndpoint{Port: 8444}, true, nil, appProxyEndpointWire{}, false},
		{"organization unreadable", AppProxyEndpoint{Port: 8444}, true, broken, appProxyEndpointWire{}, true},
		{"on, gateway's own agent host", AppProxyEndpoint{Port: 8444}, true, on, appProxyEndpointWire{Enabled: true, Port: 8444}, false},
		{"on, operator host", AppProxyEndpoint{Port: 8444, Host: "10.70.0.2"}, true, on, appProxyEndpointWire{Enabled: true, Port: 8444, Host: "10.70.0.2"}, false},
	} {
		a := &AgentChannel{appAccessEntitled: func() bool { return tc.entitled }}
		a.SetAppProxyEndpoint(tc.endpoint, tc.orgOn)
		got, err := a.appProxyEndpointFor(context.Background(), org)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%s = %+v, %v; want %+v (error %v)", tc.name, got, err, tc.want, tc.err)
		}
	}
}

// Over the real handler: a gateway identity is required, the answer is
// no-store JSON, and an unreadable organization setting is 503 (the gateway
// keeps its current state), never "off".
func TestAppProxyEndpointAgentHandler(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, gateway, client := uuid.New(), uuid.New(), uuid.New()
	serial := func(id uuid.UUID) *big.Int { return new(big.Int).SetBytes(id[:]) }
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'AA endpoint',$2,'10.94.0.0/24')`, []any{org, "aa-endpoint-" + org.String()}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,status,enrolled_kind,cert_delivered) VALUES($1,$2,'gw',$3,'active','gateway',true),($4,$2,'not-gw',$5,'active','agent',true)`, []any{gateway, org, hex.EncodeToString(serial(gateway).Bytes()), client, hex.EncodeToString(serial(client).Bytes())}},
	} {
		if _, err := pool.Exec(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	orgOn := true
	var orgErr error
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	channel.appAccessEntitled = func() bool { return true }
	channel.SetAppProxyEndpoint(AppProxyEndpoint{Port: 8444, Host: "10.70.0.2"}, func(_ context.Context, got uuid.UUID) (bool, error) {
		if got != org {
			t.Errorf("organization read for %s, want the gateway's own %s", got, org)
		}
		return orgOn, orgErr
	})
	ask := func(node uuid.UUID) (*httptest.ResponseRecorder, appProxyEndpointWire) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/agent/app-access/proxy-endpoint", nil).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial(node)}}}
		rr := httptest.NewRecorder()
		channel.Handler().ServeHTTP(rr, req)
		var out appProxyEndpointWire
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return rr, out
	}
	if rr, _ := ask(client); rr.Code != http.StatusForbidden {
		t.Fatalf("non-gateway node status = %d", rr.Code)
	}
	if rr, _ := ask(uuid.New()); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unknown certificate status = %d", rr.Code)
	}
	rr, out := ask(gateway)
	if rr.Code != http.StatusOK || out != (appProxyEndpointWire{Enabled: true, Port: 8444, Host: "10.70.0.2"}) {
		t.Fatalf("enabled gateway = %d %+v", rr.Code, out)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rr.Header().Get("Cache-Control"))
	}
	orgOn = false
	if rr, out := ask(gateway); rr.Code != http.StatusOK || out != (appProxyEndpointWire{}) {
		t.Fatalf("organization off = %d %+v", rr.Code, out)
	}
	orgErr = errors.New("database unavailable")
	if rr, _ := ask(gateway); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable organization = %d, want 503 so the gateway keeps its state", rr.Code)
	}
}

// Founder ruling 3: a listener bound only to loopback cannot be reached by a
// remote gateway, so it is not delivered unless the operator names a host.
func TestAppProxyEndpointLoopbackBindIsNotDelivered(t *testing.T) {
	on := func(context.Context, uuid.UUID) (bool, error) { return true, nil }
	for _, tc := range []struct {
		bind, host string
		enabled    bool
	}{
		{"", "", true},
		{"0.0.0.0", "", true},
		{"::", "", true},
		{"10.70.0.2", "", true},
		{"127.0.0.1", "", false},
		{"127.0.0.53", "", false},
		{"::1", "", false},
		{"127.0.0.1", "gw-tunnel.internal", true},
	} {
		endpoint, err := NewAppProxyEndpointWithBind("8444", tc.host, tc.bind, false)
		if err != nil {
			t.Fatalf("%q: %v", tc.bind, err)
		}
		a := &AgentChannel{appAccessEntitled: func() bool { return true }}
		a.SetAppProxyEndpoint(endpoint, on)
		got, err := a.appProxyEndpointFor(context.Background(), uuid.New())
		if err != nil || got.Enabled != tc.enabled {
			t.Errorf("bind %q host %q = %+v, %v; want enabled %v", tc.bind, tc.host, got, err, tc.enabled)
		}
	}
	if _, err := NewAppProxyEndpointWithBind("8444", "", "not-an-ip", false); err == nil {
		t.Fatal("invalid bind address accepted")
	}
}
