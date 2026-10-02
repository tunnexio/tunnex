package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProposalVPNHTTPChannelPolicyAndReports(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, node, other := uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(node[:])
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,ai_gateway_enabled) VALUES($1,'VPN HTTP',$2,'10.99.0.0/24',true)`, org, org.String())
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,cert_delivered) VALUES($1,$2,'VPN gateway',$3,true),($4,$2,'other gateway',$5,true)`, node, org, hex.EncodeToString(serial.Bytes()), other, other.String())
	user, device, group, connection := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@test.local")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,'VPN peer','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','10.99.0.2','active','human')`, device, org, user, node)
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'VPN group')`, group, org)
	exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, user)
	exec(`INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,applied_revision,status) VALUES($1,$2,$3,'openrouter','Fixture',ARRAY['openrouter/vpn'],true,1,1,'applied')`, connection, org, "tnx-managed-"+connection.String())
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policies := aigateway.NewPolicies(pool, sealer, userAccessEngine{})
	policies.ConfigureAutomaticVPNIngress(true)
	if _, err := policies.PutUserModelGrant(ctx, org, user, group, connection, "openrouter/vpn", true, 0); err != nil {
		t.Fatal(err)
	}
	var arrivals atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("X-Bf-Vk") != "sk-bf-private-group-key" {
			t.Error("wrong private engine path or scoped key")
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Tunnex-VPN-IP", "X-Tunnex-VPN-Key", "X-Tunnex-Tenant", "X-Forwarded-For", "X-Forwarded-Proto"} {
			if r.Header.Get(name) != "" {
				t.Errorf("caller header %s reached engine", name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"VPN fixture success"}}]}`)
	}))
	defer upstream.Close()
	adapter, err := aigateway.NewAdapter(upstream.URL, func(context.Context, string, string) (aigateway.Grant, error) {
		t.Fatal("untrusted authorizer used")
		return aigateway.Grant{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	channel.SetVPNInference(adapter, policies)
	channel.SetVPNHTTPTransport(aitransport.New(pool))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	srv := httptest.NewUnstartedServer(channel.Handler())
	// Permit absent certificates through to the handler's 401, but cryptographically verify every presented one.
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	plainClient := srv.Client()
	certTransport := plainClient.Transport.(*http.Transport).Clone()
	certTransport.TLSClientConfig = certTransport.TLSClientConfig.Clone()
	certTransport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	certClient := &http.Client{Transport: certTransport}
	defer certTransport.CloseIdleConnections()
	call := func(path, body string, cert bool) *httptest.ResponseRecorder {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tunnex-VPN-IP", "10.99.0.2")
		r.Header.Set("X-Tunnex-VPN-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		r.Header.Set("Authorization", "Bearer unused")
		r.Header.Set("Cookie", "forged=session")
		r.Header.Set("X-Tunnex-Tenant", "forged")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-For", "10.99.0.2")
		client := plainClient
		if cert {
			client = certClient
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		w := httptest.NewRecorder()
		w.Code = response.StatusCode
		_, err = io.Copy(w.Body, response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	route := "/agent/ai-http/organizations/" + org.String() + "/v1/chat/completions"
	for _, path := range []string{route, "/agent/ai-http/v1/chat/completions", "/agent/ai/v1/chat/completions"} {
		if w := call(path, "{}", false); w.Code != 401 {
			t.Fatalf("forged headers bypassed mTLS: %d %s", w.Code, w.Body.String())
		}
	}
	check := func(want int, code string) {
		t.Helper()
		w := call(route, "{}", true)
		if w.Code != want || !strings.Contains(w.Body.String(), code) {
			t.Fatalf("status %d want %d/%s: %s", w.Code, want, code, w.Body.String())
		}
	}
	check(403, "ai_https_required")
	exec(`UPDATE server_ai_transport_settings SET allow_http=true,revision=revision+1 WHERE singleton`)
	// The intentionally incomplete body reaches normal adapter validation only when policy permits.
	check(400, "")
	exec(`UPDATE server_ai_transport_settings SET allow_http=false,revision=revision+1 WHERE singleton`)
	check(403, "ai_https_required")
	channel.SetVPNHTTPTransport(nil)
	check(503, "ai_transport_settings_unavailable")
	channel.SetVPNHTTPTransport(&aiTransportStub{failure: errors.New("fixture unavailable")})
	check(503, "ai_transport_settings_unavailable")
	channel.SetVPNHTTPTransport(aitransport.New(pool))
	policies.ConfigureAutomaticVPNIngress(false)
	check(403, "ai_vpn_unavailable")
	policies.ConfigureAutomaticVPNIngress(true)
	if w := call("/agent/ai-http/organizations/"+uuid.NewString()+"/v1/chat/completions", "{}", true); w.Code != 403 {
		t.Fatal("wrong org passed")
	}
	// Manual TLS route ignores the new HTTP policy, retaining its pre-existing validation flow.
	if w := call("/agent/ai/v1/chat/completions", "{}", true); w.Code != 400 {
		t.Fatalf("manual TLS was blocked by HTTP policy: %d %s", w.Code, w.Body.String())
	}
	// Report decoding, certificate-selected node and omission clearing use the real wire/service pipeline.
	const pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	for _, tc := range []struct {
		fields  string
		ready   bool
		address string
	}{
		{`,"ai_vpn_http_ready":true,"ai_vpn_http_address":"10.99.0.1"`, true, "10.99.0.1"},
		{``, false, ""},
		{`,"ai_vpn_http_ready":true,"ai_vpn_http_address":"https://10.99.0.1"`, false, ""},
		{`,"ai_vpn_http_ready":true,"ai_vpn_http_address":"8.8.8.8"`, false, ""},
	} {
		body := `{"public_key":"` + pk + `","node_id":"` + other.String() + `"` + tc.fields + `}`
		w := call("/agent/report", body, true)
		if w.Code != 204 {
			t.Fatalf("report %d: %s", w.Code, w.Body.String())
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, node).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Ready   bool   `json:"ai_vpn_http_ready"`
			Address string `json:"ai_vpn_http_address"`
		}
		if json.Unmarshal(raw, &got) != nil || got.Ready != tc.ready || got.Address != tc.address {
			t.Fatalf("wrong persisted report %s", raw)
		}
	}
	var untouched bool
	if err := pool.QueryRow(ctx, `SELECT NOT (capabilities ? 'ai_vpn_http_ready') FROM nodes WHERE id=$1`, other).Scan(&untouched); err != nil || !untouched {
		t.Fatal("body-selected identity changed")
	}
	// Fully composed automatic HTTP route: mTLS gateway -> exact peer/current
	// grant -> adapter -> local fake engine. No external provider call occurs.
	const chat = `{"model":"openrouter/vpn","messages":[{"role":"user","content":"fixture"}]}`
	if w := call("/agent/report", `{"public_key":"`+pk+`","ai_vpn_http_ready":true,"ai_vpn_http_address":"10.99.0.1"}`, true); w.Code != 204 {
		t.Fatal("ready report failed")
	}
	exec(`UPDATE server_ai_transport_settings SET allow_http=true,revision=revision+1 WHERE singleton`)
	if w := call(route, chat, true); w.Code != 200 || !strings.Contains(w.Body.String(), "VPN fixture success") {
		t.Fatalf("valid inference %d: %s", w.Code, w.Body.String())
	}
	if arrivals.Load() != 1 {
		t.Fatal("valid request did not reach fixture engine once")
	}
	if w := call("/agent/ai-http/v1/chat/completions", chat, true); w.Code != 200 {
		t.Fatalf("single-organization short route failed: %d %s", w.Code, w.Body.String())
	}
	if arrivals.Load() != 2 {
		t.Fatal("short route did not reach fixture engine once")
	}
	exec(`UPDATE devices SET status='revoked' WHERE id=$1`, device)
	if w := call(route, chat, true); w.Code != 403 {
		t.Fatalf("revoked peer status %d", w.Code)
	}
	exec(`UPDATE devices SET status='active' WHERE id=$1`, device)
	exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, user)
	if w := call(route, chat, true); w.Code != 403 {
		t.Fatalf("revoked grant status %d", w.Code)
	}
	exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, user)
	exec(`UPDATE server_ai_transport_settings SET allow_http=false,revision=revision+1 WHERE singleton`)
	if w := call(route, chat, true); w.Code != 403 || !strings.Contains(w.Body.String(), "ai_https_required") {
		t.Fatalf("current HTTP OFF ignored: %d", w.Code)
	}
	if arrivals.Load() != 2 {
		t.Fatal("denied request reached fixture engine")
	}
	exec(`UPDATE nodes SET status='revoked' WHERE id=$1`, node)
	if w := call(route, "{}", true); w.Code != 401 {
		t.Fatal("revoked gateway accepted")
	}
}
func TestProposalVPNMetadataHTTPPolicy(t *testing.T) {
	policies := aigateway.NewPolicies(nil, nil, nil)
	policies.ConfigureAutomaticVPNIngress(true)
	server := apiServer{aiPolicies: policies}
	for _, tc := range []struct {
		settings aiTransportRepository
		reason   string
	}{
		{nil, "transport_unavailable"}, {&aiTransportStub{failure: errors.New("read failed")}, "transport_unavailable"},
		{&aiTransportStub{value: aitransport.Settings{AllowHTTP: false}}, "http_disabled"},
		{&aiTransportStub{value: aitransport.Settings{AllowHTTP: true}}, "gateway_not_ready"},
	} {
		server.aiTransport = tc.settings
		url, reason := server.userVPNEndpoint(context.Background(), uuid.New(), uuid.New())
		if url != "" || reason != tc.reason {
			t.Fatalf("url=%q reason=%q want %q", url, reason, tc.reason)
		}
	}
	policies.ConfigureAutomaticVPNIngress(false)
	if _, reason := server.userVPNEndpoint(context.Background(), uuid.New(), uuid.New()); reason != "deployment_disabled" {
		t.Fatal("disabled deployment advertised")
	}
}

func TestProposalPublicRoutesNeverAcceptVPNIdentityHeaders(t *testing.T) {
	authorizations := 0
	adapter, err := aigateway.NewAdapter("http://127.0.0.1:1", func(_ context.Context, token, model string) (aigateway.Grant, error) {
		authorizations++
		if token != "unused" {
			t.Fatalf("public credential input changed: %q", token)
		}
		return aigateway.Grant{}, apierr.New(401, "unauthenticated", "authentication required")
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := aigateway.NewPolicies(nil, nil, nil)
	policies.ConfigureAutomaticVPNIngress(true)
	handler, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		AIAdapter: adapter, AIPolicies: policies, AITransport: &aiTransportStub{value: aitransport.Settings{AllowHTTP: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	org := uuid.NewString()
	for _, path := range []string{"/ai/v1/chat/completions", "/api/v1/organizations/" + org + "/ai-gateway/inference/v1/chat/completions"} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(`{"model":"openrouter/vpn","messages":[{"role":"user","content":"fixture"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer unused")
		req.Header.Set("X-Tunnex-VPN-IP", "10.99.0.2")
		req.Header.Set("X-Tunnex-VPN-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		req.Header.Set("X-Forwarded-For", "10.99.0.2")
		req.Header.Set("X-Forwarded-Proto", "https")
		response, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 401 {
			t.Fatalf("public route %s accepted/changed refusal: %d %s", path, response.StatusCode, body)
		}
	}
	if authorizations != 1 {
		t.Fatalf("public route used unexpected credential path: %d", authorizations)
	}
}

func TestProposalLegacyTLSMetadataRequiresOwnedActiveDevice(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,ai_gateway_enabled) VALUES($1,'TLS VPN',$2,'10.99.0.0/24',true)`, org, org.String())
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@test.local")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'TLS gateway',$3)`, node, org, node.String())
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,'TLS peer','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','10.99.0.2','active','human')`, device, org, user, node)
	policies := aigateway.NewPolicies(pool, nil, nil)
	if err := policies.ConfigureVPNIngress("internal.test", node.String(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	settings := &aiTransportStub{value: aitransport.Settings{AllowHTTP: false}}
	server := apiServer{aiPolicies: policies, aiTransport: settings}
	want := "https://internal.test/api/v1/organizations/" + org.String() + "/ai-gateway/inference/v1"
	ready := func() {
		t.Helper()
		endpoint, reason := server.userVPNEndpoint(ctx, org, user)
		if endpoint != want || reason != "" {
			t.Fatalf("legacy TLS endpoint=%q reason=%q", endpoint, reason)
		}
	}
	absent := func() {
		t.Helper()
		endpoint, err := policies.ManualVPNBaseURL(ctx, org, user)
		if err != nil || endpoint != "" {
			t.Fatalf("invalid TLS ownership advertised %q, %v", endpoint, err)
		}
	}
	// Existing TLS works with automatic deployment mode OFF and the saved HTTP
	// setting OFF, unavailable, or nil; no HTTP repository read is necessary.
	ready()
	if settings.calls.Load() != 0 {
		t.Fatal("TLS discovery read HTTP opt-in")
	}
	settings.failure = errors.New("HTTP settings unavailable")
	ready()
	server.aiTransport = nil
	ready()
	for _, ids := range [][2]uuid.UUID{{org, uuid.New()}, {uuid.New(), user}} {
		if endpoint, err := policies.ManualVPNBaseURL(ctx, ids[0], ids[1]); err != nil || endpoint != "" {
			t.Fatal("foreign identity advertised")
		}
	}
	for _, tc := range []struct {
		table, where, set, restore string
		id                         uuid.UUID
	}{
		{"nodes", "id", "status='revoked'", "status='active'", node},
		{"nodes", "id", "revoked_at=now()", "revoked_at=NULL", node},
		{"devices", "id", "status='revoked'", "status='active'", device},
		{"devices", "id", "health_blocked=true", "health_blocked=false", device},
		{"devices", "id", "deleted_at=now()", "deleted_at=NULL", device},
		{"devices", "id", "kind='agent'", "kind='human'", device},
		{"users", "id", "status='deactivated'", "status='active'", user},
		{"users", "id", "email_verified_at=NULL", "email_verified_at=now()", user},
		{"memberships", "user_id", "access_revoked_at=now()", "access_revoked_at=NULL", user},
		{"organizations", "id", "ai_gateway_enabled=false", "ai_gateway_enabled=true", org},
	} {
		t.Run(tc.table+tc.set, func(t *testing.T) {
			exec("UPDATE "+tc.table+" SET "+tc.set+" WHERE "+tc.where+"=$1", tc.id)
			absent()
			exec("UPDATE "+tc.table+" SET "+tc.restore+" WHERE "+tc.where+"=$1", tc.id)
		})
	}
	if err := policies.ConfigureVPNIngress("internal.test", uuid.NewString(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	absent()
	if err := policies.ConfigureVPNIngress("internal.test", node.String(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	ready()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if endpoint, reason := server.userVPNEndpoint(cancelled, org, user); endpoint != "" || reason != "transport_unavailable" {
		t.Fatal("failed discovery read guessed an endpoint")
	}
	server.aiPolicies = aigateway.NewPolicies(pool, nil, nil)
	if endpoint, reason := server.userVPNEndpoint(ctx, org, user); endpoint != "" || reason != "deployment_disabled" {
		t.Fatal("unconfigured TLS endpoint guessed")
	}
}
