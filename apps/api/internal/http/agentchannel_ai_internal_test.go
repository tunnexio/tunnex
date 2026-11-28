package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type internalTestEngine struct{}

func (internalTestEngine) EnsureKey(context.Context, string, string, []string, []string) (aigateway.EngineKey, error) {
	return aigateway.EngineKey{}, nil
}
func (internalTestEngine) DisableKey(context.Context, string) error { return nil }
func (internalTestEngine) Price(context.Context, string, string) (aigateway.Price, error) {
	return aigateway.Price{}, nil
}
func (internalTestEngine) Usage(context.Context, []string, time.Time, time.Time) (aigateway.Usage, error) {
	return aigateway.Usage{}, nil
}

type internalHarness struct {
	*mcpfixture.Fixture
	t         *testing.T
	handler   http.Handler
	endpoints *aigateway.InternalEndpoints
	kicked    []uuid.UUID
}

const internalNodeSerial, otherNodeSerial = 0x616931, 0x616932

func newInternalHarness(t *testing.T) *internalHarness {
	t.Helper()
	f := mcpfixture.New(t)
	f.Exec(`UPDATE nodes SET cert_serial=$2 WHERE id=$1`, f.Node, hex.EncodeToString(big.NewInt(internalNodeSerial).Bytes()))
	f.Exec(`UPDATE nodes SET cert_serial=$2 WHERE id=$1`, f.OtherNode, hex.EncodeToString(big.NewInt(otherNodeSerial).Bytes()))
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workloads, err := aigateway.NewWorkloads(aigateway.NewPolicies(f.Pool, sealer, internalTestEngine{}), "https://cp.example")
	if err != nil {
		t.Fatal(err)
	}
	keys := aigateway.NewStaticKeys(workloads, nil)
	h := &internalHarness{Fixture: f, t: t, endpoints: aigateway.NewInternalEndpoints(workloads, keys)}
	h.endpoints.SetKick(func(_ context.Context, node uuid.UUID) { h.kicked = append(h.kicked, node) })
	adapter, err := aigateway.NewAdapter("http://127.0.0.1:1", func(context.Context, string, string) (aigateway.Grant, error) {
		t.Fatal("default closure reached")
		return aigateway.Grant{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	channel := NewAgentChannel(nodes.NewService(f.Pool, nil, nil), nil, nil, nil)
	channel.SetAIInternal(h.endpoints, adapter)
	h.handler = channel.Handler()
	return h
}

func (h *internalHarness) do(serial int64, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, "https://control"+path, strings.NewReader(body)).WithContext(h.Ctx)
	if serial != 0 {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(serial)}}}
	}
	for name, values := range headers {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

func (h *internalHarness) supported(node uuid.UUID) {
	h.Exec(`UPDATE nodes SET capabilities=coalesce(capabilities,'{}'::jsonb)||'{"ai_internal_endpoint_version":1}'::jsonb,policy_reported_at=now() WHERE id=$1`, node)
}

func (h *internalHarness) put(node uuid.UUID, in api.AIInternalEndpointInput) (api.AIInternalEndpoint, error) {
	return h.endpoints.Put(h.Ctx, h.Org, h.Owner, node, in)
}

func apiCode(err error) string {
	if e, ok := err.(*apierr.Error); ok {
		return e.Code
	}
	return ""
}

func TestAIInternalEndpointConfigurationAndDesiredState(t *testing.T) {
	h := newInternalHarness(t)
	in := api.AIInternalEndpointInput{Enabled: true, ListenAddresses: []string{"10.123.0.1"}, Port: 9443, SourceCidrs: []string{"10.20.0.0/16"}, TlsMode: "tunnex_ca"}
	if _, err := h.put(h.Node, in); apiCode(err) != "ai_internal_endpoint_unsupported" {
		t.Fatalf("old gateway configured: %v", err)
	}
	h.supported(h.Node)
	bad := in
	bad.ListenAddresses = []string{"192.168.50.5"}
	if _, err := h.put(h.Node, bad); apiCode(err) != "ai_internal_endpoint_address_unapproved" {
		t.Fatalf("unapproved LAN address accepted: %v", err)
	}
	for _, cidrs := range [][]string{{"0.0.0.0/0"}, {"8.8.8.0/24"}, {"10.0.0.1/8"}, {}} {
		bad := in
		bad.SourceCidrs = cidrs
		if _, err := h.put(h.Node, bad); apiCode(err) != "invalid_ai_internal_endpoint" {
			t.Fatalf("bad ranges %v accepted: %v", cidrs, err)
		}
	}
	for _, port := range []int{8083, 8084, 80} {
		bad := in
		bad.Port = port
		if _, err := h.put(h.Node, bad); apiCode(err) != "invalid_ai_internal_endpoint" {
			t.Fatalf("port %d accepted", port)
		}
	}
	out, err := h.put(h.Node, in)
	if err != nil || out.Endpoint == nil || out.Endpoint.Revision != 1 || out.Url == nil || *out.Url != "https://10.123.0.1:9443/v1" || !out.Supported || out.Ready {
		t.Fatalf("configure: %+v %v", out, err)
	}
	if len(h.kicked) != 1 || h.kicked[0] != h.Node {
		t.Fatal("saved change did not wake the gateway")
	}
	if _, err = h.put(h.Node, in); err == nil {
		t.Fatal("stale revision accepted")
	}
	if h.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ai_gateway.internal_endpoint_changed'`, h.Org) != 1 {
		t.Fatal("endpoint audit missing")
	}
	var doc aigateway.InternalDesiredState
	w := h.do(internalNodeSerial, "GET", "/agent/ai-internal/desired-state", "", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &doc) != nil || doc.Version != 1 || doc.Endpoint == nil || doc.Endpoint.Port != 9443 || doc.Endpoint.SourceCIDRs[0] != "10.20.0.0/16" || doc.Endpoint.TLSMode != "tunnex_ca" {
		t.Fatalf("desired state: %d %s", w.Code, w.Body.String())
	}
	w = h.do(otherNodeSerial, "GET", "/agent/ai-internal/desired-state", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"endpoint":null`) {
		t.Fatalf("other gateway sees an endpoint: %s", w.Body.String())
	}
	if w = h.do(0, "GET", "/agent/ai-internal/desired-state", "", nil); w.Code != 401 {
		t.Fatal("desired state without a node certificate")
	}
	// The gateway reports readiness as typed fields; the list shows ready.
	report := `{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","ai_internal_endpoint_version":1,"ai_internal_endpoint_ready":true,"ai_internal_endpoint_addresses":["10.123.0.1"],"ai_internal_endpoint_port":9443,"ai_internal_endpoint_revision":1,"ai_internal_endpoint_cert_sha256":"` + strings.Repeat("ab", 32) + `","ai_internal_endpoint_cert_not_after":"2027-01-01T00:00:00Z","unknown_field":"x"}`
	if w = h.do(internalNodeSerial, "POST", "/agent/report", report, nil); w.Code != 204 {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	h.Exec(`UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, h.Node)
	items, err := h.endpoints.List(h.Ctx, h.Org)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.NodeId == h.Node && (!item.Ready || item.CertificateSha256 == nil || item.CertificateNotAfter == nil) {
			t.Fatalf("reported readiness not shown: %+v", item)
		}
		if item.NodeId == h.OtherNode && (item.Supported || item.Endpoint != nil) {
			t.Fatal("other gateway reported as supported")
		}
	}
	if h.Count(`SELECT count(*) FROM nodes WHERE id=$1 AND capabilities ? 'unknown_field'`, h.Node) != 0 {
		t.Fatal("unknown report field stored")
	}
	bogus := `{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","ai_internal_endpoint_version":1,"ai_internal_endpoint_ready":true,"ai_internal_endpoint_addresses":["8.8.8.8"],"ai_internal_endpoint_port":9443}`
	if w = h.do(internalNodeSerial, "POST", "/agent/report", bogus, nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if h.Count(`SELECT count(*) FROM nodes WHERE id=$1 AND (capabilities->>'ai_internal_endpoint_ready')::boolean`, h.Node) != 0 {
		t.Fatal("public listen address reported as ready")
	}
	// Disabled: the document is null and the CP refuses at once.
	in.Enabled, in.ExpectedRevision = false, 1
	if _, err = h.put(h.Node, in); err != nil {
		t.Fatal(err)
	}
	if w = h.do(internalNodeSerial, "GET", "/agent/ai-internal/desired-state", "", nil); !strings.Contains(w.Body.String(), `"endpoint":null`) {
		t.Fatal("disabled endpoint still served")
	}
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"evil.example"}, IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestAIInternalCertificateSignsOnlyConfiguredSANs(t *testing.T) {
	h := newInternalHarness(t)
	h.supported(h.Node)
	name := "ai.internal.example"
	if _, err := h.put(h.Node, api.AIInternalEndpointInput{Enabled: true, ListenAddresses: []string{"10.123.0.1"}, Port: 9443, DnsName: &name, SourceCidrs: []string{"10.20.0.0/16"}, TlsMode: "tunnex_ca"}); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body, _ := json.Marshal(map[string]string{"csr_pem": csrFor(t, key)})
	w := h.do(internalNodeSerial, "POST", "/agent/ai-internal/certificate", string(body), nil)
	var out aigateway.InternalCertificate
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.123.0.1" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || leaf.NotAfter.After(time.Now().Add(30*24*time.Hour+time.Minute)) || !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatalf("leaf: ips=%v dns=%v ca=%v", leaf.IPAddresses, leaf.DNSNames, leaf.IsCA)
	}
	ca, err := h.endpoints.CA(h.Ctx, h.Org)
	if err != nil || ca.CertificatePem != out.ChainPEM {
		t.Fatalf("chain is not the organization CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca.CertificatePem))
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.example"}); err == nil {
		t.Fatal("CSR SAN was signed")
	}
	if h.Count(`SELECT count(*) FROM ai_internal_cas WHERE org_id=$1 AND sealed_key NOT LIKE '%PRIVATE%'`, h.Org) != 1 {
		t.Fatal("CA key not sealed")
	}
	if w = h.do(otherNodeSerial, "POST", "/agent/ai-internal/certificate", string(body), nil); w.Code != 409 {
		t.Fatalf("gateway without an endpoint got a certificate: %d", w.Code)
	}
	if w = h.do(internalNodeSerial, "POST", "/agent/ai-internal/certificate", `{"csr_pem":"garbage"}`, nil); w.Code != 400 {
		t.Fatalf("garbage CSR: %d", w.Code)
	}
}

func TestAIKeyRouteChecksPeerEndpointAndCredential(t *testing.T) {
	h := newInternalHarness(t)
	h.supported(h.Node)
	if _, err := h.put(h.Node, api.AIInternalEndpointInput{Enabled: true, ListenAddresses: []string{"10.123.0.1"}, Port: 9443, SourceCidrs: []string{"10.20.0.0/16"}, TlsMode: "tunnex_ca"}); err != nil {
		t.Fatal(err)
	}
	key := "Bearer tnx_sk_0123456789abcdefghijABCDEFGHIJ0123456789abcdeXXXXXX"
	headers := func(peer ...string) http.Header {
		v := http.Header{"Authorization": {key}, "Content-Type": {"application/json"}}
		for _, p := range peer {
			v.Add("X-Tunnex-Peer-IP", p)
		}
		return v
	}
	body := `{"model":"openrouter/a","messages":[{"role":"user","content":"hi"}]}`
	for _, c := range []struct {
		name    string
		serial  int64
		method  string
		path    string
		headers http.Header
		status  int
	}{
		{"no certificate", 0, "POST", "/agent/ai-key/v1/chat/completions", headers("10.20.1.5"), 401},
		{"no peer", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", headers(), 403},
		{"two peers", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", headers("10.20.1.5", "10.20.1.6"), 403},
		{"peer outside ranges", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", headers("10.30.0.1"), 403},
		{"peer not IPv4", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", headers("fd00::1"), 403},
		{"gateway without endpoint", otherNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", headers("10.20.1.5"), 403},
		{"workload token", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", http.Header{"Authorization": {"Bearer tnx_wai_x"}, "X-Tunnex-Peer-IP": {"10.20.1.5"}}, 401},
		{"api key off the messages route", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions", http.Header{"X-Api-Key": {strings.TrimPrefix(key, "Bearer ")}, "X-Tunnex-Peer-IP": {"10.20.1.5"}}, 401},
		{"videos", internalNodeSerial, "POST", "/agent/ai-key/v1/videos", headers("10.20.1.5"), 404},
		{"query string", internalNodeSerial, "POST", "/agent/ai-key/v1/chat/completions?x=1", headers("10.20.1.5"), 400},
		{"models wrong method", internalNodeSerial, "POST", "/agent/ai-key/v1/models", headers("10.20.1.5"), 404},
	} {
		w := h.do(c.serial, c.method, c.path, body, c.headers)
		if w.Code != c.status {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
	}
}
