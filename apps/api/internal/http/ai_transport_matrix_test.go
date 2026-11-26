package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AI-SEC-1 item 5: "HTTP inside the VPN" and "public HTTP" are separate
// switches. The VPN switch governs only the gateway relay route and the member
// VPN endpoint; the public switch governs only plaintext on public AI paths;
// HTTPS is never gated by either, and never depends on reading the policy.
func TestAITransportVPNAndPublicSwitchMatrix(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, node, user := uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(node[:])
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr,ai_gateway_enabled) VALUES($1,'Transport matrix',$2,'10.98.0.0/24',true)`, []any{org, org.String()}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,cert_delivered) VALUES($1,$2,'Matrix gateway',$3,true)`, []any{node, org, hex.EncodeToString(serial.Bytes())}},
		{`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, []any{user, user.String() + "@test.local"}},
		{`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, []any{org, user}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	policies := aigateway.NewPolicies(pool, nil, nil)
	policies.ConfigureAutomaticVPNIngress(true)
	adapter, err := aigateway.NewAdapter("http://127.0.0.1:1", func(context.Context, string, string) (aigateway.Grant, error) {
		return aigateway.Grant{}, errors.New("matrix requests never carry a valid credential")
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := &aiTransportStub{value: aitransport.Settings{Revision: 1}}

	// Gateway relay route: certificate-authenticated node channel.
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	channel.SetVPNInference(adapter, policies)
	channel.SetVPNHTTPTransport(settings)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	relay := httptest.NewUnstartedServer(channel.Handler())
	relay.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	relay.StartTLS()
	t.Cleanup(relay.Close)
	relayTransport := relay.Client().Transport.(*http.Transport).Clone()
	relayTransport.TLSClientConfig = relayTransport.TLSClientConfig.Clone()
	relayTransport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	t.Cleanup(relayTransport.CloseIdleConnections)
	relayClient := &http.Client{Transport: relayTransport}
	relayCall := func(path string) (int, string) {
		t.Helper()
		// The intentionally incomplete body reaches adapter validation (400)
		// only when the transport policy admits the request.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, relay.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tunnex-VPN-IP", "10.98.0.2")
		req.Header.Set("X-Tunnex-VPN-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		res, err := relayClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, string(body)
	}

	// Public AI paths: the real router, so middleware order is the shipped one.
	public, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AITransport: settings, AIAdapter: adapter, AIPolicies: policies, AppBaseURL: "https://console.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	publicPaths := []string{
		"/ai/v1/models",
		"/api/v1/workload/ai-credential",
		"/api/v1/agent/runtime/ai-credential",
		"/api/v1/organizations/" + org.String() + "/ai-gateway/providers",
	}
	publicCall := func(path string, secure bool) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://console.example.test"+path, nil)
		if secure {
			req = httptest.NewRequest(http.MethodGet, "https://console.example.test"+path, nil)
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		public.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	server := apiServer{aiPolicies: policies, aiTransport: settings}
	relayPaths := []string{"/agent/ai-http/organizations/" + org.String() + "/v1/chat/completions", "/agent/ai-http/v1/chat/completions"}

	for _, vpn := range []bool{false, true} {
		for _, pub := range []bool{false, true} {
			t.Run(fmt.Sprintf("vpn=%v public=%v", vpn, pub), func(t *testing.T) {
				settings.failure = nil
				settings.value = aitransport.Settings{AllowVPNHTTP: vpn, AllowHTTP: pub, Revision: 1}

				t.Run("relay route", func(t *testing.T) {
					for _, path := range relayPaths {
						code, body := relayCall(path)
						if vpn {
							if code != 400 || strings.Contains(body, "ai_vpn_http_disabled") || strings.Contains(body, "ai_https_required") {
								t.Fatalf("%s: VPN switch on but relay refused: %d %s", path, code, body)
							}
						} else if code != 403 || !strings.Contains(body, "ai_vpn_http_disabled") {
							t.Fatalf("%s: VPN switch off but relay answered: %d %s", path, code, body)
						}
					}
					// The member-facing endpoint follows the same switch.
					endpoint, reason := server.userVPNEndpoint(ctx, org, user)
					if endpoint != "" || (reason == "http_disabled") == vpn {
						t.Fatalf("member VPN endpoint=%q reason=%q", endpoint, reason)
					}
				})

				t.Run("public HTTP route", func(t *testing.T) {
					for _, path := range publicPaths {
						code, body := publicCall(path, false)
						refused := code == 403 && strings.Contains(body, "ai_https_required")
						if refused == pub {
							t.Fatalf("%s: public switch=%v but got %d %s", path, pub, code, body)
						}
						if strings.Contains(body, "ai_vpn_http_disabled") {
							t.Fatalf("%s: public route reported the VPN switch: %s", path, body)
						}
					}
				})

				t.Run("HTTPS route", func(t *testing.T) {
					for _, path := range publicPaths {
						if code, body := publicCall(path, true); strings.Contains(body, "ai_https_required") || strings.Contains(body, "ai_vpn_http_disabled") || strings.Contains(body, "ai_transport_settings_unavailable") {
							t.Fatalf("%s: HTTPS was gated: %d %s", path, code, body)
						}
					}
					// HTTPS admission never reads the HTTP policy, so it cannot
					// be gated by either switch or by a failing policy store.
					before := settings.calls.Load()
					settings.failure = errors.New("policy store unavailable")
					for _, path := range publicPaths {
						if code, body := publicCall(path, true); strings.Contains(body, "ai_https_required") || strings.Contains(body, "ai_transport_settings_unavailable") {
							t.Fatalf("%s: HTTPS depended on HTTP policy storage: %d %s", path, code, body)
						}
					}
					settings.failure = nil
					if settings.calls.Load() != before {
						t.Fatal("HTTPS admission read the HTTP policy")
					}
					// The configured private TLS relay route is HTTPS end to end
					// and ignores both switches.
					if code, body := relayCall("/agent/ai/v1/chat/completions"); code != 400 {
						t.Fatalf("TLS relay route was gated: %d %s", code, body)
					}
				})
			})
		}
	}
}
