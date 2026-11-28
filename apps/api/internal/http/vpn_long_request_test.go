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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// A VPN request that runs longer than two thirds of its authorization lease
// (when the adapter renews it) must complete on every relay route, streaming
// and not. The engine fixture holds its answer for more than two leases.
// Regression: the VPN identity check captured admission's context, which the
// adapter cancels once authorization returns, so every renewal failed and
// requests were cut at 2/3 of the lease (20 s live).
func TestVPNLongRequestsSurviveLeaseRenewal(t *testing.T) {
	restore := aigateway.SetGrantLeaseForTests(600 * time.Millisecond)
	defer restore()
	const hold = 1500 * time.Millisecond
	ctx, pool := testpostgres.New(t)
	org, node := uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(node[:])
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,ai_gateway_enabled) VALUES($1,'VPN long',$2,'10.99.0.0/24',true)`, org, org.String())
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,cert_delivered) VALUES($1,$2,'VPN gateway',$3,true)`, node, org, hex.EncodeToString(serial.Bytes()))
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
	if err := policies.ConfigureVPNIngress("vpn.example.test", node.String(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.PutUserModelGrant(ctx, org, user, group, connection, "openrouter/vpn", true, 0); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			deadline := time.Now().Add(hold)
			for i := 0; time.Now().Before(deadline); i++ {
				fmt.Fprintf(w, "data: {\"i\":%d}\n\n", i)
				w.(http.Flusher).Flush()
				select {
				case <-time.After(100 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
			io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"long answer"}}]}`)
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
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	post := func(path, body string) (int, string, error) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tunnex-VPN-IP", "10.99.0.2")
		r.Header.Set("X-Tunnex-VPN-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		res, err := client.Do(r)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return res.StatusCode, string(data), err
	}
	// A fresh ready report for the automatic HTTP route (as the gateway sends).
	if code, body, err := post("/agent/report", `{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","ai_vpn_http_ready":true,"ai_vpn_http_address":"10.99.0.1"}`); err != nil || code != 204 {
		t.Fatalf("ready report: %d %s %v", code, body, err)
	}
	exec(`UPDATE server_ai_transport_settings SET allow_vpn_http=true,revision=revision+1 WHERE singleton`)
	for _, route := range []string{
		"/agent/ai-http/v1/chat/completions",
		"/agent/ai-http/organizations/" + org.String() + "/v1/chat/completions",
		"/agent/ai/v1/chat/completions",
		"/agent/ai/organizations/" + org.String() + "/v1/chat/completions",
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s stream=%v", route, stream), func(t *testing.T) {
				body := `{"model":"openrouter/vpn","messages":[{"role":"user","content":"long"}]}`
				if stream {
					body = `{"model":"openrouter/vpn","messages":[{"role":"user","content":"long"}],"stream":true}`
				}
				start := time.Now()
				code, out, err := post(route, body)
				if err != nil || code != 200 {
					t.Fatalf("status=%d err=%v body=%.200s after %s", code, err, out, time.Since(start))
				}
				if stream && !strings.Contains(out, "[DONE]") || !stream && !strings.Contains(out, "long answer") {
					t.Fatalf("incomplete answer after %s: %.200s", time.Since(start), out)
				}
				if time.Since(start) < hold {
					t.Fatal("fixture did not hold the request past the lease")
				}
			})
		}
	}
	// Revocation still reaches a long request within one lease.
	go func() {
		time.Sleep(200 * time.Millisecond)
		exec(`UPDATE devices SET status='revoked' WHERE id=$1`, device)
	}()
	code, out, err := post("/agent/ai-http/v1/chat/completions", `{"model":"openrouter/vpn","messages":[{"role":"user","content":"long"}],"stream":true}`)
	if err == nil && code == 200 && strings.Contains(out, "[DONE]") {
		t.Fatal("revoked device's stream completed")
	}
}
