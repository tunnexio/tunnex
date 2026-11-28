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
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Static-key requests that run longer than two thirds of the authorization
// lease must complete on the internal endpoint (through the node mTLS agent
// channel) and on the public route, streaming and not; revoking the key
// mid-request still ends it within one lease.
func TestStaticKeyLongRequestsSurviveLeaseRenewal(t *testing.T) {
	restore := aigateway.SetGrantLeaseForTests(600 * time.Millisecond)
	defer restore()
	const hold = 1500 * time.Millisecond
	ctx, pool := testpostgres.New(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, node, owner, connection := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(node[:])
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,ai_gateway_enabled) VALUES($1,'Static long',$2,'10.98.0.0/24',true)`, org, org.String())
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,cert_delivered,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,true,'{"ai_internal_endpoint_version":1}',now())`, node, org, hex.EncodeToString(serial.Bytes()))
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, owner, owner.String()+"@test.local")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	exec(`INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,applied_revision,status) VALUES($1,$2,$3,'openrouter','Fixture',ARRAY['openrouter/sk'],true,1,1,'applied')`, connection, org, "tnx-managed-"+connection.String())
	exec(`INSERT INTO ai_static_key_settings(org_id,public_static_keys_allowed) VALUES($1,true)`, org)
	exec(`INSERT INTO ai_internal_endpoints(id,org_id,node_id,enabled,listen_addresses,source_cidrs) VALUES($1,$2,$3,true,'{10.9.0.1}','{10.20.0.0/16}')`, uuid.New(), org, node)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policies := aigateway.NewPolicies(pool, sealer, userAccessEngine{})
	workloads, err := aigateway.NewWorkloads(policies, "https://cp.example")
	if err != nil {
		t.Fatal(err)
	}
	workload, err := workloads.Put(ctx, org, owner, uuid.Nil, api.AIWorkloadInput{Name: "batch/long", Enabled: true, Models: []api.AIWorkloadModel{{ConnectionId: connection, Model: "openrouter/sk", Mode: "chat"}}})
	if err != nil || workload.Status != "applied" {
		t.Fatalf("workload: status=%s err=%v", workload.Status, err)
	}
	keys := aigateway.NewStaticKeys(workloads, nil)
	create := func(scope string) api.AIWorkloadStaticKeySecret {
		t.Helper()
		in := api.AIWorkloadStaticKeyInput{Name: "long-" + scope, Scope: api.AIWorkloadStaticKeyScope(scope), ExpiresAt: time.Now().Add(24 * time.Hour)}
		if scope == "public" {
			anySource := true
			in.AllowAnySource = &anySource
		}
		out, err := keys.Create(ctx, org, owner, workload.Id, in)
		if err != nil || out.Key.Status != "applied" {
			t.Fatalf("create %s key: status=%s err=%v", scope, out.Key.Status, err)
		}
		return out
	}
	internalKey, publicKey := create("internal"), create("public")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			for end := time.Now().Add(hold); time.Now().Before(end); {
				io.WriteString(w, "data: {}\n\n")
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
		t.Fatal("default closure reached")
		return aigateway.Grant{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Internal endpoint: the node mTLS agent channel.
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	channel.SetAIInternal(aigateway.NewInternalEndpoints(workloads, keys), adapter)
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	internalSrv := httptest.NewUnstartedServer(channel.Handler())
	internalSrv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	internalSrv.StartTLS()
	defer internalSrv.Close()
	transport := internalSrv.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: certKey}}
	defer transport.CloseIdleConnections()
	internalClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// Public route: the dedicated static-key middleware on an HTTPS transport.
	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), requestTransportKey{}, requestTransportState{secure: true, clientAddr: netip.MustParseAddr("203.0.113.9")}))
		staticKeyMiddleware(keys, adapter)(http.NotFoundHandler()).ServeHTTP(w, r)
	}))
	defer publicSrv.Close()
	publicClient := &http.Client{Timeout: 10 * time.Second}

	send := func(internal bool, stream bool) (int, string, error) {
		body := `{"model":"openrouter/sk","messages":[{"role":"user","content":"long"}]` + map[bool]string{true: `,"stream":true`}[stream] + `}`
		var r *http.Request
		client := publicClient
		if internal {
			r, _ = http.NewRequestWithContext(ctx, "POST", internalSrv.URL+"/agent/ai-key/v1/chat/completions", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+internalKey.Secret)
			r.Header.Set("X-Tunnex-Peer-IP", "10.20.1.5")
			client = internalClient
		} else {
			r, _ = http.NewRequestWithContext(ctx, "POST", publicSrv.URL+"/ai/v1/chat/completions", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+publicKey.Secret)
		}
		r.Header.Set("Content-Type", "application/json")
		res, err := client.Do(r)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return res.StatusCode, string(data), err
	}
	for _, internal := range []bool{true, false} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("internal=%v stream=%v", internal, stream), func(t *testing.T) {
				start := time.Now()
				code, out, err := send(internal, stream)
				want := "long answer"
				if stream {
					want = "[DONE]"
				}
				if err != nil || code != 200 || !strings.Contains(out, want) {
					t.Fatalf("status=%d err=%v body=%.200s after %s", code, err, out, time.Since(start))
				}
				if time.Since(start) < hold {
					t.Fatal("fixture did not hold the request past the lease")
				}
			})
		}
	}
	// Revoking the key mid-request ends it.
	for _, internal := range []bool{true, false} {
		t.Run(fmt.Sprintf("revoke internal=%v", internal), func(t *testing.T) {
			id := publicKey.Key.Id
			if internal {
				id = internalKey.Key.Id
			}
			go func() {
				time.Sleep(200 * time.Millisecond)
				exec(`UPDATE ai_workload_static_keys SET revoked_at=now() WHERE id=$1`, id)
			}()
			code, out, err := send(internal, true)
			if err == nil && code == 200 && strings.Contains(out, "[DONE]") {
				t.Fatal("revoked key's stream completed")
			}
		})
	}
}
