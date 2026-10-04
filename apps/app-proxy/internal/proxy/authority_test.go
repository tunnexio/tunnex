package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func authorityFixture(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	leaf, ca := browserCertificates(t)
	cert, key := leaf(7, true)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	return server, &tls.Config{RootCAs: roots, ServerName: "tunnex-app-proxy"}
}
func testProxyCredential() string { return "tnxap_" + strings.Repeat("a", 43) }
func TestAuthorityClientTLSAndGeneratedPayload(t *testing.T) {
	var calls atomic.Int32
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS.Version != tls.VersionTLS13 || r.Method != "POST" || r.Header.Get("Authorization") != "AppProxy "+testProxyCredential() || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("invalid service admission metadata")
		}
		var body map[string]json.RawMessage
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
		}
		switch r.URL.Path {
		case "/internal/app-access/route-lookup":
			if len(body) != 1 || string(body["hostname"]) != `"app.apps.test"` {
				t.Errorf("lookup payload %s", body)
			}
			w.Write([]byte(`{"binding":{},"origin_url":"http://origin.test","allowed_destination_cidrs":[],"origin_ca_pem":"","origin_ca_digest":""}`))
		case "/internal/app-access/authorize":
			if len(body) != 3 || string(body["app_session_token"]) != `"opaque"` {
				t.Error("authorize payload")
			}
			var metadata map[string]string
			json.Unmarshal(body["request"], &metadata)
			if len(metadata) != 4 || metadata["method"] != "POST" || metadata["relative_path"] != "/form?q=1" || metadata["origin"] != "https://app.apps.test" || metadata["referer"] != "https://app.apps.test/page" {
				t.Error("metadata drift")
			}
			var binding map[string]any
			json.Unmarshal(body["binding"], &binding)
			if len(binding) != 9 || binding["authority_version"] != float64(3) || binding["purpose"] != "browser_proxy" {
				t.Error("binding drift")
			}
			w.Write([]byte(`{"stream_id":"stream","expires_at":"2099-01-01T00:00:00Z"}`))
		case "/internal/app-access/leases/renew":
			if len(body) != 2 || string(body["stream_id"]) != `"stream"` {
				t.Error("renew drift")
			}
			w.Write([]byte(`{"stream_id":"stream","expires_at":"2099-01-01T00:00:00Z"}`))
		case "/internal/app-access/channel-authorize":
			if len(body) != 2 || string(body["certificate_serial"]) != `"ab12"` {
				t.Error("channel drift")
			}
			w.Write([]byte(`{"expires_at":"2099-01-01T00:00:00Z"}`))
		default:
			t.Error("unexpected authority path")
			w.WriteHeader(404)
		}
	}))
	client, e := NewClient(server.URL, testProxyCredential(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer client.http.CloseIdleConnections()
	ctx := context.Background()
	if _, e = client.Lookup(ctx, "app.apps.test"); e != nil {
		t.Fatal(e)
	}
	b := Binding{OrgID: "org", AppID: "app", GatewayID: "gateway", Generation: "generation", Revision: 2, AuthorityVersion: 3, Digest: strings.Repeat("a", 64), Hostname: "app.apps.test", Purpose: "browser_proxy"}
	if _, e = client.Authorize(ctx, b, "opaque", Request{Method: "POST", RelativePath: "/form?q=1", Origin: "https://app.apps.test", Referer: "https://app.apps.test/page"}); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Renew(ctx, b, "stream"); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Channel(ctx, b, "ab12"); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 4 {
		t.Fatal("missing wire calls")
	}
	for _, bad := range []*tls.Config{{RootCAs: x509.NewCertPool(), ServerName: config.ServerName}, {RootCAs: config.RootCAs, ServerName: "wrong.test"}, {RootCAs: config.RootCAs, ServerName: config.ServerName, MaxVersion: tls.VersionTLS12}} {
		c, e := NewClient(server.URL, testProxyCredential(), bad)
		if e != nil {
			continue
		}
		if _, e = c.Lookup(ctx, "app.apps.test"); e == nil {
			t.Fatal("invalid TLS accepted")
		}
		c.http.CloseIdleConnections()
	}

	legacy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	legacy.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: server.TLS.Certificates}
	legacy.StartTLS()
	defer legacy.Close()
	legacyClient, e := NewClient(legacy.URL, testProxyCredential(), config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = legacyClient.Lookup(ctx, "app.apps.test"); e == nil {
		t.Fatal("TLS1.2-only authority accepted")
	}
	legacyClient.http.CloseIdleConnections()
	if calls.Load() != 4 {
		t.Fatal("TLS refusal reached handler")
	}
	if _, e = NewClient(server.URL, testProxyCredential(), &tls.Config{InsecureSkipVerify: true, RootCAs: config.RootCAs, ServerName: config.ServerName}); e == nil {
		t.Fatal("insecure fallback accepted")
	}
}
func TestAuthorityClientResponseFailClosed(t *testing.T) {
	for _, payload := range []string{`{`, `{"expires_at":"bad"}`, `{"expires_at":"2099-01-01T00:00:00Z","unexpected":true}`, `{"expires_at":"2099-01-01T00:00:00Z"} {}`, strings.Repeat(" ", 65537)} {
		t.Run("response", func(t *testing.T) {
			server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(payload)) }))
			c, e := NewClient(server.URL, testProxyCredential(), config)
			if e != nil {
				t.Fatal(e)
			}
			defer c.http.CloseIdleConnections()
			if _, e = c.Channel(context.Background(), Binding{}, "ab"); e == nil {
				t.Fatal("malformed or oversized response accepted")
			}
		})
	}
	var leaked atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer sink.Close()
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 307) }))
	c, e := NewClient(server.URL, testProxyCredential(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer c.http.CloseIdleConnections()
	if _, e = c.Lookup(context.Background(), "app.apps.test"); e == nil || leaked.Load() != 0 {
		t.Fatal("redirect followed or credential leaked")
	}
}
