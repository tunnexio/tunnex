package http

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAppProxyAuthorityTLSIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") == "1" {
		password := os.Getenv("AA0_DB_PASSWORD")
		if password == "" {
			t.Fatal("owned password required")
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
		t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	}
	ctx, pool := testpostgres.New(t)
	var publications int
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM app_access_serving_publications").Scan(&publications); e != nil || publications != 0 {
		t.Fatalf("initial publication store not empty: %d %v", publications, e)
	}
	master := make([]byte, 32)
	if _, e := rand.Read(master); e != nil {
		t.Fatal(e)
	}
	sealer, e := crypto.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	ca, _, e := agentca.LoadOrCreate(ctx, sqlc.New(pool), sealer)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ca.ServerTLSCertificate("tunnex-app-authority")
	if e != nil {
		t.Fatal(e)
	}
	svc := appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	credential, secret, e := svc.IssueProxyCredential(ctx, "isolated HTTP authority test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(NewAppProxyAuthorityHandler(svc, func() bool { return true }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "tunnex-app-authority", MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	call := func(auth, hostname string) string {
		t.Helper()
		r, _ := http.NewRequest("POST", server.URL+"/internal/app-access/route-lookup", strings.NewReader(`{"hostname":"`+hostname+`"}`))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Cookie", "__Host-tunnex-session=human")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		want := 401
		if auth == "AppProxy "+secret {
			want = 404
		}
		if response.StatusCode != want {
			t.Fatalf("status %d wanted %d", response.StatusCode, want)
		}
		if strings.Contains(string(body), secret) {
			t.Fatal("secret echoed")
		}
		return string(body)
	}
	a := call("AppProxy "+secret, "unknown.apps.fixture.test")
	b := call("AppProxy "+secret, "another.apps.fixture.test")
	if a != b {
		t.Fatal("empty publication oracle")
	}
	call("Bearer "+secret, "unknown.apps.fixture.test")
	call("", "unknown.apps.fixture.test")
	call("AppProxy tnxap_"+strings.Repeat("a", 43), "unknown.apps.fixture.test")

	binding, _ := json.Marshal(appProxyBindingWire{OrgID: uuid.New(), AppID: uuid.New(), GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.fixture.test", Purpose: "browser_proxy"})
	for _, tc := range []struct{ path, body string }{
		{"authorize", `{"binding":` + string(binding) + `,"app_session_token":"opaque","request":{"method":"GET","relative_path":"/","origin":"","referer":""}}`},
		{"leases/renew", `{"binding":` + string(binding) + `,"stream_id":"` + uuid.NewString() + `"}`},
		{"channel-authorize", `{"binding":` + string(binding) + `,"certificate_serial":"abcd"}`},
	} {
		r, _ := http.NewRequest("POST", server.URL+"/internal/app-access/"+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "AppProxy "+secret)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatalf("closed %s returned %d", tc.path, response.StatusCode)
		}
	}
	if _, e := svc.RevokeProxyCredential(ctx, credential.ID, credential.Version); e != nil {
		t.Fatal(e)
	}
	r, _ := http.NewRequest("POST", server.URL+"/internal/app-access/route-lookup", strings.NewReader(`{"hostname":"unknown.apps.fixture.test"}`))
	r.Header.Set("Authorization", "AppProxy "+secret)
	response, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("revoked credential accepted")
	}
	downgrade := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "tunnex-app-authority", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}
	defer downgrade.CloseIdleConnections()
	if response, e := (&http.Client{Transport: downgrade}).Get(server.URL); e == nil {
		response.Body.Close()
		t.Fatal("TLS1.2 handshake accepted")
	}
}
