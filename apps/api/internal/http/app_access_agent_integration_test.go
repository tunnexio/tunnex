package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func appAccessCSR(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "caller-supplied-name-is-not-authority"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// Exercise actual CA-verified TLS and serial lookup against the same disposable
// migrated database as the browser test. Submitted diagnostic stages here test
// correlated gateway reporting, not real origin/network connectivity.
func exerciseAppAccessAgentHTTP(t *testing.T, ctx context.Context, pool *pgxpool.Pool, manager *licence.Manager, org, gateway, app uuid.UUID, login, prefix, detail string, call func(string, string, string, string, string, bool, int) []byte) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(master)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := agentca.LoadOrCreate(ctx, sqlc.New(pool), sealer)
	if err != nil {
		t.Fatal(err)
	}
	key, csr := appAccessCSR(t)
	issued, err := ca.SignCSR(csr, "aa-http-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE nodes SET cert_serial=$2,cert_not_after=$3 WHERE id=$1", gateway, issued.Serial, issued.NotAfter); err != nil {
		t.Fatal(err)
	}
	nodeService := nodes.NewService(pool, ca, sealer)
	channel := NewAgentChannel(nodeService, ca, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	channel.SetAppAccessConnector(appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}}), manager)
	defer channel.CloseAppAccessConnector()
	config, err := channel.TLSConfig("app-access-fixture")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(channel.Handler())
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	clientFor := func(certPEM string, key []byte) *http.Client {
		t.Helper()
		pair, err := tls.X509KeyPair([]byte(certPEM), key)
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "app-access-fixture", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport}
	}
	client := clientFor(issued.CertPEM, key)
	missingCertTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "app-access-fixture", MinVersion: tls.VersionTLS12}}
	defer missingCertTransport.CloseIdleConnections()
	if response, err := (&http.Client{Transport: missingCertTransport}).Get(server.URL + "/agent/app-access/desired-state"); err == nil {
		response.Body.Close()
		t.Fatal("mTLS admitted a caller without a certificate")
	}

	agentCall := func(client *http.Client, method, path, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("agent %s %s got%d want%d %s", method, path, response.StatusCode, want, raw)
		}
		return raw
	}
	unknownKey, unknownCSR := appAccessCSR(t)
	unknown, err := ca.SignCSR(unknownCSR, "aa-http-gateway")
	if err != nil {
		t.Fatal(err)
	}
	// Identical trusted CN cannot impersonate the database-owned current serial.
	agentCall(clientFor(unknown.CertPEM, unknownKey), "GET", "/agent/app-access/desired-state", "", 401)
	browserDesired := agentCall(client, "GET", "/agent/app-access/browser-desired-state", "", 200)
	var withdrawn struct {
		ProtocolVersion int               `json:"protocol_version"`
		Purpose         string            `json:"purpose"`
		Withdrawn       bool              `json:"withdrawn"`
		Assignments     []json.RawMessage `json:"assignments"`
	}
	if e := json.Unmarshal(browserDesired, &withdrawn); e != nil || withdrawn.ProtocolVersion != 1 || withdrawn.Purpose != "browser_proxy" || !withdrawn.Withdrawn || len(withdrawn.Assignments) != 0 {
		t.Fatalf("browser assignments escaped withdrawal: %s", browserDesired)
	}
	agentCall(client, "POST", "/agent/app-access/capability", `{"protocol_version":0}`, 200)
	call("POST", detail+"/checks", `{"expected_version":2}`, login, "", true, 409)
	agentCall(client, "POST", "/agent/app-access/capability", `{"protocol_version":1,"org_id":"forged"}`, 400)
	agentCall(client, "POST", "/agent/app-access/capability", `{"protocol_version":1}`, 200)
	call("GET", prefix+"/gateways/"+gateway.String()+"/status", "", login, "", false, 200)
	var check api.AppAccessCheck
	if err = json.Unmarshal(call("POST", detail+"/checks", `{"expected_version":2}`, login, "", true, 202), &check); err != nil {
		t.Fatal(err)
	}
	call("GET", detail+"/checks/"+check.Id.String(), "", login, "", false, 200)
	var desired appAccessDesiredWire
	if err = json.Unmarshal(agentCall(client, "GET", "/agent/app-access/desired-state", "", 200), &desired); err != nil || len(desired.Checks) != 1 || desired.Checks[0].Id != check.Id || desired.Checks[0].Status != "running" {
		t.Fatalf("exact desired state %v %#v", err, desired)
	}
	result := appAccessResultWire{RequestID: check.Id, Generation: check.Generation, AppID: app, Revision: check.Revision, Digest: check.Digest, Purpose: "origin_check", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "passed", ErrorCode: ""}
	body, _ := json.Marshal(result)
	agentCall(client, "POST", "/agent/app-access/checks/"+uuid.NewString()+"/result", string(body), 400)
	bad := result
	bad.Digest = strings.Repeat("b", 64)
	badBody, _ := json.Marshal(bad)
	agentCall(client, "POST", "/agent/app-access/checks/"+check.Id.String()+"/result", string(badBody), 409)
	// A second enrolled gateway may authenticate, but it cannot report another
	// gateway's exact assignment, even within the same organization.
	otherGateway := uuid.New()
	otherKey, otherCSR := appAccessCSR(t)
	otherIssued, err := ca.SignCSR(otherCSR, "other-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind,cert_not_after) VALUES($1,$2,'other-app-gateway',$3,'gateway',$4)", otherGateway, org, otherIssued.Serial, otherIssued.NotAfter); err != nil {
		t.Fatal(err)
	}
	otherClient := clientFor(otherIssued.CertPEM, otherKey)
	agentCall(otherClient, "POST", "/agent/app-access/capability", `{"protocol_version":1}`, 200)
	agentCall(otherClient, "POST", "/agent/app-access/checks/"+check.Id.String()+"/result", string(body), 409)
	agentCall(client, "POST", "/agent/app-access/checks/"+check.Id.String()+"/result", string(body), 200)
	agentCall(client, "POST", "/agent/app-access/checks/"+check.Id.String()+"/result", string(body), 409)
	newKey, newCSR := appAccessCSR(t)
	newCert := agentCall(client, "POST", "/agent/renew", string(newCSR), 200)
	agentCall(client, "GET", "/agent/app-access/desired-state", "", 401)
	rotated := clientFor(string(newCert), newKey)
	agentCall(rotated, "POST", "/agent/app-access/capability", `{"protocol_version":1}`, 200)
	agentCall(rotated, "GET", "/agent/app-access/desired-state", "", 200)
	if _, err = pool.Exec(ctx, "UPDATE nodes SET status='revoked' WHERE id=$1", gateway); err != nil {
		t.Fatal(err)
	}
	agentCall(rotated, "GET", "/agent/app-access/desired-state", "", 401)
	if _, err = pool.Exec(ctx, "UPDATE nodes SET status='active' WHERE id=$1", gateway); err != nil {
		t.Fatal(err)
	}
}
