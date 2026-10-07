package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This explicitly invoked qualification uses real durable authority and binaries.
// Every identity/database is owned by this fixture, separate from the local CP.
func TestBeamNativePersistentJourney(t *testing.T) {
	if os.Getenv("BEAM_NATIVE_INTEGRATION") != "1" {
		t.Skip("set BEAM_NATIVE_INTEGRATION=1 with the built proxy and client checkout")
	}
	if os.Getenv("TUNNEX_TEST_DATABASE_URL") == "" {
		t.Fatal("Native integration requires an explicit owned PostgreSQL admin endpoint")
	}
	binary := os.Getenv("BEAM_PROXY_BINARY")
	clientPath := os.Getenv("BEAM_CLIENT_WORKTREE")
	node := os.Getenv("BEAM_NODE_BINARY")
	if node == "" {
		node = "node"
	}
	if binary == "" || clientPath == "" {
		t.Fatal("BEAM_PROXY_BINARY and BEAM_CLIENT_WORKTREE are required once native integration is invoked")
	}
	if _, e := os.Stat(binary); e != nil {
		t.Fatal("Built native Beam proxy required")
	}
	for _, withdrawal := range []string{"stop", "pause", "expiry", "grant-removal", "reviewer-logout", "reviewer-membership", "reviewer-group", "publisher-group", "publisher-credential", "policy-disable", "policy-mfa", "fresh-generation", "restore-barrier", "supported-restore", "authority-down", "installation-disable", "installation-domain", "readiness-failed", "readiness-expired", "session-store-down", "proxy-restart", "publisher-status", "publisher-role", "publisher-credential-expiry", "organization-deleted", "reviewer-parent-expiry", "reviewer-auth-epoch", "mfa-freshness", "mfa-future-proof", "authority-clock-ahead", "authority-clock-behind"} {
		t.Run(withdrawal, func(t *testing.T) { beamNativeJourney(t, binary, clientPath, node, withdrawal) })
	}
}
func beamNativeJourney(t *testing.T, binary, clientPath, node, withdrawal string) {
	ctx, pool := testpostgres.New(t)
	owned, e := os.MkdirTemp("/private/tmp", "beam-native-authority-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(owned) })
	if e = os.Chmod(owned, 0700); e != nil {
		t.Fatal(e)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(owned, name)
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	org, publisher, reviewer, group, credential := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	query := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	query(`INSERT INTO organizations(id,name,slug)VALUES($1,'Native Beam fixture',$2)`, org, org.String())
	for _, id := range []uuid.UUID{publisher, reviewer} {
		query(`INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Native fixture',now())`, id, id.String()+"@beam.native")
		role := "member"
		if id == publisher {
			role = "owner"
		}
		query(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,$3)`, org, id, role)
	}
	query(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Native publishers')`, group, org)
	query(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, org, group, publisher)
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	humanToken := "tnx_" + base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(humanToken))
	query(`INSERT INTO cli_credentials(id,user_id,token_hash,fingerprint,expires_at)VALUES($1,$2,$3,'native-fixture',now()+interval '1 hour')`, credential, publisher, tokenHash[:])
	master := make([]byte, crypto.KeySize)
	_, _ = rand.Read(master)
	seal, e := crypto.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	ca, _, e := agentca.LoadOrCreate(ctx, sqlc.New(pool), seal)
	if e != nil {
		t.Fatal(e)
	}
	rdb := miniredis.RunT(t)
	sessions := session.NewWithClient(redis.NewClient(&redis.Options{Addr: rdb.Addr()}), time.Hour, time.Hour)
	reviewSession, e := sessions.CreateWithAuthority(ctx, reviewer, "local_password", 1)
	if e != nil {
		t.Fatal(e)
	}
	if withdrawal == "mfa-freshness" || withdrawal == "mfa-future-proof" {
		reviewSession, e = sessions.CreateWithMFAAuthority(ctx, reviewer, "local_password", 1, time.Now(), session.MFAAssuranceLocalTOTP)
		if e != nil {
			t.Fatal(e)
		}
	}
	publicAddress := nativeAddress(t)
	connectorAddress := nativeAddress(t)
	if os.Getenv("BEAM_NATIVE_CONNECTOR_443") == "1" {
		connectorAddress = "[::1]:443"
	}
	service := beam.New(pool, beam.Config{BaseDomain: "beam.example.net", PortalURL: "https://console.other.org", ProxyURL: "https://" + connectorAddress, DomainReady: true, RestoreMarker: filepath.Join(owned, "restore.pending")}, ca, sessions)
	query(`UPDATE beam_installation_settings SET configured=true,operator_enabled=true,base_domain='beam.example.net',proxy_url=$1,portal_url='https://console.other.org' WHERE singleton`, "https://"+connectorAddress)
	readiness, e := service.GetDomainReadiness(ctx)
	if e != nil {
		t.Fatal(e)
	}
	query(`UPDATE beam_installation_settings SET readiness_version=$1,readiness_passed=true,readiness_checked_at=now(),readiness_expires_at=now()+interval '5 minutes' WHERE singleton`, readiness.ConfigurationVersion)
	owner := beam.Actor{ID: publisher, CredentialID: credential, ManageAll: true, ManagePolicy: true}
	browserOwner := owner
	browserOwner.CredentialID = uuid.Nil
	browserOwner.SessionID = "fixture-admin"
	policyInput := beam.PolicyInput{RequireMFA: withdrawal == "mfa-freshness" || withdrawal == "mfa-future-proof", Enabled: true, ExpectedVersion: 1, PublisherGroups: []uuid.UUID{group}, ReviewerUsers: []uuid.UUID{reviewer}, MaxDuration: 3600, MaxShares: 5}
	if withdrawal == "reviewer-group" {
		query(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, org, group, reviewer)
		policyInput.ReviewerUsers = nil
		policyInput.ReviewerGroups = []uuid.UUID{group}
	}
	_, e = service.UpdatePolicy(ctx, org, browserOwner, policyInput)
	if e != nil {
		t.Fatal(e)
	}
	appAccess := appaccess.NewService(pool, appaccess.Config{})
	_, proxyCredential, e := appAccess.IssueProxyCredential(ctx, "native Beam fixture")
	if e != nil {
		t.Fatal(e)
	}
	var authorityClockOffset atomic.Int64
	authorityHandler := NewBeamProxyAuthorityHandler(service, appAccess, http.NotFoundHandler())
	authority := httptest.NewUnstartedServer(nativeSkewedLeaseHandler(authorityHandler, &authorityClockOffset))
	authorityLeaf, e := ca.ServerTLSCertificate("tunnex-app-authority")
	if e != nil {
		t.Fatal(e)
	}
	authority.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{authorityLeaf}, NextProtos: []string{"http/1.1"}}
	authority.StartTLS()
	t.Cleanup(authority.Close)
	apiHandler, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Beam: service, AuthFn: SessionAuth(sessions, sqlc.New(pool)), BearerFn: BearerAuth(sqlc.New(pool))})
	if e != nil {
		t.Fatal(e)
	}
	apiServer := httptest.NewServer(apiHandler)
	t.Cleanup(apiServer.Close)
	publicCert, e := ca.ServerTLSCertificate("*.beam.example.net")
	if e != nil {
		t.Fatal(e)
	}
	connectorCert, e := ca.ServerTLSCertificate("tunnex-beam-proxy")
	if e != nil {
		t.Fatal(e)
	}
	publicCertPath, publicKeyPath := nativePair(t, write, "public", publicCert)
	connectorCertPath, connectorKeyPath := nativePair(t, write, "connector", connectorCert)
	caPath := write("ca.pem", ca.CertPEM())
	credentialPath := write("proxy-credential", []byte(proxyCredential))
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "TUNNEX_BEAM_PROXY_PUBLIC_ADDR="+publicAddress, "TUNNEX_BEAM_PROXY_CONNECTOR_ADDR="+connectorAddress, "TUNNEX_BEAM_PROXY_TLS_CERT_FILE="+publicCertPath, "TUNNEX_BEAM_PROXY_TLS_KEY_FILE="+publicKeyPath, "TUNNEX_BEAM_PROXY_CONNECTOR_TLS_CERT_FILE="+connectorCertPath, "TUNNEX_BEAM_PROXY_CONNECTOR_TLS_KEY_FILE="+connectorKeyPath, "TUNNEX_BEAM_PROXY_CONNECTOR_CA_FILE="+caPath, "TUNNEX_BEAM_PROXY_AUTHORITY_URL="+authority.URL, "TUNNEX_BEAM_PROXY_AUTHORITY_SERVER_NAME=tunnex-app-authority", "TUNNEX_BEAM_PROXY_AUTHORITY_CA_FILE="+caPath, "TUNNEX_BEAM_PROXY_CREDENTIAL_FILE="+credentialPath, "TUNNEX_BEAM_PROXY_BASE_DOMAIN=beam.example.net", "TUNNEX_BEAM_PROXY_CONSOLE_BASE_URL=https://console.other.org", "TUNNEX_BEAM_PROXY_RESTORE_MARKER="+filepath.Join(owned, "restore.pending"))
	var proxyLog nativeLog
	command.Stdout = &proxyLog
	command.Stderr = &proxyLog
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		if strings.Contains(proxyLog.String(), humanToken) || strings.Contains(proxyLog.String(), proxyCredential) || strings.Contains(proxyLog.String(), "PRIVATE KEY") {
			t.Error("Native proxy leaked fixture credential")
		}
	})
	// Node creates the real fixed-loopback app and runs the shipping native connector.
	script := write("native-connector.cjs", []byte(nativeNodeScript))
	optionsPath := filepath.Join(owned, "options.json")
	child := exec.Command(node, "--require", "ts-node/register", script)
	child.Dir = filepath.Join(clientPath, "apps/client")
	child.Env = append(os.Environ(), "BEAM_NATIVE_CLIENT="+clientPath, "BEAM_NATIVE_OPTIONS="+optionsPath)
	stdout, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var nodeLog nativeLog
	child.Stderr = &nodeLog
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = child.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = child.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = child.Process.Kill()
			<-done
		}
		if strings.Contains(nodeLog.String(), humanToken) || strings.Contains(nodeLog.String(), "PRIVATE KEY") {
			t.Error("Native connector leaked fixture credential")
		}
	})
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	var appPort int
	select {
	case line := <-lines:
		var result struct {
			Port int `json:"port"`
		}
		if e = json.Unmarshal([]byte(line), &result); e != nil || result.Port < 1 {
			t.Fatal("Native app port handshake invalid")
		}
		appPort = result.Port
	case <-time.After(10 * time.Second):
		t.Fatal("Native app did not start")
	}
	create := beam.CreateInput{Name: "Native app", Target: beam.Target{Protocol: "http", Address: "127.0.0.1", Port: appPort}, Duration: 600, Grants: []beam.Grant{{SubjectKind: "user", SubjectID: reviewer}}, IdempotencyKey: uuid.New()}
	if withdrawal == "reviewer-group" {
		create.Grants = []beam.Grant{{SubjectKind: "group", SubjectID: group}}
	}
	var share beam.Share
	nativeAPI(t, apiServer.URL, org, "shares", humanToken, "", create, &share)
	connectorKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "native connector fixture"}}, connectorKey)
	if e != nil {
		t.Fatal(e)
	}
	var connector beam.Connector
	nativeAPI(t, apiServer.URL, org, "shares/"+share.ID.String()+"/connector", humanToken, "", beam.ConnectorInput{ExpectedVersion: share.Version, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}, &connector)
	keyDER, e := x509.MarshalPKCS8PrivateKey(connectorKey)
	if e != nil {
		t.Fatal(e)
	}
	b := connector.Binding
	foreign, e := ca.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), "beam:foreign-native-fixture")
	if e != nil {
		t.Fatal(e)
	}
	options := map[string]any{"foreignCertificatePEM": foreign.CertPEM, "proxyUrl": connector.ProxyURL, "proxyServerName": connector.ProxyServerName, "binding": map[string]any{"orgId": b.OrgID, "connectorId": b.GatewayID, "shareId": b.AppID, "generation": b.Generation, "revision": b.Revision, "targetDigest": b.Digest, "hostname": b.Hostname, "authorityVersion": b.AuthorityVersion}, "target": create.Target, "identity": map[string]string{"ca": connector.CAPEM, "cert": connector.CertificatePEM, "key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}}
	nativeWaitListener(t, connectorAddress)
	payload, _ := json.Marshal(options)
	write("options.json", payload)
	select {
	case line := <-lines:
		if line != "connector_started" {
			t.Fatal("Native connector start handshake invalid")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Native connector did not begin")
	}
	shareID := share.ID
	heartbeatCtx, cancelHeartbeat := context.WithCancel(context.Background())
	defer cancelHeartbeat()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				_, _ = service.Heartbeat(heartbeatCtx, org, shareID, owner, beam.Heartbeat{Generation: b.Generation, OriginReady: true})
			}
		}
	}()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		current, e := service.Get(ctx, org, share.ID, owner)
		if e == nil && current.State == "active" && current.Connectivity == "online" {
			share = current
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if share.State != "active" {
		t.Fatalf("Native connector never reached durable Live: %s", proxyLog.String())
	}
	client := nativePublicClient(ca.Pool(), share.Hostname, publicAddress)
	t.Cleanup(client.CloseIdleConnections)
	response, e := client.Get(share.URL + "/_beam/start?target=%2F")
	if e != nil {
		t.Fatal(e)
	}
	_ = response.Body.Close()
	if response.StatusCode != 302 && response.StatusCode != 303 {
		t.Fatalf("native pending launch status%d body%s", response.StatusCode, proxyLog.String())
	}
	redirect, e := url.Parse(response.Header.Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	var launch beam.Launch
	nativeAPI(t, apiServer.URL, org, "shares/"+share.ID.String()+"/launch", "", reviewSession.ID, beam.LaunchInput{RelativeTarget: "/", NonceHash: redirect.Query().Get("nonce_hash")}, &launch)
	req, _ := http.NewRequest("GET", launch.RedirectURL, nil)
	for _, cookie := range response.Cookies() {
		req.AddCookie(cookie)
	}
	redeem, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = redeem.Body.Close()
	if redeem.StatusCode != 303 && redeem.StatusCode != 302 {
		t.Fatalf("native redemption status%d", redeem.StatusCode)
	}
	var appCookie *http.Cookie
	for _, cookie := range redeem.Cookies() {
		if cookie.Value != "" {
			appCookie = cookie
		}
	}
	if appCookie == nil {
		t.Fatal("native browser session not issued")
	}
	get := func(path string, headers http.Header) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", share.URL+path, nil)
		req.AddCookie(appCookie)
		for k, v := range headers {
			req.Header[k] = v
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return res
	}
	page := get("/", nil)
	html, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != 200 || !bytes.Contains(html, []byte("Your local app is reaching the browser")) {
		t.Fatalf("native HTTP failed %d", page.StatusCode)
	}
	headers := http.Header{"Cookie": []string{appCookie.Name + "=" + appCookie.Value + "; tunnex_session=secret; app_theme=green"}, "Authorization": []string{"Bearer " + humanToken}, "X-Tunnex-User": []string{"spoof"}, "X-Forwarded-For": []string{"spoof"}}
	inspect := get("/headers", headers)
	var seen map[string]string
	if e = json.NewDecoder(inspect.Body).Decode(&seen); e != nil {
		t.Fatal(e)
	}
	_ = inspect.Body.Close()
	if seen["authorization"] != "" || seen["x-tunnex-user"] != "" || seen["x-forwarded-for"] != "" || strings.Contains(seen["cookie"], "secret") || strings.Contains(seen["cookie"], appCookie.Value) || seen["host"] != share.Hostname {
		t.Fatal("native origin received Tunnex authority or wronghost")
	}
	if !strings.Contains(seen["cookie"], "app_theme=green") {
		t.Fatal("native application cookie was stripped")
	}
	download := get("/native-download", nil)
	if download.StatusCode != 200 || download.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatal("native long HTTP transfer was not admitted")
	}
	firstChunk := make([]byte, 4)
	if _, e = io.ReadFull(download.Body, firstChunk); e != nil || string(firstChunk) != "beam" {
		t.Fatal("native HTTP transfer never started", e)
	}
	httpClosed := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, download.Body); _ = download.Body.Close(); close(httpClosed) }()
	sse := get("/events", nil)
	if sse.StatusCode != 200 {
		t.Fatalf("native SSE status%d", sse.StatusCode)
	}
	sseReader := bufio.NewReader(sse.Body)
	line, e := sseReader.ReadString('\n')
	if e != nil || !strings.HasPrefix(line, "data: local-") {
		t.Fatal("native SSE not live", e)
	}
	sseClosed := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, sseReader); _ = sse.Body.Close(); close(sseClosed) }()
	websocket := nativeWebsocket(t, ca.Pool(), share.Hostname, publicAddress, appCookie)
	defer websocket.Close()
	echo := []byte("native-review")
	mask := []byte{1, 2, 3, 4}
	masked := append([]byte{}, echo...)
	for i := range masked {
		masked[i] ^= mask[i%4]
	}
	frame := append([]byte{0x81, 0x80 | byte(len(echo))}, mask...)
	_, e = websocket.Write(append(frame, masked...))
	if e != nil {
		t.Fatal(e)
	}
	received := make([]byte, 2+len(echo))
	if _, e = io.ReadFull(websocket, received); e != nil || !bytes.Equal(received[2:], echo) {
		t.Fatal("native WebSocket echo failed", e)
	}
	wsClosed := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, websocket); close(wsClosed) }()
	started := time.Now()
	var recoveryDone chan error
	switch withdrawal {
	case "stop", "pause":
		current, e := service.Get(ctx, org, share.ID, owner)
		if e != nil {
			t.Fatal(e)
		}
		_, e = service.Action(ctx, org, share.ID, owner, beam.ActionInput{Action: withdrawal, ExpectedVersion: current.Version})
		if e != nil {
			t.Fatal(e)
		}
	case "expiry":
		query(`UPDATE beam_shares SET expires_at=now() WHERE org_id=$1 AND id=$2`, org, share.ID)
	case "grant-removal":
		query(`DELETE FROM beam_grants WHERE org_id=$1 AND share_id=$2 AND subject_id=$3`, org, share.ID, reviewer)
	case "reviewer-logout":
		if e = sessions.Delete(ctx, reviewSession.ID); e != nil {
			t.Fatal(e)
		}
	case "reviewer-membership":
		query(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, org, reviewer)
	case "reviewer-group":
		query(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, reviewer)
	case "publisher-group":
		query(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, publisher)
	case "publisher-credential":
		query(`UPDATE cli_credentials SET revoked_at=now() WHERE id=$1`, credential)
	case "policy-disable", "policy-mfa":
		policy, err := service.GetPolicy(ctx, org, browserOwner)
		if err != nil {
			t.Fatal(err)
		}
		_, e = service.UpdatePolicy(ctx, org, browserOwner, beam.PolicyInput{ConfirmEndActiveShares: true, Enabled: withdrawal == "policy-mfa", RequireMFA: withdrawal == "policy-mfa", ExpectedVersion: policy.Version, PublisherGroups: []uuid.UUID{group}, ReviewerUsers: []uuid.UUID{reviewer}, MaxDuration: 3600, MaxShares: 5})
		if e != nil {
			t.Fatal(e)
		}
	case "installation-disable", "installation-domain":
		query(`UPDATE users SET cp_admin=true WHERE id=$1`, publisher)
		settings, err := service.GetDomainSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		input := beam.DomainSettingsInput{ExpectedVersion: settings.Version, OperatorEnabled: withdrawal != "installation-disable", BaseDomain: settings.BaseDomain, ProxyURL: settings.ProxyURL, ConfirmEndActiveShares: true}
		if withdrawal == "installation-domain" {
			input.BaseDomain = "beam.changed.net"
		}
		if _, err = service.UpdateDomainSettings(ctx, publisher, input); err != nil {
			t.Fatal(err)
		}
	case "readiness-failed":
		query(`UPDATE beam_installation_settings SET readiness_passed=false WHERE singleton`)
	case "readiness-expired":
		query(`UPDATE beam_installation_settings SET readiness_checked_at=now()-interval '2 minutes', readiness_expires_at=now()-interval '1 minute' WHERE singleton`)
	case "fresh-generation":
		current, err := service.Get(ctx, org, share.ID, owner)
		if err != nil {
			t.Fatal(err)
		}
		if _, e = service.IssueConnector(ctx, org, share.ID, owner, beam.ConnectorInput{ExpectedVersion: current.Version, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}); e != nil {
			t.Fatal(e)
		}
	case "restore-barrier":
		write("restore.pending", []byte("pending"))
	case "supported-restore":
		// The supported offline tool fences serving before restoration. Recovery
		// deliberately waits five seconds after committing durable revocation;
		// observe active streams concurrently with that mandatory wait.
		write("restore.pending", []byte("pending"))
		recoveryDone = make(chan error, 1)
		go func() {
			_, err := appaccess.NewRecoveryService(pool).RecoverAuthority(ctx, "native-fixture-operator")
			recoveryDone <- err
		}()
	case "authority-clock-ahead":
		authorityClockOffset.Store(30)
	case "authority-clock-behind":
		authorityClockOffset.Store(-30)
	case "session-store-down":
		rdb.Close()
	case "publisher-status":
		query(`UPDATE users SET status='deactivated' WHERE id=$1`, publisher)
	case "publisher-role":
		query(`UPDATE memberships SET role='ai-view',roles=ARRAY['ai-view'] WHERE org_id=$1 AND user_id=$2`, org, publisher)
	case "publisher-credential-expiry":
		query(`UPDATE cli_credentials SET expires_at=now()-interval '1 second' WHERE id=$1`, credential)
	case "organization-deleted":
		query(`UPDATE organizations SET deleted_at=now() WHERE id=$1`, org)
	case "reviewer-auth-epoch":
		query(`UPDATE users SET app_auth_epoch=app_auth_epoch+1 WHERE id=$1`, reviewer)
	case "reviewer-parent-expiry", "mfa-freshness", "mfa-future-proof":
		changed := reviewSession
		if withdrawal == "reviewer-parent-expiry" {
			changed.ExpiresAt = time.Now().Add(-time.Second)
		} else if withdrawal == "mfa-freshness" {
			changed.MFAVerifiedAt = time.Now().Add(-6 * time.Minute)
		} else {
			changed.MFAVerifiedAt = time.Now().Add(2 * time.Minute)
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err = sessions.Client().Set(ctx, "sess:"+reviewSession.ID, raw, time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
	case "proxy-restart":
		if err := command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = command.Wait()
		// Revoke source while the serving process is absent. A new process must
		// consult current durable authority, never reconstruct permission from the old connector.
		query(`UPDATE cli_credentials SET revoked_at=now() WHERE id=$1`, credential)
		restart := exec.Command(binary)
		restart.Env = command.Env
		restart.Stdout = &proxyLog
		restart.Stderr = &proxyLog
		if err := restart.Start(); err != nil {
			t.Fatal(err)
		}
		command = restart
		nativeWaitListener(t, publicAddress)
	case "authority-down":
		authority.Close()
	default:
		t.Fatal("unknown native withdrawal fixture")
	}
	for _, closed := range []chan struct{}{httpClosed, sseClosed, wsClosed} {
		select {
		case <-closed:
		case <-time.After(time.Until(started.Add(5 * time.Second))):
			t.Fatal("native persistent withdrawal exceeded5seconds")
		}
	}
	withdrawalTime := time.Since(started)
	if recoveryDone != nil {
		select {
		case e = <-recoveryDone:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("durable recovery did not complete")
		}
		if e = os.Remove(filepath.Join(owned, "restore.pending")); e != nil {
			t.Fatal(e)
		}
	}
	denied := get("/", nil)
	_ = denied.Body.Close()
	if denied.StatusCode == 200 {
		t.Fatal("withdrawn native share stillserved")
	}
	t.Logf("Real durable Beam authority -> dedicated proxy -> native connector passed HTTP/SSE/WebSocket and %s withdrawal in %s", withdrawal, withdrawalTime)
}

type nativeLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *nativeLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(b)
}
func (l *nativeLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }
func nativeAddress(t *testing.T) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}
func nativePair(t *testing.T, write func(string, []byte) string, name string, pair tls.Certificate) (string, string) {
	t.Helper()
	var cert []byte
	for _, der := range pair.Certificate {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	return write(name+"-cert.pem", cert), write(name+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func nativePublicClient(roots *x509.CertPool, host, address string) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func nativeAPI(t *testing.T, base string, org uuid.UUID, path, token, sessionID string, in, out any) {
	t.Helper()
	payload, _ := json.Marshal(in)
	r, _ := http.NewRequest("POST", base+"/api/v1/organizations/"+org.String()+"/beam/"+path, bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		r.AddCookie(&http.Cookie{Name: session.CookieName, Value: sessionID})
		r.Header.Set("X-Tunnex-CSRF", "1")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		t.Fatalf("Beam native API %s status%d %s", path, res.StatusCode, body)
	}
	if e = json.NewDecoder(res.Body).Decode(out); e != nil {
		t.Fatal(e)
	}
}
func nativeWebsocket(t *testing.T, roots *x509.CertPool, host, address string, cookie *http.Cookie) net.Conn {
	t.Helper()
	connection, e := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13})
	if e != nil {
		t.Fatal(e)
	}
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	_, e = fmt.Fprintf(connection, "GET /echo HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nCookie: %s=%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", host, host, cookie.Name, cookie.Value, base64.StdEncoding.EncodeToString(nonce))
	if e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(connection)
	response, e := http.ReadResponse(reader, nil)
	if e != nil || response.StatusCode != 101 {
		if response != nil {
			t.Fatalf("native upgrade status%d", response.StatusCode)
		}
		t.Fatal("native upgrade failed", e)
	}
	_ = connection.SetDeadline(time.Time{})
	return connection
}

const nativeNodeScript = `const fs=require('node:fs/promises');const path=require('node:path');const root=process.env.BEAM_NATIVE_CLIENT;const{startBeamFixtureApp}=require(path.join(root,'apps/client/dev/beamfixture.ts'));const{runBeamFixturePool}=require(path.join(root,'apps/client/dev/beampool.ts'));const{openBeamChannel}=require(path.join(root,'apps/client/src/main/beamconnector.ts'));(async()=>{const app=await startBeamFixtureApp();const original=app.server.listeners('request')[0];app.server.removeListener('request',original);app.server.on('request',(req,res)=>{if(req.url!=='/native-download'){original(req,res);return}res.writeHead(200,{'Content-Type':'application/octet-stream'});res.write('beam');const timer=setInterval(()=>res.write('beam'),50);res.on('close',()=>clearInterval(timer))});console.log(JSON.stringify({port:app.port}));let options;for(let i=0;i<600;i++){try{options=JSON.parse(await fs.readFile(process.env.BEAM_NATIVE_OPTIONS,'utf8'));break}catch{await new Promise(r=>setTimeout(r,100))}}if(!options)throw new Error('native options timeout');const stop=new AbortController();for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{stop.abort();app.server.closeAllConnections();app.server.close()});for(const bad of [{...options,binding:{...options.binding,orgId:'99999999-0000-4000-8000-000000000009'}},{...options,identity:{...options.identity,cert:options.foreignCertificatePEM}}]){let denied=false;try{const channel=await openBeamChannel(bad,stop.signal);channel.close()}catch(e){denied=/beam_channel_refused/.test(String(e))}if(!denied)throw new Error('foreignidentity notrefused')}console.log('connector_started');await runBeamFixturePool(options,stop.signal);app.server.closeAllConnections();app.server.close()})().catch(()=>{console.error('native fixture failed');process.exit(1)});`

func nativeWaitListener(t *testing.T, address string) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Native proxy listener didnotstart")
}

// A timestamp offset simulates distinct authority/proxy wall clocks at their
// TLS wire boundary. It never changes a host clock or fabricates authorization:
// the production handler still resolves every current database/session decision.
func nativeSkewedLeaseHandler(next http.Handler, offset *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delta := offset.Load()
		if delta == 0 || (r.URL.Path != "/internal/beam/authorize" && r.URL.Path != "/internal/beam/renew") {
			next.ServeHTTP(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		body := recorder.Body.Bytes()
		if recorder.Code == http.StatusOK {
			var decision beam.Decision
			if e := json.Unmarshal(body, &decision); e != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			decision.ExpiresAt = decision.ExpiresAt.Add(time.Duration(delta) * time.Second)
			var e error
			body, e = json.Marshal(decision)
			if e != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		for k, values := range recorder.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(body)
	})
}
