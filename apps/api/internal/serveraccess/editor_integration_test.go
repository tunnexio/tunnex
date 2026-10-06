package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

func TestEditorApprovalExchangeAndRevocation(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	redis := miniredis.RunT(t)
	parents, e := session.New("redis://"+redis.Addr(), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	sealer, _ := secret.NewSealer(make([]byte, 32))
	svc := New(pool, parents, sealer, true)
	org, user, gateway, server, grant := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'Editor fixture',$2,'10.96.0.0/24')`, org, "editor-"+org.String())
	seed(`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, user, user.String()+"@example.invalid")
	seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['owner'])`, org, user)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'Editor gateway','editor-test-cert','editor-test-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	seed(`INSERT INTO server_access_gateway_runtime(org_id,gateway_id,cert_serial,protocol_version,observed_at,editor_protocol_version) VALUES($1,$2,'editor-test-cert',1,now(),1)`, org, gateway)
	if e = svc.Configure(ctx, org, user, api.ServerAccessSettingsInput{Enabled: true}); e != nil {
		t.Fatal(e)
	}
	seed(`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,ready_accounts,enabled,recording_enabled,developer_access_enabled) VALUES($1,$2,$3,'Linux','10.1.2.3',2222,'SHA256:fixture',ARRAY['ubuntu'],ARRAY['ubuntu'],true,true,true)`, server, org, gateway)
	seed(`INSERT INTO server_access_grants(id,org_id,server_id,account,user_id,starts_at,expires_at,created_by) VALUES($1,$2,$3,'ubuntu',$4,now(),now()+interval '1 hour',$4)`, grant, org, server, user)
	parent, e := parents.CreateWithMFAAuthority(ctx, user, "local_password", 1, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	principal := &authctx.Principal{UserID: user, SessionID: parent.ID}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	verifier := strings.Repeat("a", 43)
	hash := sha256.Sum256([]byte(verifier))
	input := api.ServerAccessEditorInput{ServerId: server, Account: "ubuntu", PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:])}
	// An owner still needs a grant and cannot bypass a default-off server policy.
	seed(`UPDATE server_access_servers SET developer_access_enabled=false WHERE id=$1`, server)
	if _, e = svc.AuthorizeEditor(ctx, org, principal, input); e == nil {
		t.Fatal("disabled developer access admitted")
	}
	seed(`UPDATE server_access_servers SET developer_access_enabled=true WHERE id=$1`, server)
	seed(`UPDATE server_access_grants SET enabled=false WHERE id=$1`, grant)
	if _, e = svc.AuthorizeEditor(ctx, org, principal, input); e == nil {
		t.Fatal("owner bypassed grant")
	}
	seed(`UPDATE server_access_grants SET enabled=true WHERE id=$1`, grant)
	stale, e := parents.CreateWithMFAAuthority(ctx, user, "local_password", 1, time.Now().Add(-20*time.Minute), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), stale.ID)
	if _, e = svc.AuthorizeEditor(ctx, org, &authctx.Principal{UserID: user, SessionID: stale.ID}, input); e == nil {
		t.Fatal("stale MFA admitted")
	}
	approval, e := svc.AuthorizeEditor(ctx, org, principal, input)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.ExchangeEditor(ctx, api.ServerAccessEditorExchangeInput{Code: approval.Code, CodeVerifier: strings.Repeat("b", 43)}); e == nil {
		t.Fatal("PKCE mismatch accepted")
	}
	connection, e := svc.ExchangeEditor(ctx, api.ServerAccessEditorExchangeInput{Code: approval.Code, CodeVerifier: verifier})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.ExchangeEditor(ctx, api.ServerAccessEditorExchangeInput{Code: approval.Code, CodeVerifier: verifier}); e == nil {
		t.Fatal("code replay accepted")
	}
	r, e := svc.load(ctx, org, connection.SessionId)
	if e != nil || r.View.Kind != "editor" || r.View.RecordingEnabled {
		t.Fatalf("editor recording snapshot: %v", e)
	}
	var recordings int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM server_access_recordings WHERE session_id=$1`, connection.SessionId).Scan(&recordings); e != nil || recordings != 0 {
		t.Fatal("editor created recording")
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if e := svc.Editor(w, req, connection.SessionId, true); e != nil {
			http.Error(w, "refused", 403)
		}
	}))
	defer endpoint.Close()
	wsConfig, _ := websocket.NewConfig("ws"+strings.TrimPrefix(endpoint.URL, "http"), endpoint.URL)
	wsConfig.Header.Set("Authorization", "TunnexEditor "+connection.Token)
	ws, e := websocket.DialConfig(wsConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame
	if _, e = websocket.DialConfig(wsConfig); e == nil {
		t.Fatal("connection replay accepted")
	}
	_, gatewayPrivate, _ := ed25519.GenerateKey(rand.Reader)
	gatewaySigner, _ := ssh.NewSignerFromKey(gatewayPrivate)
	material, e := svc.Material(ctx, org, gateway, connection.SessionId, "editor-test-cert", string(ssh.MarshalAuthorizedKey(gatewaySigner.PublicKey())))
	if e != nil || material.EditorClientKey != input.PublicKey || len(material.EditorHostKey) != 64 {
		t.Fatalf("editor material: %v", e)
	}
	public, _, _, _, e := ssh.ParseAuthorizedKey([]byte(material.Certificate))
	if e != nil {
		t.Fatal(e)
	}
	cert := public.(*ssh.Certificate)
	if _, exists := cert.Extensions["permit-port-forwarding"]; exists {
		t.Fatal("unbounded SSH forwarding enabled")
	}
	left, right := net.Pipe()
	defer right.Close()
	if e = svc.Attach(ctx, org, gateway, connection.SessionId, "editor-test-cert", left); e != nil {
		t.Fatal(e)
	}
	_ = ws.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _, _ = right.Write([]byte("SSH-2.0-synthetic\r\n")) }()
	readback := make([]byte, len("SSH-2.0-synthetic\r\n"))
	if _, e = io.ReadFull(ws, readback); e != nil || string(readback) != "SSH-2.0-synthetic\r\n" {
		t.Fatal("editor bytes changed", e)
	}
	go func() { _, _ = ws.Write([]byte("synthetic-client")) }()
	clientBytes := make([]byte, len("synthetic-client"))
	_ = right.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.ReadFull(right, clientBytes); e != nil || string(clientBytes) != "synthetic-client" {
		t.Fatal("client bytes changed", e)
	}
	seed(`UPDATE server_access_grants SET enabled=false WHERE id=$1`, grant)
	_ = ws.SetReadDeadline(time.Now().Add(6 * time.Second))
	if _, e = ws.Read(make([]byte, 1)); e == nil {
		t.Fatal("revoked grant remained connected")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		r, e = svc.load(ctx, org, connection.SessionId)
		if e != nil {
			t.Fatal(e)
		}
		if r.View.Status == "ended" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation not audited")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r.View.Reason != "grant_revoked" {
		t.Fatalf("unexpected reason %s", r.View.Reason)
	}
	var events int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_id=$1 AND action IN ('server_access.session_requested','server_access.session_started','server_access.session_ended')`, connection.SessionId.String()).Scan(&events); e != nil || events != 3 {
		t.Fatalf("editor audit events %d: %v", events, e)
	}
}
