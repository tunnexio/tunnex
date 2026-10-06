package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"golang.org/x/crypto/ssh"
)

func TestWindowsMaterialBindsChannelClaim(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	redis := miniredis.RunT(t)
	parents, err := session.New("redis://"+redis.Addr(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer parents.Client().Close()
	sealer, err := secret.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	org, user, gateway, server, grant, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'RDP fixture',$2,'10.97.0.0/24')`, org, "rdp-"+org.String())
	seed(`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, user, user.String()+"@example.invalid")
	seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['owner'])`, org, user)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'RDP gateway','rdp-test-cert','rdp-test-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	seed(`INSERT INTO server_access_settings(org_id,enabled,ca_private_sealed,ca_public) VALUES($1,true,'unused','unused')`, org)
	seed(`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled,os,clipboard_policy) VALUES($1,$2,$3,'Windows','10.1.2.3',3389,'SHA256:fixture',ARRAY['Administrator'],true,'windows','both')`, server, org, gateway)
	seed(`INSERT INTO server_access_grants(id,org_id,server_id,account,user_id,starts_at,expires_at,created_by) VALUES($1,$2,$3,'Administrator',$4,now(),now()+interval '1 hour',$4)`, grant, org, server, user)
	parent, err := parents.CreateWithMFAAuthority(ctx, user, "local_password", 1, time.Now(), session.MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(pool, parents, sealer, true)
	registered, err := svc.Server(ctx, org, server)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(parentBinding{Org: org, User: user, Token: parent.ID, AuthorityHash: serverAuthorityHash(registered)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(parent.ID))
	seed(`INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,grant_id,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled,browser_claimed_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,'Administrator',1,'rdp-test-cert','terminal','connecting',now()+interval '5 minutes',now()+interval '5 minutes',false,now())`, id, org, server, gateway, user, []byte(sealed), hash[:], grant)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	public := string(ssh.MarshalAuthorizedKey(key.PublicKey()))
	material, err := svc.Material(ctx, org, gateway, id, "rdp-test-cert", public)
	if err != nil || material.OS != "windows" || material.Certificate != "" || material.ClipboardPolicy != "both" {
		t.Fatalf("Windows material: %v", err)
	}
	if _, err = svc.Material(ctx, org, gateway, id, "rdp-test-cert", public); err != nil {
		t.Fatal("same claim rejected", err)
	}
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ssh.NewSignerFromKey(otherPrivate)
	if _, err = svc.Material(ctx, org, gateway, id, "rdp-test-cert", string(ssh.MarshalAuthorizedKey(otherKey.PublicKey()))); err == nil {
		t.Fatal("changed claim accepted")
	}
	left, right := net.Pipe()
	defer right.Close()
	live := &liveSession{done: make(chan struct{}), attached: make(chan struct{})}
	svc.live[id] = live
	defer svc.closeLive(id)
	if err = svc.Attach(ctx, org, gateway, id, "rdp-test-cert", left); err != nil {
		left.Close()
		t.Fatal("Windows channel could not attach", err)
	}
	var status string
	if err = pool.QueryRow(ctx, `SELECT status FROM server_access_sessions WHERE id=$1`, id).Scan(&status); err != nil || status != "connected" {
		t.Fatalf("status %s: %v", status, err)
	}
	select {
	case <-live.attached:
	default:
		t.Fatal("browser not released after attach")
	}
	duplicate, peer := net.Pipe()
	defer duplicate.Close()
	defer peer.Close()
	if err = svc.Attach(ctx, org, gateway, id, "rdp-test-cert", duplicate); err == nil {
		t.Fatal("duplicate channel accepted")
	}
}
