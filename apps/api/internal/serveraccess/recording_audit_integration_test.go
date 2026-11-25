package serveraccess

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

// SA-UX-4 bug 2: an open replay re-checks authority every five seconds with a metadata-only read. Those
// re-checks must not write audit rows; every read of recording content must write exactly one.
func TestRecordingAuditOneRowPerContentReadNonePerMetadataCheck(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	redis := miniredis.RunT(t)
	parents, e := session.New("redis://"+redis.Addr(), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	sealer, _ := secret.NewSealer(make([]byte, 32))
	svc := New(pool, parents, sealer, true)
	org, owner, viewer, gateway, server, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'Recording audit fixture',$2,'10.95.0.0/24')`, org, "recording-audit-"+org.String())
	for _, u := range []uuid.UUID{owner, viewer} {
		seed(`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, u, u.String()+"@example.invalid")
	}
	seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['owner'])`, org, owner)
	seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['member'])`, org, viewer)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'gw','recording-audit-cert','recording-audit-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	if e = svc.Configure(ctx, org, owner, api.ServerAccessSettingsInput{Enabled: true}); e != nil {
		t.Fatal(e)
	}
	seed(`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled,recording_enabled) VALUES($1,$2,$3,'Linux','10.1.2.3',2222,'SHA256:fixture',ARRAY['ubuntu'],true,true)`, server, org, gateway)
	// The viewer replays their own recorded terminal session.
	seed(`INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'test','test',1,'ubuntu',1,'test','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, id, org, server, gateway, viewer)
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = svc.prepareRecording(ctx, tx, org, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = svc.capture(ctx, org, id, time.Now(), terminalwire.Frame{Type: "output", Data: []byte("hello")}); e != nil {
		t.Fatal(e)
	}
	parent, e := parents.CreateWithAuthority(ctx, viewer, authctx.AuthLocalPassword, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	p := &authctx.Principal{UserID: viewer, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}

	audits := func() map[string]int {
		t.Helper()
		rows, e := pool.Query(ctx, `SELECT action FROM audit_logs WHERE org_id=$1 AND target_id=$2 AND action LIKE 'server_access.recording_%'`, org, id.String())
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var a string
			if e := rows.Scan(&a); e != nil {
				t.Fatal(e)
			}
			out[a]++
		}
		return out
	}
	if got := audits(); len(got) != 0 {
		t.Fatalf("fixture already has recording audit rows: %v", got)
	}

	// Opening the replay: one content read, one audit row.
	got, e := svc.Recording(ctx, org, id, p, false)
	if e != nil || len(got.Events) != 1 {
		t.Fatalf("content read: %v events=%d", e, len(got.Events))
	}
	if a := audits(); a["server_access.recording_read"] != 1 || len(a) != 1 {
		t.Fatalf("want one recording_read after opening, got %v", a)
	}

	// Twelve five-second authority re-checks (a minute of an open replay): no rows, no content.
	for i := 0; i < 12; i++ {
		meta, e := svc.Recording(ctx, org, id, p, true)
		if e != nil {
			t.Fatalf("metadata re-check %d: %v", i, e)
		}
		if len(meta.Events) != 0 || meta.Status != "capturing" {
			t.Fatalf("metadata re-check disclosed content or lost status: status=%s events=%d", meta.Status, len(meta.Events))
		}
	}
	if a := audits(); a["server_access.recording_read"] != 1 || len(a) != 1 {
		t.Fatalf("metadata re-checks wrote audit rows: %v", a)
	}

	// "Load latest output" is another content read: exactly one more row.
	if _, e = svc.Recording(ctx, org, id, p, false); e != nil {
		t.Fatal(e)
	}
	if a := audits(); a["server_access.recording_read"] != 2 || len(a) != 1 {
		t.Fatalf("want two recording_read after Load latest output, got %v", a)
	}

	// Revoked replay permission: the metadata re-check is still enforced (and still writes nothing).
	seed(`UPDATE memberships SET roles=ARRAY['ai-view'] WHERE org_id=$1 AND user_id=$2`, org, viewer)
	if _, e = svc.Recording(ctx, org, id, p, true); authorityReason(e) != "recording_permission_denied" {
		t.Fatalf("revoked viewer passed a metadata re-check: %v", e)
	}
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "recording_permission_denied" {
		t.Fatalf("revoked viewer read content: %v", e)
	}
	if a := audits(); a["server_access.recording_read"] != 2 || len(a) != 1 {
		t.Fatalf("denied reads changed audit rows: %v", a)
	}
}
