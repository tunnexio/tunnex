package serveraccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

// Only a separately seeded synthetic database and synthetic master are accepted.
func TestRecordingSyntheticArchiveLifecycle(t *testing.T) {
	if os.Getenv("TUNNEX_SA_RECOVERY_TEST") != "1" {
		t.Skip("requires synthetic schema186 source and local Moto")
	}
	name := os.Getenv("TUNNEX_SA_RECOVERY_SOURCE")
	if !regexp.MustCompile(`^sa_recovery_source_[a-f0-9]{12}$`).MatchString(name) {
		t.Fatal("foreign source refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	u, e := url.Parse(os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + name
	pool, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var actual string
	if e = pool.QueryRow(ctx, `SELECT current_database()`).Scan(&actual); e != nil || actual != name {
		t.Fatal("database boundary refused")
	}
	raw, e := os.ReadFile("/tmp/" + name + ".master")
	if e != nil {
		t.Fatal(e)
	}
	master, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if e != nil {
		t.Fatal(e)
	}
	sealer, e := secret.NewSealer(master)
	clear(master)
	if e != nil {
		t.Fatal(e)
	}
	var org, user, admin, server, gateway uuid.UUID
	var epoch int64
	if e = pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA synthetic recovery'`).Scan(&org); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='member@sa-recovery.invalid'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id FROM users WHERE email='admin@sa-recovery.invalid'`).Scan(&admin); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,gateway_id FROM server_access_servers WHERE org_id=$1`, org).Scan(&server, &gateway); e != nil {
		t.Fatal(e)
	}
	parents, e := session.New(recoveryRedisURL(t), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	parent, e := parents.CreateWithAuthority(ctx, user, authctx.AuthLocalPassword, epoch)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(pool, parents, sealer, true)
	p := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	bucket := "sa-archive-synthetic-186"
	cfg := recordingStorageConfig{Org: org, Kind: "s3", Endpoint: "http://127.0.0.1:9000", Bucket: bucket, Region: "us-east-1", AccessKeyID: "fixture", SecretAccessKey: "synthetic-fixture-secret"}
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, cfg.Endpoint+"/"+bucket, nil)
	if e != nil {
		t.Fatal(e)
	}
	signS3(req, cfg, nil, time.Now().UTC())
	resp, e := recordingHTTPClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("owned Moto bucket creation: %d", resp.StatusCode)
	}
	t.Logf("owned Moto bucket retained: %s", bucket)
	var oldConfig []byte
	var oldEnabled bool
	if e = pool.QueryRow(ctx, `SELECT archive_storage_sealed,archive_enabled FROM server_access_settings WHERE org_id=$1`, org).Scan(&oldConfig, &oldEnabled); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `UPDATE server_access_settings SET archive_storage_sealed=$2,archive_enabled=$3 WHERE org_id=$1`, org, oldConfig, oldEnabled)
	str := func(s string) *string { return &s }
	view, e := svc.ConfigureRecordingArchive(ctx, org, admin, api.ServerAccessRecordingArchiveInput{Enabled: false, Endpoint: str(cfg.Endpoint), Bucket: str(bucket), Region: str(cfg.Region), AccessKeyId: str(cfg.AccessKeyID), SecretAccessKey: str(cfg.SecretAccessKey)})
	if e != nil || view.Enabled || !view.CredentialsConfigured {
		t.Fatalf("manual configuration with auto disabled: %v", e)
	}
	id := uuid.New()
	defer pool.Exec(context.Background(), `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id)
	_, e = pool.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'synthetic','synthetic',$6,'fixture',1,'synthetic-serial','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, id, org, server, gateway, user, epoch)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if e = svc.prepareRecording(ctx, tx, org, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	started := time.Now().Add(-125 * time.Millisecond)
	for _, frame := range []terminalwire.Frame{{Type: "output", Data: append([]byte("SYNTHETIC_ARCHIVE_PAYLOAD\r\nUTF8: "), 0xe2)}, {Type: "resize", Rows: 40, Cols: 120}, {Type: "output", Data: []byte{0x82, 0xac, 0x0d, 0x0a}}} {
		if e = svc.capture(ctx, org, id, started, frame); e != nil {
			t.Fatal(e)
		}
	}
	_, e = pool.Exec(ctx, `UPDATE server_access_sessions SET status='ended',ended_at=now() WHERE org_id=$1 AND id=$2`, org, id)
	if e != nil {
		t.Fatal(e)
	}
	_, e = pool.Exec(ctx, `UPDATE server_access_recordings SET status='incomplete' WHERE org_id=$1 AND session_id=$2`, org, id)
	if e != nil {
		t.Fatal(e)
	}
	before, e := svc.DownloadRecording(ctx, org, id, p)
	if e != nil || len(before.Events) != 3 {
		t.Fatalf("source download: %v", e)
	}
	if before.Events[0].Millis < 100 || before.Events[2].Millis < before.Events[0].Millis || before.Events[1].Type != "resize" || before.Events[1].Rows != 40 || before.Events[1].Cols != 120 || before.Events[0].Data[len(before.Events[0].Data)-1] != 0xe2 || !bytes.Equal(before.Events[2].Data, []byte{0x82, 0xac, 0x0d, 0x0a}) {
		t.Fatal("fixture did not preserve split UTF8, resize and elapsed timing")
	}
	if _, e = svc.QueueRecordingArchive(ctx, org, id, p); e != nil {
		t.Fatal(e)
	}
	// Changing current configuration must not redirect the immutable queued copy.
	if _, e = svc.ConfigureRecordingArchive(ctx, org, admin, api.ServerAccessRecordingArchiveInput{Enabled: false, Endpoint: str(cfg.Endpoint), Bucket: str("unused-synthetic-bucket"), Region: str(cfg.Region), AccessKeyId: str(cfg.AccessKeyID), SecretAccessKey: str(cfg.SecretAccessKey)}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		if _, e = svc.archiveRecordingStep(ctx, org, id); e != nil {
			t.Fatal(e)
		}
	}
	var size, n int
	var status, archive string
	if e = pool.QueryRow(ctx, `SELECT status,archive_status,payload_bytes,(SELECT sum(octet_length(ciphertext)) FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2) FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&status, &archive, &size, &n); e != nil || status != "incomplete" || archive != "available" || size == 0 || n == 0 {
		t.Fatalf("manual archive prematurely released PG: %s/%s %d/%d %v", status, archive, size, n, e)
	}
	if _, e = svc.QueueRecordingArchive(ctx, org, id, p); e != nil {
		t.Fatal(e)
	}
	_, e = pool.Exec(ctx, `UPDATE server_access_recordings SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND session_id=$2`, org, id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.expireRecordingStep(ctx, org, id); e != nil {
		t.Fatal(e)
	}
	// Inject a fixture-only unavailable destination into the immutable job row.
	// The worker must persist failure without releasing any original ciphertext.
	var originalSnapshot []byte
	if e = pool.QueryRow(ctx, `SELECT archive_storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&originalSnapshot); e != nil {
		t.Fatal(e)
	}
	bad := cfg
	bad.Endpoint = "http://127.0.0.1:1"
	badRaw, _ := json.Marshal(bad)
	badSealed, e := sealer.Seal(badRaw)
	clear(badRaw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET archive_storage_sealed=$3 WHERE org_id=$1 AND session_id=$2`, org, id, []byte(badSealed)); e != nil {
		t.Fatal(e)
	}
	if e = svc.processRecordingArchives(ctx); e == nil {
		t.Fatal("unavailable archive returned success")
	}
	if e = pool.QueryRow(ctx, `SELECT archive_status,payload_bytes FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&archive, &size); e != nil || archive != "failed" || size == 0 {
		t.Fatal("archive failure released PG or was not durable")
	}
	// Restore only our deliberately injected snapshot; current settings stay changed.
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET archive_storage_sealed=$3,archive_retry_after=NULL WHERE org_id=$1 AND session_id=$2`, org, id, originalSnapshot); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		if _, e = svc.archiveRecordingStep(ctx, org, id); e != nil {
			t.Fatal(e)
		}
	}
	after, e := svc.DownloadRecording(ctx, org, id, p)
	if e != nil || after.Status != "incomplete" {
		t.Fatalf("archived download: %v", e)
	}
	meta, e := svc.Recording(ctx, org, id, p, true)
	if e != nil || meta.Status != "incomplete" || len(meta.Events) != 0 {
		t.Fatal("metadata refresh lost incomplete warning")
	}
	a, _ := json.Marshal(before.Events)
	b, _ := json.Marshal(after.Events)
	if !bytes.Equal(a, b) {
		t.Fatal("archive replay changed lossless timing/output/resize")
	}
	if e = pool.QueryRow(ctx, `SELECT payload_bytes,(SELECT sum(octet_length(ciphertext)) FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2) FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&size, &n); e != nil || size != 0 || n != 0 {
		t.Fatal("verified expiry failed to release PG")
	}
	packageBytes, e := svc.DownloadRecordingPackage(ctx, org, id, p)
	if e != nil {
		t.Fatal(e)
	}
	// Delete only this fixture's original rows, then retrieve the self-contained
	// encrypted S3 object independently of PostgreSQL session/recording lookup.
	if _, e = pool.Exec(ctx, `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	store, e := svc.loadRecordingStorage(ctx, org, originalSnapshot)
	if e != nil {
		t.Fatal(e)
	}
	objects, ok := store.(recordingPackageStore)
	if !ok {
		t.Fatal("package store unavailable")
	}
	downloaded, e := objects.GetPackage(ctx, org, id)
	if e != nil || !bytes.Equal(downloaded, packageBytes) {
		t.Fatal("S3 package depends on deleted original row")
	}
	imported, e := svc.ImportRecordingPackage(ctx, org, p, downloaded)
	if e != nil || imported.Status != "incomplete" {
		t.Fatalf("import after original deletion failed: %v", e)
	}
	c, _ := json.Marshal(imported.Events)
	if !bytes.Equal(a, c) {
		t.Fatal("self-contained imported events changed")
	}
	if _, e = svc.ImportRecordingPackage(ctx, uuid.New(), p, downloaded); e == nil {
		t.Fatal("foreign tenant package imported")
	}
	decoded, _, e := svc.openRecordingPackage(org, downloaded)
	if e != nil {
		t.Fatal(e)
	}
	decoded.Owner = admin
	foreignOwner, e := svc.sealRecordingPackage(decoded)
	if e != nil {
		t.Fatal(e)
	}
	p.Roles[org] = "admin" // cached role cannot override current database member role
	if _, e = svc.ImportRecordingPackage(ctx, org, p, foreignOwner); authorityReason(e) != "recording_permission_denied" {
		t.Fatal("nonowner cached administrator imported package")
	}
	if e = parents.Delete(ctx, parent.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.ImportRecordingPackage(ctx, org, p, downloaded); e == nil {
		t.Fatal("logged-out parent imported package")
	}
	// Private credentials/package artifacts prepare a separate synthetic API/UI.
	if os.Getenv("TUNNEX_SA_PACKAGE_UI") == "1" {
		memberPassword, adminPassword := uuid.NewString()+"Aa!", uuid.NewString()+"Aa!"
		memberHash, e := password.Hash(memberPassword)
		if e != nil {
			t.Fatal(e)
		}
		adminHash, e := password.Hash(adminPassword)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, `UPDATE users SET password_hash=CASE WHEN id=$1 THEN $3 ELSE $4 END WHERE id IN ($1,$2)`, user, admin, memberHash, adminHash); e != nil {
			t.Fatal(e)
		}
		metadata, _ := json.Marshal(map[string]any{"database": name, "org_id": org, "session_id": id, "bucket": bucket, "package_key": org.String() + "/" + id.String() + "/recording-v2.tunnex-recording", "member_email": "member@sa-recovery.invalid", "member_password": memberPassword, "admin_email": "admin@sa-recovery.invalid", "admin_password": adminPassword, "master_file": name + ".master", "package_file": name + ".tunnex-recording", "expected_events": before.Events, "expected_status": "incomplete"})
		if e = os.WriteFile("/tmp/"+name+".package-ui.json", metadata, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile("/tmp/"+name+".tunnex-recording", downloaded, 0600); e != nil {
			t.Fatal(e)
		}
		t.Log("private synthetic login/package artifacts saved; credentials not emitted")
	}
	t.Log("auto OFF manual S3 snapshot, incomplete lossless download, idempotent export, retained PG before expiry, verified S3 replay after expiry passed")
}
