package serveraccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
)

// Explicit fixture opt-in; the original database is never mutated. Only a
// separately named sa_recovery_<hex> clone and this test's Redis parent change.
func TestRecoveryOwnedSnapshot(t *testing.T) {
	if os.Getenv("TUNNEX_SA_RECOVERY_TEST") != "1" {
		t.Skip("requires owned recovery fixture")
	}
	name := os.Getenv("TUNNEX_SA_RECOVERY_DB")
	if !regexp.MustCompile(`^sa_recovery_(source|dest)_[a-f0-9]{12}$`).MatchString(name) {
		t.Fatal("foreign restore target refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	sourceDB := os.Getenv("TUNNEX_SA_RECOVERY_SOURCE")
	if !regexp.MustCompile(`^sa_recovery_source_[a-f0-9]{12}$`).MatchString(sourceDB) {
		t.Fatal("non-synthetic source refused")
	}
	if os.Getenv("TUNNEX_SA_RECOVERY_PHASE") == "seed" {
		seedRecoverySynthetic(ctx, t, sourceDB)
		return
	}
	rawKey, e := os.ReadFile("/tmp/" + sourceDB + ".master")
	if e != nil {
		t.Fatal("mounted original master unavailable")
	}
	master, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawKey)))
	clear(rawKey)
	if e != nil || len(master) != 32 {
		t.Fatal("invalid mounted master")
	}
	defer clear(master)
	sealer, e := secret.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	wrong, _ := secret.NewSealer(wrongKey)
	clear(wrongKey)
	dump, e := os.ReadFile("/binaries/recovery-fixture.dump")
	if e != nil {
		t.Fatal(e)
	}
	defer clear(dump)
	digest := sha256.Sum256(dump)
	manifest := backup.NewManifestWithDump(sealer, 203, "owned Server Access restore qualification", hex.EncodeToString(digest[:]))
	if backup.Verify(manifest, sealer) != nil || backup.VerifyDumpSHA256(manifest, hex.EncodeToString(digest[:])) != nil {
		t.Fatal("backup manifest verification failed")
	}
	if backup.Verify(manifest, wrong) == nil {
		t.Fatal("wrong master accepted")
	}
	modified := manifest
	modified.DumpSHA256 = strings.Repeat("0", 64)
	if backup.Verify(modified, sealer) == nil {
		t.Fatal("archive replacement accepted")
	}
	encrypted, e := sealer.Seal(dump)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := sealer.Open(encrypted)
	if e != nil || !bytes.Equal(restored, dump) {
		t.Fatal("encrypted archive roundtrip failed")
	}
	clear(restored)
	if _, e = wrong.Open(encrypted); e == nil {
		t.Fatal("wrong key decrypted backup")
	}
	if os.Getenv("TUNNEX_SA_RECOVERY_PHASE") == "verify" {
		if e = os.WriteFile("/tmp/"+name+".backup.enc", []byte(encrypted), 0600); e != nil {
			t.Fatal(e)
		}
		info, e := os.Stat("/tmp/" + name + ".backup.enc")
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("encrypted backup permissions failed")
		}
		t.Log("synthetic archive verified; wrong key/tampered manifest refused; encrypted private artifact created")
		return
	}
	sourceURL, e := url.Parse(os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	sourceURL.Path = "/" + sourceDB
	source, e := pgxpool.New(ctx, sourceURL.String())
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	var sourceName string
	var org uuid.UUID
	if e = source.QueryRow(ctx, `SELECT current_database()`).Scan(&sourceName); e != nil || sourceName != sourceDB {
		t.Fatal("foreign source refused")
	}
	if e = source.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA synthetic recovery'`).Scan(&org); e != nil || org == uuid.Nil {
		t.Fatal("foreign org refused")
	}
	u, e := url.Parse(os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + name
	clone, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer clone.Close()
	var actual string
	var version int
	var dirty bool
	if e = clone.QueryRow(ctx, `SELECT current_database()`).Scan(&actual); e != nil || actual != name {
		t.Fatal("foreign clone refused")
	}
	if e = clone.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); e != nil || version != 203 || dirty {
		t.Fatal("restore schema unqualified")
	}
	// Dump restores memberships and durable parent logout ledger exactly. Do not
	// compare terminal counts against the live source, whose new sessions may advance.
	var sourceRoles, cloneRoles []byte
	var sourceLogout, cloneLogout int
	query := `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY org_id,user_id),'[]'::jsonb) FROM memberships m`
	if e = source.QueryRow(ctx, query).Scan(&sourceRoles); e != nil {
		t.Fatal(e)
	}
	if e = clone.QueryRow(ctx, query).Scan(&cloneRoles); e != nil || !bytes.Equal(sourceRoles, cloneRoles) {
		t.Fatal("restored membership roles differ")
	}
	if e = source.QueryRow(ctx, `SELECT count(*) FROM app_access_parent_logout_tombstones`).Scan(&sourceLogout); e != nil {
		t.Fatal(e)
	}
	if e = clone.QueryRow(ctx, `SELECT count(*) FROM app_access_parent_logout_tombstones`).Scan(&cloneLogout); e != nil || sourceLogout != cloneLogout {
		t.Fatal("restored logout ledger differs")
	}
	parents, e := session.New(recoveryRedisURL(t), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	var user, server, gateway uuid.UUID
	var epoch int64
	var serial string
	if e = clone.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='member@sa-recovery.invalid'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	if e = clone.QueryRow(ctx, `SELECT id,gateway_id FROM server_access_servers WHERE org_id=$1 AND name='Synthetic Linux fixture'`, org).Scan(&server, &gateway); e != nil {
		t.Fatal(e)
	}
	if e = clone.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE org_id=$1 AND id=$2`, org, gateway).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	parent, e := parents.CreateWithMFAAuthority(ctx, user, authctx.AuthLocalPassword, epoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(clone, parents, sealer, true)
	if _, e = clone.Exec(ctx, `UPDATE server_access_settings SET enabled=true WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	var archivedSession uuid.UUID
	if e = clone.QueryRow(ctx, `SELECT session_id FROM server_access_recordings WHERE org_id=$1 LIMIT 1`, org).Scan(&archivedSession); e != nil {
		t.Fatal(e)
	}
	archivedPrincipal := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	archived, e := svc.Recording(ctx, org, archivedSession, archivedPrincipal, false)
	if e != nil || len(archived.Events) != 1 || string(archived.Events[0].Data) != "SYNTHETIC_ENCRYPTED_RECOVERY" {
		t.Fatalf("restored encrypted database payload cannot replay: %v", e)
	}
	originalSigner, e := svc.signer(ctx, org)
	if e != nil {
		t.Fatal("original CA cannot decrypt under restored master")
	}
	// Compromised/mismatched signer material fails closed. CA rotation is offline,
	// after disabling the org and removing old host trust; no UI is claimed here.
	pub, newCA, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(newCA)
	bound, e := json.Marshal(struct {
		Org uuid.UUID `json:"org"`
		Key []byte    `json:"key"`
	}{org, newCA})
	if e != nil {
		t.Fatal(e)
	}
	newSealed, e := sealer.Seal(bound)
	clear(bound)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = clone.Exec(ctx, `UPDATE server_access_settings SET ca_private_sealed=$2 WHERE org_id=$1`, org, []byte(newSealed)); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.signer(ctx, org); authorityReason(e) != "invalid_ca_binding" {
		t.Fatal("mismatched CA public/private accepted")
	}
	newPub, _ := ssh.NewPublicKey(pub)
	if _, e = clone.Exec(ctx, `UPDATE server_access_settings SET ca_public=$2 WHERE org_id=$1`, org, string(ssh.MarshalAuthorizedKey(newPub))); e != nil {
		t.Fatal(e)
	}
	rotated, e := svc.signer(ctx, org)
	if e != nil || bytes.Equal(rotated.PublicKey().Marshal(), originalSigner.PublicKey().Marshal()) {
		t.Fatal("signer rotation failed")
	}
	view, e := svc.Server(ctx, org, server)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := json.Marshal(parentBinding{org, user, parent.ID, serverAuthorityHash(view)})
	if e != nil {
		t.Fatal(e)
	}
	sealedParent, e := sealer.Seal(binding)
	clear(binding)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256([]byte(parent.ID))
	id := uuid.New()
	if _, e = clone.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'fixture',$9,$10,'check','connected',now()+interval '1 hour',now()+interval '1 hour',false)`, id, org, server, gateway, user, []byte(sealedParent), hash[:], epoch, view.Revision, serial); e != nil {
		t.Fatal(e)
	}
	r, e := svc.load(ctx, org, id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = clone.Exec(ctx, `UPDATE server_access_servers SET host_fingerprint=$3 WHERE org_id=$1 AND id=$2`, org, server, "SHA256:"+base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))); e != nil {
		t.Fatal(e)
	}
	if _, _, e = svc.validate(ctx, org, r); authorityReason(e) != "server_authority_changed" {
		t.Fatalf("old host authority survived replacement: %v", e)
	}
	// Startup fences every snapshotted active terminal; disabled feature must not
	// be mistaken for successful recovery (operators still run the epoch fence).
	if e = svc.Boot(ctx); e != nil {
		t.Fatal(e)
	}
	var active int
	if e = clone.QueryRow(ctx, `SELECT count(*) FROM server_access_sessions WHERE status IN ('pending','connecting','connected')`).Scan(&active); e != nil || active != 0 {
		t.Fatal("stale sessions survived boot")
	}
	var reason string
	if e = clone.QueryRow(ctx, `SELECT reason FROM server_access_sessions WHERE id=$1`, id).Scan(&reason); e != nil || reason != "control_plane_restarted" {
		t.Fatal("startup fence not audited/reasoned")
	}
	if _, _, e = svc.parent(ctx, org, user, parent.ID); e != nil {
		t.Fatalf("restored same-epoch parent unexpectedly invalid before offline fence: %v", e)
	}
	recovery, e := appaccess.NewRecoveryService(clone).RecoverAuthority(ctx, "sa-owned-recovery-test")
	if e != nil || !recovery.Confirmed {
		t.Fatal("offline authority fence failed")
	}
	if _, _, e = svc.parent(ctx, org, user, parent.ID); authorityReason(e) != "user_authority_changed" {
		t.Fatal("surviving Redis parent revived after recovery")
	}
	p := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "replay_authority_changed" {
		t.Fatal("surviving parent replay reopened after restore")
	}
	if e = clone.QueryRow(ctx, query).Scan(&cloneRoles); e != nil || !bytes.Equal(sourceRoles, cloneRoles) {
		t.Fatal("recovery altered restored roles")
	}
	var recoveredEpoch int64
	if e = clone.QueryRow(ctx, `SELECT app_auth_epoch FROM users WHERE id=$1`, user).Scan(&recoveredEpoch); e != nil || recoveredEpoch <= epoch {
		t.Fatal("user epoch did not advance")
	}
	fresh, e := parents.CreateWithMFAAuthority(ctx, user, authctx.AuthLocalPassword, recoveredEpoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), fresh.ID)
	archivedPrincipal.SessionID = fresh.ID
	archived, e = svc.Recording(ctx, org, archivedSession, archivedPrincipal, false)
	if e != nil || len(archived.Events) != 1 || string(archived.Events[0].Data) != "SYNTHETIC_ENCRYPTED_RECOVERY" {
		t.Fatal("fresh authorized parent could not replay restored recording")
	}
	// Rotating only the recording envelope: rewrap the same per-session DEK under
	// another master and retain authenticated ciphertext. This is a qualification
	// primitive, not a full installation master-key migration tool.
	dek := make([]byte, 32)
	rand.Read(dek)
	defer clear(dek)
	wrapped, _ := json.Marshal(recordingKey{org, id, dek})
	oldEnvelope, _ := sealer.Seal(wrapped)
	event := recordingEvent{Seq: 0, Millis: 1, Type: "output", Data: []byte("RECOVERY_CIPHERTEXT_PROBE")}
	chunk, e := sealEvent(dek, org, id, event)
	if e != nil {
		t.Fatal(e)
	}
	replacement, e := wrong.Seal(wrapped)
	clear(wrapped)
	if e != nil {
		t.Fatal(e)
	}
	migratedSvc := New(clone, nil, wrong, true)
	if _, e = migratedSvc.recordingKey(org, id, []byte(oldEnvelope)); e == nil {
		t.Fatal("wrong envelope master accepted")
	}
	recoveredDEK, e := migratedSvc.recordingKey(org, id, []byte(replacement))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(recoveredDEK)
	if got, e := openEvent(recoveredDEK, org, id, 0, chunk); e != nil || !bytes.Equal(got.Data, event.Data) {
		t.Fatal("recording envelope rotation lost ciphertext")
	}
	t.Log("separate restore verified: encrypted CA, roles/logout ledger, CA mismatch/rotation, host fence, boot stale-session closure, epoch/replay fence, wrapped-DEK rotation")
}

func recoveryRedisURL(t *testing.T) string {
	t.Helper()
	u, e := url.Parse(os.Getenv("REDIS_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/3"
	return u.String()
}
func seedRecoverySynthetic(ctx context.Context, t *testing.T, name string) {
	t.Helper()
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
	var count int
	if e = pool.QueryRow(ctx, `SELECT current_database(),(SELECT count(*) FROM users)+(SELECT count(*) FROM organizations)`).Scan(&actual, &count); e != nil || actual != name || count != 0 {
		t.Fatal("synthetic empty source boundary refused")
	}
	master := make([]byte, 32)
	rand.Read(master)
	defer clear(master)
	if e = os.WriteFile("/tmp/"+name+".master", []byte(base64.StdEncoding.EncodeToString(master)), 0600); e != nil {
		t.Fatal(e)
	}
	sealer, _ := secret.NewSealer(master)
	org, user, admin, gateway, server, grant, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO schema_migrations(version,dirty) VALUES(203,false)`, nil},
		{`INSERT INTO app_access_installation_authority DEFAULT VALUES`, nil},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'SA synthetic recovery','sa-synthetic-recovery')`, []any{org}},
		{`INSERT INTO users(id,email,email_verified_at) VALUES($1,'member@sa-recovery.invalid',now()),($2,'admin@sa-recovery.invalid',now())`, []any{user, admin}},
		{`INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,'member',ARRAY['member']),($1,$3,'admin',ARRAY['admin'])`, []any{org, user, admin}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'synthetic-gateway','synthetic-serial','gateway',now(),now()+interval '1 hour')`, []any{gateway, org}},
		{`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled,ready_accounts) VALUES($1,$2,$3,'Synthetic Linux fixture','10.99.0.3',2222,$4,ARRAY['fixture'],true,ARRAY['fixture'])`, []any{server, org, gateway, "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))}},
		{`INSERT INTO server_access_grants(id,org_id,server_id,account,user_id,starts_at,expires_at,created_by) VALUES($1,$2,$3,'fixture',$4,now(),now()+interval '1 hour',$5)`, []any{grant, org, server, user, admin}},
		{`INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,grant_id,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'synthetic','synthetic',1,$6,'fixture',1,'synthetic-serial','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, []any{id, org, server, gateway, user, grant}},
		{`INSERT INTO app_access_parent_logout_tombstones(parent_hash,user_id,parent_expires_at) VALUES($1,$2,now()+interval '1 hour')`, []any{bytes.Repeat([]byte{19}, 32), user}},
	}
	for _, statement := range statements {
		if _, e = tx.Exec(ctx, statement.sql, statement.args...); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	svc := New(pool, nil, sealer, true)
	if e = svc.Configure(ctx, org, admin, structSettingsEnabled()); e != nil {
		t.Fatal(e)
	}
	view, e := svc.Server(ctx, org, server)
	if e != nil {
		t.Fatal(e)
	}
	parentRaw, _ := json.Marshal(parentBinding{org, user, "synthetic-backup-parent", serverAuthorityHash(view)})
	sealedParent, e := sealer.Seal(parentRaw)
	clear(parentRaw)
	if e != nil {
		t.Fatal(e)
	}
	parentHash := sha256.Sum256([]byte("synthetic-backup-parent"))
	configRaw, _ := json.Marshal(recordingStorageConfig{Org: org, Kind: "postgres"})
	sealedConfig, e := sealer.Seal(configRaw)
	clear(configRaw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_sessions SET parent_sealed=$2,parent_hash=$3 WHERE id=$1`, id, []byte(sealedParent), parentHash[:]); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, []byte(sealedConfig)); e != nil {
		t.Fatal(e)
	}
	tx, e = pool.Begin(ctx)
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
	// Model an existing sealed PostgreSQL snapshot for upgrade/rotation proof.
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET storage_sealed=$3 WHERE org_id=$1 AND session_id=$2`, org, id, []byte(sealedConfig)); e != nil {
		t.Fatal(e)
	}
	if e = svc.capture(ctx, org, id, time.Now(), terminalwire.Frame{Type: "output", Data: []byte("SYNTHETIC_ENCRYPTED_RECOVERY")}); e != nil {
		t.Fatal(e)
	}
	t.Log("fresh synthetic users/roles/grant/gateway/session/ciphertext/logout ledger seeded; no original private data copied")
}
func structSettingsEnabled() api.ServerAccessSettingsInput {
	return api.ServerAccessSettingsInput{Enabled: true}
}
