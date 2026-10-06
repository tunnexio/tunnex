package serveraccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// Server Access envelope inventory only. Not a product-wide master-key migrator.
func TestRecoveryOwnedEnvelopeMigration(t *testing.T) {
	if os.Getenv("TUNNEX_SA_RECOVERY_TEST") != "1" {
		t.Skip("requires synthetic recovery target")
	}
	source, target := os.Getenv("TUNNEX_SA_RECOVERY_SOURCE"), os.Getenv("TUNNEX_SA_RECOVERY_DB")
	if !regexp.MustCompile(`^sa_recovery_source_[a-f0-9]{12}$`).MatchString(source) || !regexp.MustCompile(`^sa_recovery_dest_[a-f0-9]{12}$`).MatchString(target) {
		t.Fatal("non-synthetic rotation target refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, e := os.ReadFile("/tmp/" + source + ".master")
	if e != nil {
		t.Fatal(e)
	}
	oldMaster, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(oldMaster)
	oldSeal, e := secret.NewSealer(oldMaster)
	if e != nil {
		t.Fatal(e)
	}
	newMaster := make([]byte, 32)
	rand.Read(newMaster)
	defer clear(newMaster)
	newSeal, _ := secret.NewSealer(newMaster)
	u, e := url.Parse(os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + target
	pool, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var actual string
	var org, user, recording uuid.UUID
	var epoch int64
	if e = pool.QueryRow(ctx, `SELECT current_database()`).Scan(&actual); e != nil || actual != target {
		t.Fatal("foreign database refused")
	}
	if e = pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA synthetic recovery'`).Scan(&org); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='member@sa-recovery.invalid'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT session_id FROM server_access_recordings WHERE org_id=$1 LIMIT 1`, org).Scan(&recording); e != nil {
		t.Fatal(e)
	}
	var ciphertext []byte
	if e = pool.QueryRow(ctx, `SELECT ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=0`, org, recording).Scan(&ciphertext); e != nil {
		t.Fatal(e)
	}
	cipherDigest := sha256.Sum256(ciphertext)
	parents, e := session.New(recoveryRedisURL(t), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	parent, e := parents.CreateWithMFAAuthority(ctx, user, authctx.AuthLocalPassword, epoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	p := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	original := New(pool, parents, oldSeal, true)
	originalSigner, e := original.signer(ctx, org)
	if e != nil {
		t.Fatal(e)
	}
	before, e := original.Recording(ctx, org, recording, p, false)
	if e != nil || len(before.Events) != 1 {
		t.Fatal("pre-migration replay unavailable")
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	type inventory struct{ table, column, key string }
	specs := []inventory{{"server_access_settings", "ca_private_sealed", "org_id"}, {"server_access_settings", "recording_storage_sealed", "org_id"}, {"server_access_sessions", "parent_sealed", "id"}, {"server_access_recordings", "key_sealed", "session_id"}, {"server_access_recordings", "storage_sealed", "session_id"}}
	type cell struct {
		spec  inventory
		id    uuid.UUID
		plain []byte
	}
	var cells []cell
	defer func() {
		for _, c := range cells {
			clear(c.plain)
		}
	}()
	for _, spec := range specs {
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT %s,%s FROM %s WHERE org_id=$1 AND %s IS NOT NULL FOR UPDATE`, spec.key, spec.column, spec.table, spec.column), org)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for rows.Next() {
			var id uuid.UUID
			var sealed []byte
			if err = rows.Scan(&id, &sealed); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plain, err := oldSeal.Open(string(sealed))
			if err != nil {
				rows.Close()
				t.Fatal("envelope inventory contains unreadable material")
			}
			cells = append(cells, cell{spec, id, plain})
			found++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		if found == 0 {
			t.Fatalf("envelope inventory missing %s.%s", spec.table, spec.column)
		}
	}
	for _, c := range cells {
		newWrapped, err := newSeal.Seal(c.plain)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s=$3 WHERE org_id=$1 AND %s=$2`, c.spec.table, c.spec.column, c.spec.key), org, c.id, []byte(newWrapped)); err != nil {
			t.Fatal(err)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	migrated := New(pool, parents, newSeal, true)
	if _, e = original.signer(ctx, org); e == nil {
		t.Fatal("old master still decrypts migrated CA")
	}
	migratedSigner, e := migrated.signer(ctx, org)
	if e != nil || !bytes.Equal(originalSigner.PublicKey().Marshal(), migratedSigner.PublicKey().Marshal()) {
		t.Fatal("rewrap changed signer identity")
	}
	for _, c := range cells {
		var wrapped []byte
		if e = pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM %s WHERE org_id=$1 AND %s=$2`, c.spec.column, c.spec.table, c.spec.key), org, c.id).Scan(&wrapped); e != nil {
			t.Fatal(e)
		}
		plain, e := newSeal.Open(string(wrapped))
		if e != nil || !bytes.Equal(plain, c.plain) {
			t.Fatal("migrated envelope did not retain original binding")
		}
		clear(plain)
		if _, e = oldSeal.Open(string(wrapped)); e == nil {
			t.Fatal("old master opened migrated envelope")
		}
	}
	after, e := migrated.Recording(ctx, org, recording, p, false)
	if e != nil || len(after.Events) != 1 || !bytes.Equal(after.Events[0].Data, before.Events[0].Data) {
		t.Fatal("full server-access envelope rewrap lost replay")
	}
	var afterCipher []byte
	if e = pool.QueryRow(ctx, `SELECT ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=0`, org, recording).Scan(&afterCipher); e != nil || sha256.Sum256(afterCipher) != cipherDigest {
		t.Fatal("master envelope migration rewrote terminal ciphertext")
	}
	if e = os.WriteFile("/tmp/"+target+".serveraccess-only.master", []byte(base64.StdEncoding.EncodeToString(newMaster)), 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("synthetic offline atomic rewrap PASS: %d org CA/parent/DEK/current storage/snapshot storage envelopes; signer and replay preserved; old master refused; ciphertext unchanged", len(cells))
}
