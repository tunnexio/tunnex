package http

// Nonshipping backup/restore for exactly one owned browser-fixture configuration.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type nativeSSOConfigSnapshot struct {
	t                   *testing.T
	pool                *pgxpool.Pool
	org, actor          uuid.UUID
	clientID            string
	original, installed *sqlc.SsoConfig
}

func nativeSSOConfigBackup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, actor uuid.UUID, clientID string) *nativeSSOConfigSnapshot {
	t.Helper()
	b := &nativeSSOConfigSnapshot{t: t, pool: pool, org: org, actor: actor, clientID: clientID}
	row, err := sqlc.New(pool).GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: org, Provider: "google"})
	if err == nil {
		b.original = &row
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("owned SSO configuration backup unavailable")
	}
	if err := b.persist("original", b.original); err != nil {
		t.Fatal("private owned SSO configuration backup unavailable")
	}
	return b
}

func (b *nativeSSOConfigSnapshot) CaptureInstalled() {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	row, err := sqlc.New(b.pool).GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: b.org, Provider: "google"})
	if err != nil || row.ClientID != b.clientID || !row.Enabled || row.TenantID != nil {
		b.t.Fatal("exact owned SSO fixture configuration unavailable")
	}
	b.installed = &row
	if err := b.persist("installed", b.installed); err != nil {
		b.t.Fatal("private installed SSO snapshot unavailable")
	}
}

func (b *nativeSSOConfigSnapshot) Restore() {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if b.installed == nil {
		// A failed Set/Capture may have an unknown commit outcome. Never assume
		// setup left the original state untouched, and never overwrite it blindly.
		row, err := sqlc.New(b.pool).GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: b.org, Provider: "google"})
		unchanged := b.original == nil && errors.Is(err, pgx.ErrNoRows) || b.original != nil && err == nil && reflect.DeepEqual(row, *b.original)
		if !unchanged {
			b.t.Error("owned SSO setup cleanup unconfirmed; exact private backup retained in /owned-aa9-sso-config")
		}
		return
	}
	if err := b.restore(ctx); err != nil {
		b.t.Error("owned SSO configuration restore refused; exact private backup retained in /owned-aa9-sso-config")
		return
	}
	fmt.Println("owned_native_sso_config_restored_exact; scoped_audit_committed")
}

func (b *nativeSSOConfigSnapshot) restore(ctx context.Context) error {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize cleanup and compare every field, including sealed bytes and times.
	var locked uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM sso_configs WHERE org_id=$1 AND provider='google' FOR UPDATE`, b.org).Scan(&locked); err != nil {
		return err
	}
	current, err := sqlc.New(tx).GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: b.org, Provider: "google"})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, *b.installed) {
		return errors.New("configuration changed since fixture installation")
	}
	tag, err := tx.Exec(ctx, `DELETE FROM sso_configs WHERE org_id=$1 AND provider='google' AND id=$2`, b.org, locked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("configuration identity mismatch")
	}
	if r := b.original; r != nil {
		// Insert preserves original timestamps without disabling the UPDATE trigger.
		_, err = tx.Exec(ctx, `INSERT INTO sso_configs(id,org_id,provider,client_id,client_secret_sealed,enabled,created_at,updated_at,tenant_id,secret_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, r.OrgID, r.Provider, r.ClientID, r.ClientSecretSealed, r.Enabled, r.CreatedAt, r.UpdatedAt, r.TenantID, r.SecretFingerprint)
		if err != nil {
			return err
		}
	}
	targetType, targetID := "sso_config", "google"
	_, err = sqlc.New(tx).InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: [16]byte(b.org), Valid: true}, ActorUserID: pgtype.UUID{Bytes: [16]byte(b.actor), Valid: true}, Action: "sso.fixture_config_restored", TargetType: &targetType, TargetID: &targetID, Metadata: []byte(`{"provider":"google","fixture":"aa9-native-browser","exact_original_restored":true}`)})
	if err != nil {
		return err
	}
	restored, err := sqlc.New(tx).GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: b.org, Provider: "google"})
	if b.original == nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return errors.New("original absence not restored")
		}
	} else if err != nil || !reflect.DeepEqual(restored, *b.original) {
		return errors.New("original sealed configuration not restored exactly")
	}
	return tx.Commit(ctx)
}

// Sealed credentials stay in the exact private fixture mount, never logs.
func (b *nativeSSOConfigSnapshot) persist(stage string, row *sqlc.SsoConfig) error {
	const directory = "/owned-aa9-sso-config"
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("private backup directory unavailable")
	}
	data, err := json.Marshal(struct {
		OrgID    uuid.UUID       `json:"org_id"`
		Provider string          `json:"provider"`
		Row      *sqlc.SsoConfig `json:"sealed_row"`
	}{b.org, "google", row})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(directory, stage+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}
