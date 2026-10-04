package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"net/url"
	"os"
	"testing"
	"time"
)

// Nonshipping setup creates only two explicitly owned synthetic member
// identities. Real grants, sessions and publications use product APIs.
func TestAppAccessLocalLifecycleIdentitySeed(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_LIFECYCLE_SEED") != "1" {
		t.Skip("explicit owned fixture only")
	}
	email, plain, dbPassword := os.Getenv("AA1_UI_EMAIL"), os.Getenv("AA1_UI_PASSWORD"), os.Getenv("AA0_DB_PASSWORD")
	kind := ""
	switch email {
	case "aa8-direct@example.test":
		kind = "direct"
	case "aa8-group@example.test":
		kind = "group"
	default:
		t.Fatal("refuse non-synthetic identity")
	}
	target := "/owned-seed/aa8-" + kind + "-identity.json"
	if len(plain) < 32 || dbPassword == "" || os.Getenv("AA8_IDENTITY_RESULT") != target {
		t.Fatal("exact private fixture inputs required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", dbPassword), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal("owned database unavailable")
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("owned transaction unavailable")
	}
	defer tx.Rollback(ctx)
	var database, owner string
	var version int
	var dirty bool
	if err = tx.QueryRow(ctx, "SELECT current_database(),current_user").Scan(&database, &owner); err != nil || database != "aa0" || owner != "aa0" {
		t.Fatal("refuse non-owned database")
	}
	if err = tx.QueryRow(ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty); err != nil || version != 174 || dirty {
		t.Fatal("clean owned schema174 required")
	}
	var org uuid.UUID
	var gateways int
	if err = tx.QueryRow(ctx, "SELECT id FROM organizations WHERE slug='first-organization' AND deleted_at IS NULL").Scan(&org); err != nil {
		t.Fatal("owned organization required")
	}
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE org_id=$1 AND name='aa0-gateway' AND enrolled_kind='gateway' AND status='active'", org).Scan(&gateways); err != nil || gateways != 1 {
		t.Fatal("owned gateway required")
	}
	var user uuid.UUID
	var hash *string
	var verified, admin, wall bool
	var status string
	err = tx.QueryRow(ctx, "SELECT id,password_hash,email_verified_at IS NOT NULL,cp_admin,must_change_password,status FROM users WHERE email=$1 AND deleted_at IS NULL", email).Scan(&user, &hash, &verified, &admin, &wall, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		user = uuid.New()
		h, e := password.Hash(plain)
		if e != nil {
			t.Fatal("fixture hashing failed")
		}
		if _, err = tx.Exec(ctx, "INSERT INTO users(id,email,password_hash,email_verified_at,cp_admin,must_change_password) VALUES($1,$2,$3,now(),false,false)", user, email, h); err != nil {
			t.Fatal("fixture identity insert failed")
		}
		if _, err = tx.Exec(ctx, "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')", org, user); err != nil {
			t.Fatal("fixture membership insert failed")
		}
	} else {
		if err != nil || hash == nil || !verified || admin || wall || status != "active" {
			t.Fatal("existing fixture identity differs; refusing reset")
		}
		if _, err = password.Verify(plain, *hash); err != nil {
			t.Fatal("existing fixture credential differs; refusing reset")
		}
		var role string
		if err = tx.QueryRow(ctx, "SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2 AND access_revoked_at IS NULL", org, user).Scan(&role); err != nil || role != "member" {
			t.Fatal("existing fixture membership differs")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("fixture commit failed")
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private result unavailable")
	}
	defer f.Close()
	if err = json.NewEncoder(f).Encode(map[string]any{"org_id": org, "user_id": user, "email": email, "role": "member", "fixture_only": true}); err != nil {
		t.Fatal("private result failed")
	}
	if err = f.Sync(); err != nil {
		t.Fatal("private result sync failed")
	}
	t.Log("Synthetic member ready; review identity, grants and publication unchanged")
}
