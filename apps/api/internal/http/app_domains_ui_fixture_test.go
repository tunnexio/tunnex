package http

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
)

// Explicitly opted-in CP admin for the owned local domain-settings browser fixture.
// Existing identities, bootstrap credentials and memberships are never changed.
func TestAppAccessLocalDomainAdminSeed(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_DOMAIN_ADMIN_SEED") != "1" {
		t.Skip("explicit owned local UI seed only")
	}
	dbPassword := os.Getenv("AA0_DB_PASSWORD")
	plain := os.Getenv("AA_DOMAIN_ADMIN_PASSWORD")
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" {
		t.Fatal("unexpected domain fixture ownership")
	}
	if dbPassword == "" || len(plain) < 32 || os.Getenv("AA_DOMAIN_ADMIN_EMAIL") != "aa-domains-admin@example.test" {
		t.Fatal("owned UI seed inputs missing")
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", dbPassword), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal("owned PostgreSQL configuration rejected")
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("owned database unavailable")
	}
	defer tx.Rollback(ctx)
	var db, user string
	if err = tx.QueryRow(ctx, "SELECT current_database(),current_user").Scan(&db, &user); err != nil || db != "aa0" || user != "aa0" {
		t.Fatal("refuse non-owned database")
	}
	var org uuid.UUID
	var count int
	if err = tx.QueryRow(ctx, "SELECT id FROM organizations WHERE slug='first-organization'").Scan(&org); err != nil {
		t.Fatal("owned bootstrap org missing")
	}
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE org_id=$1 AND name='aa0-gateway' AND status='active' AND enrolled_kind='gateway'", org).Scan(&count); err != nil || count != 1 {
		t.Fatal("owned active gateway missing")
	}
	const email = "aa-domains-admin@example.test"
	var id uuid.UUID
	var hash *string
	var verified, cpAdmin, wall bool
	var status string
	err = tx.QueryRow(ctx, "SELECT id,password_hash,email_verified_at IS NOT NULL,cp_admin,must_change_password,status FROM users WHERE email=$1", email).Scan(&id, &hash, &verified, &cpAdmin, &wall, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		id = uuid.New()
		h, e := password.Hash(plain)
		if e != nil {
			t.Fatal("UI password hashing failed")
		}
		if _, err = tx.Exec(ctx, "INSERT INTO users(id,email,password_hash,email_verified_at,cp_admin,must_change_password) VALUES($1,$2,$3,now(),true,false)", id, email, h); err != nil {
			t.Fatal("UI account insert failed")
		}
		if _, err = tx.Exec(ctx, "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')", org, id); err != nil {
			t.Fatal("UI membership insert failed")
		}
	} else if err != nil {
		t.Fatal("UI identity lookup failed")
	} else {
		if hash == nil || !verified || !cpAdmin || wall || status != "active" {
			t.Fatal("existing UI identity does not match fixture; refusing mutation")
		}
		// Verify returns needsRehash, not success; mismatches return ErrMismatch.
		if _, err = password.Verify(plain, *hash); err != nil {
			t.Fatal("existing UI credential differs; refusing reset")
		}
		var role string
		if err = tx.QueryRow(ctx, "SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2", org, id).Scan(&role); err != nil || role != "owner" {
			t.Fatal("existing UI membership differs; refusing mutation")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("UI seed transaction failed")
	}
	t.Log("Owned local domain-admin account ready; existing accounts and bootstrap credentials unchanged")
}
