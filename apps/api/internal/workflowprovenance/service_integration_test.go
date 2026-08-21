package workflowprovenance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestReportPersistsVerifiedAndUnverifiedEvidence(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F15 database proof")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := "tnx_f15_provenance_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") })
	fresh := *base
	fresh.Path = "/" + dbName
	if err := db.MigrateTo(fresh.String(), 104); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, fresh.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F15',$2,'10.124.0.0/24')`, org, "f15-"+org.String()[:8])
	seed(`INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F15','active')`, user, user.String()+"@f15.test")
	seed(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw',$3)`, node, org, "f15-"+node.String())
	seed(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.124.0.2','active','agent')`, device, org, user, node, "f15-"+device.String())

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	claims := fixtureClaims(now)
	svc := New(pool)
	svc.now = func() time.Time { return now }
	if err := svc.RegisterKey(ctx, org, device, claims.KeyID, public); err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterKey(ctx, org, device, claims.KeyID, public); err != nil {
		t.Fatalf("same key must be idempotent: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := svc.RegisterKey(ctx, org, device, claims.KeyID, other); !errors.Is(err, ErrKeyAlreadyRegistered) {
		t.Fatalf("replacement err=%v", err)
	}

	assertion, err := Sign(private, claims)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := svc.Report(ctx, org, device, assertion)
	if err != nil || verified.State != "verified" || verified.Reason != "verified" {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	replay, err := svc.Report(ctx, org, device, assertion)
	if err != nil || replay.State != "unverified" || replay.Reason != "replay" {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	tampered := assertion
	tampered.Claims.Tool = "delete_account"
	bad, err := svc.Report(ctx, org, device, tampered)
	if err != nil || bad.State != "unverified" || bad.Reason != "bad_signature" {
		t.Fatalf("bad=%#v err=%v", bad, err)
	}
	rows, err := sqlc.New(pool).ListAgentWorkflowProvenance(ctx, sqlc.ListAgentWorkflowProvenanceParams{OrgID: org, DeviceID: device, PageSize: 10})
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	projection, err := svc.List(ctx, org, device)
	if err != nil || len(projection) != 3 || projection[0].State != "unverified" || projection[0].Chain != nil || projection[2].State != "verified" || projection[2].Chain == nil {
		t.Fatalf("safe projection=%#v err=%v", projection, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_workflow_provenance WHERE id=$1`, rows[0].ID); err == nil {
		t.Fatal("direct provenance deletion unexpectedly succeeded")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org); err != nil {
		t.Fatalf("organization cascade must retain normal lifecycle cleanup: %v", err)
	}
}
