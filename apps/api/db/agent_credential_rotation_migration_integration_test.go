package db_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestAgentCredentialRotationMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0094 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}

	newDB := func(label string) (string, *pgxpool.Pool) {
		t.Helper()
		name := "tnx_f05_" + label + "_" + uuid.NewString()[:8]
		if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
		u := *base
		u.Path = "/" + name
		pool, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return u.String(), pool
	}
	seedCredential := func(pool *pgxpool.Pool, label string) (uuid.UUID, []byte) {
		t.Helper()
		org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		hash := sha256.Sum256([]byte("tnx_runtime_" + device.String()))
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,$2,$3,'10.111.0.0/24')`, []any{org, label, label + "-" + org.String()[:8]}},
			{`INSERT INTO users (id,email) VALUES ($1,$2)`, []any{user, label + "-" + user.String()[:8] + "@example.com"}},
			{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,$3,$4)`, []any{node, org, label + "-gw", label + "-cert-" + node.String()}},
			{`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,$5,$6,'10.111.0.2','active','agent')`, []any{device, org, user, node, label + "-agent", label + "-key"}},
			{`INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash) VALUES ($1,$2,$3)`, []any{org, device, hash[:]}},
		}
		for _, statement := range statements {
			if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed %s: %v", label, err)
			}
		}
		return device, hash[:]
	}

	successDSN, successPool := newDB("success")
	if err := db.MigrateTo(successDSN, 94); err != nil {
		t.Fatal(err)
	}
	successDevice, successHash := seedCredential(successPool, "success")
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("pristine 0094 rollback: %v", err)
	}
	var stored []byte
	if err := successPool.QueryRow(ctx, `SELECT token_hash FROM agent_runtime_credentials WHERE device_id=$1`, successDevice).Scan(&stored); err != nil || !bytes.Equal(stored, successHash) {
		t.Fatalf("pristine rollback hash preservation: %x, %v", stored, err)
	}
	if err := db.MigrateTo(successDSN, 94); err != nil {
		t.Fatalf("0094 reapply: %v", err)
	}
	var revision int64
	var state string
	if err := successPool.QueryRow(ctx, `SELECT revision,state FROM agent_runtime_credentials WHERE device_id=$1`, successDevice).Scan(&revision, &state); err != nil || revision != 1 || state != "current" {
		t.Fatalf("reapplied legacy state = %d/%s, %v", revision, state, err)
	}
	for n := 2; n <= 13; n++ {
		h := sha256.Sum256([]byte{byte(n)})
		if _, err := successPool.Exec(ctx, `INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash,revision,state,terminal_at,revoked_at) SELECT org_id,device_id,$2,$3,'revoked',now(),now() FROM agent_runtime_credentials WHERE device_id=$1 AND state='current'`, successDevice, h[:], n); err != nil {
			t.Fatalf("seed bounded history %d: %v", n, err)
		}
	}
	var terminalCount int
	if err := successPool.QueryRow(ctx, `SELECT count(*) FROM agent_runtime_credentials WHERE device_id=$1 AND state IN ('superseded','revoked')`, successDevice).Scan(&terminalCount); err != nil || terminalCount != 10 {
		t.Fatalf("bounded terminal history count=%d err=%v, want 10", terminalCount, err)
	}

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 94); err != nil {
		t.Fatal(err)
	}
	refuseDevice, refuseHash := seedCredential(refusePool, "refuse")
	if _, err := refusePool.Exec(ctx, `UPDATE agent_runtime_credentials SET rotation_requested_at=now(),rotation_deadline=now()+interval '1 hour',rotation_requested_by=(SELECT user_id FROM devices WHERE id=$1) WHERE device_id=$1`, refuseDevice); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0094 rollback must refuse after a rotation request")
	}
	if err := refusePool.QueryRow(ctx, `SELECT token_hash FROM agent_runtime_credentials WHERE device_id=$1`, refuseDevice).Scan(&stored); err != nil || !bytes.Equal(stored, refuseHash) {
		t.Fatalf("refused rollback hash preservation: %x, %v", stored, err)
	}
	var requestPreserved bool
	if err := refusePool.QueryRow(ctx, `SELECT rotation_requested_at IS NOT NULL FROM agent_runtime_credentials WHERE device_id=$1`, refuseDevice).Scan(&requestPreserved); err != nil || !requestPreserved {
		t.Fatalf("refused rollback request preservation = %v, %v", requestPreserved, err)
	}
}
