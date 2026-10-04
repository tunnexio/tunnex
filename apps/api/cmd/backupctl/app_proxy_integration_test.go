package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func proxyCLIChildPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("owned local integration only")
	}
	password := os.Getenv("AA0_DB_PASSWORD")
	if password == "" {
		t.Fatal("owned DB password required")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, fmt.Sprintf("postgres://aa0:%s@postgres:5432/aa0?sslmode=disable", password))
	if e != nil {
		t.Fatal("owned DB unavailable")
	}
	t.Cleanup(admin.Close)
	name := "aa7_proxy_cli_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+name); e != nil {
		t.Fatal("child DB create failed")
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); e != nil {
			t.Error("child DB cleanup failed")
		}
	})
	dsn := fmt.Sprintf("postgres://aa0:%s@postgres:5432/%s?sslmode=disable", password, name)
	if e = db.MigrateTo(dsn, 175); e != nil {
		t.Fatal("child migration failed")
	}
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal("child DB connection failed")
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAppProxyCredentialLocalDatabase(t *testing.T) {
	p := proxyCLIChildPool(t)
	ctx := context.Background()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := config.Config{DatabaseURL: p.Config().ConnString(), AppAccessRestoreMarker: filepath.Join(dir, "restore.pending")}
	path := filepath.Join(dir, "proxy.credential")
	var output bytes.Buffer
	if e = appProxyCredential(ctx, cfg, "app-proxy-issue", []string{"--name", "Qualification", "--output", path}, &output); e != nil {
		t.Fatal(e)
	}
	contents, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	secret := strings.TrimSpace(string(contents))
	if !strings.HasPrefix(secret, appaccess.ProxyTokenPrefix) || output.Len() == 0 || strings.Contains(output.String(), secret) || strings.Contains(output.String(), appaccess.ProxyTokenPrefix) {
		t.Fatal("credential stdout/file boundary failed")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("credential output permissions", e)
	}
	var issued struct {
		ID      uuid.UUID `json:"id"`
		Version int64     `json:"version"`
		Name    string    `json:"name"`
	}
	if e = json.Unmarshal(output.Bytes(), &issued); e != nil || issued.ID == uuid.Nil || issued.Version != 1 || issued.Name != "Qualification" {
		t.Fatal("safe issuance metadata", e)
	}
	service := appaccess.NewService(p, appaccess.Config{})
	authenticated, e := service.AuthenticateProxy(ctx, secret)
	if e != nil || authenticated.CredentialID != issued.ID {
		t.Fatal("dedicated verifier refused issued credential")
	}
	if _, e = service.AuthenticateProxy(ctx, "Bearer "+secret); e == nil {
		t.Fatal("operator bearer accepted as dedicated family")
	}
	var count int64
	countRows := func() int64 {
		t.Helper()
		if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_proxy_credentials").Scan(&count); e != nil {
			t.Fatal(e)
		}
		return count
	}
	if countRows() != 1 {
		t.Fatal("issuance count")
	}
	refusal := func(target string) {
		t.Helper()
		output.Reset()
		if e = appProxyCredential(ctx, cfg, "app-proxy-issue", []string{"--name", "Refused", "--output", target}, &output); e == nil {
			t.Fatal("unsafe issuance accepted")
		}
		if output.Len() != 0 || countRows() != 1 {
			t.Fatal("refusal created credential/output")
		}
	}
	refusal(path)
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(after, contents) {
		t.Fatal("existing output overwritten")
	}
	link := filepath.Join(dir, "symlink.credential")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	refusal(link)
	unsafe := filepath.Join(dir, "unsafe")
	if e = os.Mkdir(unsafe, 0777); e != nil {
		t.Fatal(e)
	}
	os.Chmod(unsafe, 0777)
	refusal(filepath.Join(unsafe, "credential"))
	alias := filepath.Join(dir, "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	refusal(filepath.Join(alias, "other.credential"))
	output.Reset()
	if e = appProxyCredential(ctx, cfg, "app-proxy-revoke", []string{"--id", issued.ID.String(), "--expected-version", "2"}, &output); e == nil {
		t.Fatal("stale revoke version accepted")
	}
	if _, e = service.AuthenticateProxy(ctx, secret); e != nil {
		t.Fatal("stale revoke changed active credential")
	}
	output.Reset()
	if e = appProxyCredential(ctx, cfg, "app-proxy-revoke", []string{"--id", uuid.New().String(), "--expected-version", "1"}, &output); e == nil {
		t.Fatal("foreign credential revoke accepted")
	}
	output.Reset()
	if e = appProxyCredential(ctx, cfg, "app-proxy-revoke", []string{"--id", issued.ID.String(), "--expected-version", "1"}, &output); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), appaccess.ProxyTokenPrefix) {
		t.Fatal("revoke output leaked credential")
	}
	var revoked struct {
		ID      uuid.UUID `json:"id"`
		Version int64     `json:"version"`
		Revoked bool      `json:"revoked"`
	}
	if e = json.Unmarshal(output.Bytes(), &revoked); e != nil || revoked.ID != issued.ID || revoked.Version != 2 || !revoked.Revoked {
		t.Fatal("exact revoke metadata", e)
	}
	if _, e = service.AuthenticateProxy(ctx, secret); e == nil {
		t.Fatal("revoked credential admitted")
	}
	var audits int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE target_id=$1 AND action IN('app_access.proxy_credential_issued','app_access.proxy_credential_revoked')", issued.ID.String()).Scan(&audits); e != nil || audits != 2 {
		t.Fatal("provision/revoke audit", audits, e)
	}
}
