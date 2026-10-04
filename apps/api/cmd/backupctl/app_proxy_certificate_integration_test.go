package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
)

func TestAppProxyCertificateLocalDatabase(t *testing.T) {
	pool := proxyCLIChildPool(t)
	ctx := context.Background()
	dir := certificatePrivateDir(t)
	cfg := config.Config{DatabaseURL: pool.Config().ConnString(), SecretsDir: filepath.Join(dir, "roots"), AppAccessRestoreMarker: filepath.Join(dir, "pending.json")}
	sec, err := secrets.LoadOrInit(cfg.SecretsDir)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	call := func(destination string, deny bool) appProxyCertificateResult {
		t.Helper()
		var out bytes.Buffer
		err := appProxyCertificate(ctx, cfg, []string{"--output-dir", destination}, &out)
		if deny {
			if err == nil || out.Len() != 0 {
				t.Fatal("unsafe certificate issuance accepted or emitted metadata")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("refusal created certificate output")
			}
			return appProxyCertificateResult{}
		}
		if err != nil {
			t.Fatal(err)
		}
		var result appProxyCertificateResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.ServerName != appProxyServerName || result.CASHA256 == "" || result.LeafSHA256 == "" || result.Serial == "" {
			t.Fatal("missing safe issuance metadata")
		}
		if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "CERTIFICATE") {
			t.Fatal("stdout contains TLS material")
		}
		return result
	}
	call(filepath.Join(dir, "missing-ca"), true)
	if _, err := q.GetPlatformSecret(ctx, "agent_ca"); err == nil {
		t.Fatal("command created a CA")
	}
	ca, created, err := agentca.LoadOrCreate(ctx, q, sealer)
	if err != nil || !created {
		t.Fatal("test CA bootstrap failed")
	}
	before, err := q.GetPlatformSecret(ctx, "agent_ca")
	if err != nil {
		t.Fatal(err)
	}
	firstDir := filepath.Join(dir, "first")
	first := call(firstDir, false)
	pair, err := tls.LoadX509KeyPair(filepath.Join(firstDir, "gateway-cert.pem"), filepath.Join(firstDir, "gateway-key.pem"))
	if err != nil {
		t.Fatal("exported leaf/key do not match", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: appProxyServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal("exported certificate has wrong trust/purpose", err)
	}
	if leaf.IsCA || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != appProxyServerName {
		t.Fatal("exported certificate has excessive authority")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server leaf usable as enrolled gateway client")
	}
	publicCA, err := os.ReadFile(filepath.Join(firstDir, "agent-ca.pem"))
	if err != nil || !bytes.Equal(publicCA, ca.CertPEM()) {
		t.Fatal("public trust CA changed")
	}
	second := call(filepath.Join(dir, "second"), false)
	if second.CASHA256 != first.CASHA256 || second.LeafSHA256 == first.LeafSHA256 || second.Serial == first.Serial {
		t.Fatal("renewal did not retain CA and replace leaf")
	}
	exec := func(query string) {
		t.Helper()
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE schema_migrations SET dirty=true")
	call(filepath.Join(dir, "dirty"), true)
	exec("UPDATE schema_migrations SET dirty=false, version=172")
	call(filepath.Join(dir, "old-schema"), true)
	exec("UPDATE schema_migrations SET version=176")
	call(filepath.Join(dir, "future-schema"), true)
	exec("UPDATE schema_migrations SET version=175")
	exec("UPDATE app_access_installation_authority SET recovery_completed_at=NULL")
	call(filepath.Join(dir, "incomplete"), true)
	exec("UPDATE app_access_installation_authority SET recovery_completed_at=now()")
	cfg.MasterKey = strings.Repeat("A", 43) + "="
	call(filepath.Join(dir, "wrong-master"), true)
	cfg.MasterKey = ""
	after, err := q.GetPlatformSecret(ctx, "agent_ca")
	if err != nil || !bytes.Equal(before.SecretSealed, after.SecretSealed) || before.PublicPem == nil || after.PublicPem == nil || *before.PublicPem != *after.PublicPem {
		t.Fatal("certificate command changed enrollment root")
	}
	call(filepath.Join(dir, "after-refusals"), false)
}
