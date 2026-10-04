package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/config"
)

func certificatePrivateDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAppProxyCertificateExistingMasterOnly(t *testing.T) {
	dir := certificatePrivateDir(t)
	cfg := config.Config{SecretsDir: dir}
	if _, err := existingCertificateMaster(cfg); err == nil {
		t.Fatal("missing master accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("master loader created a root of trust")
	}
	key := bytes.Repeat([]byte{7}, 32)
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte(encoded+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := existingCertificateMaster(cfg)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("existing volume master not loaded")
	}
	cfg.MasterKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	got, err = existingCertificateMaster(cfg)
	if err != nil || got[0] != 8 {
		t.Fatal("inline override precedence failed")
	}
	cfg.MasterKeyFile = filepath.Join(dir, "master.key")
	got, err = existingCertificateMaster(cfg)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("file override precedence failed")
	}
	cfg.MasterKeyFile = filepath.Join(dir, "absent")
	if _, err := existingCertificateMaster(cfg); err == nil {
		t.Fatal("missing external file fell back to inline/volume")
	}
	cfg.MasterKeyFile = ""
	for _, bad := range []string{"not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		cfg.MasterKey = bad
		if _, err := existingCertificateMaster(cfg); err == nil {
			t.Fatal("malformed external key fell back to volume")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "session.key")); !os.IsNotExist(err) {
		t.Fatal("unrelated session secret initialized")
	}
}

func TestAppProxyCertificateExclusivePrivateFiles(t *testing.T) {
	dir := certificatePrivateDir(t)
	destination := filepath.Join(dir, "leaf")
	if err := writeCertificateOutput(destination, []byte("leaf"), []byte("secret"), []byte("ca")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("output directory is not private")
	}
	for _, name := range []string{"gateway-cert.pem", "gateway-key.pem", "agent-ca.pem"} {
		info, err := os.Lstat(filepath.Join(destination, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("output file is not private/regular")
		}
	}
	if err := writeCertificateOutput(destination, []byte("other"), []byte("other"), []byte("other")); err == nil {
		t.Fatal("existing output overwritten")
	}
	got, err := os.ReadFile(filepath.Join(destination, "gateway-key.pem"))
	if err != nil || string(got) != "secret" {
		t.Fatal("rejected retry changed existing output")
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(destination, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{link, filepath.Join(link, "new"), "relative", filepath.Join(dir, "missing", "leaf")} {
		if err := validateCertificateOutput(bad); err == nil {
			t.Fatalf("unsafe output accepted: %s", bad)
		}
	}
	unsafe := filepath.Join(dir, "public")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateOutput(filepath.Join(unsafe, "leaf")); err == nil {
		t.Fatal("public output parent accepted")
	}
}

func TestAppProxyCertificateRestoreBarrierBeforeAuthority(t *testing.T) {
	dir := certificatePrivateDir(t)
	cfg := config.Config{AppAccessRestoreMarker: filepath.Join(dir, "pending.json"), DatabaseURL: "must-not-be-contacted"}
	if err := os.WriteFile(cfg.AppAccessRestoreMarker, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "leaf")
	var out bytes.Buffer
	if err := appProxyCertificate(context.Background(), cfg, []string{"--output-dir", destination}, &out); err == nil || out.Len() != 0 {
		t.Fatal("restore barrier allowed issuance")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("barrier refusal left output")
	}
}
