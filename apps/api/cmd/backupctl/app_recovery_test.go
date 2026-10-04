package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
)

func privateRecoveryPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "app-access.pending.json")
}

func TestAppRestoreBeginUsesConfiguredPrivateBarrierAndRefusesReplay(t *testing.T) {
	path := privateRecoveryPath(t)
	cfg := config.Config{AppAccessRestoreMarker: path}
	var out bytes.Buffer
	if err := appRestoreBegin(cfg, []string{"--barrier", path + ".other"}, &out); err == nil {
		t.Fatal("accepted a different barrier")
	}
	if out.Len() != 0 {
		t.Fatal("failed begin emitted output")
	}
	if err := appRestoreBegin(cfg, []string{"--barrier", path}, &out); err != nil {
		t.Fatal(err)
	}
	var marker backup.AppRestoreMarker
	if err := json.Unmarshal(out.Bytes(), &marker); err != nil || marker.ID == uuid.Nil {
		t.Fatal("missing fresh marker identity", err)
	}
	original, err := os.Stat(path)
	if err != nil || original.Mode().Perm() != 0600 {
		t.Fatal("marker is not private", err)
	}
	before := append([]byte(nil), out.Bytes()...)
	if err := appRestoreBegin(cfg, []string{"--barrier", path}, &out); err == nil {
		t.Fatal("replaced existing barrier")
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(original, current) || !bytes.Equal(before, out.Bytes()) {
		t.Fatal("replay altered the retained barrier or output")
	}
}

func TestRecoveryRefusesWrongBarrierIdentityBeforeDatabaseAccess(t *testing.T) {
	path := privateRecoveryPath(t)
	marker, err := backup.BeginAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AppAccessRestoreMarker: path, DatabaseURL: "this must never be contacted"}
	for _, id := range []string{"not-a-uuid", uuid.Nil.String(), uuid.NewString()} {
		var out bytes.Buffer
		err := appRecovery(context.Background(), cfg, []string{"--barrier", path, "--barrier-id", id, "--operator", "owned-test"}, &out)
		if err == nil || out.Len() != 0 {
			t.Fatal("invalid recovery was accepted or emitted success")
		}
		retained, _, err := backup.ReadAppRestore(path)
		if err != nil || retained.ID != marker.ID {
			t.Fatal("invalid recovery removed or replaced the marker")
		}
	}
	var out bytes.Buffer
	if err := appProxyCredential(context.Background(), cfg, "app-proxy-issue", []string{"--name", "owned", "--output", filepath.Join(filepath.Dir(path), "credential")}, &out); err == nil || out.Len() != 0 {
		t.Fatal("credential issuance ignored the restore barrier")
	}
}
