package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditorTransportRequiresVerifiedHTTPS(t *testing.T) {
	for _, raw := range []string{"http://cp.example", "https://user:secret@cp.example", "https://cp.example/path", "https://cp.example/?token=secret", "https://cp.example/#fragment"} {
		if _, e := editorURL(raw); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, e := editorURL("https://cp.example"); e != nil {
		t.Fatal(e)
	}
	tls, e := editorTLS("")
	if e != nil || tls.InsecureSkipVerify {
		t.Fatal("TLS verification disabled")
	}
}
func TestEditorSSHConfigPreservesUserEntries(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "config")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	old := []byte("Host existing\n  HostName existing.example\n")
	if e := os.WriteFile(path, old, 0600); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(home, "editor profiles")
	for i := 0; i < 2; i++ {
		if e := includeEditorConfig(home, dir); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(raw), "Include ") != 1 || !strings.HasSuffix(string(raw), string(old)) {
		t.Fatal("existing SSH config changed or duplicate Include")
	}
	config := editorSSHConfig("tunnex-fixture", "ubuntu", "/Applications/Tunnex CLI/tunnex", dir+"/fixture")
	for _, want := range []string{"StrictHostKeyChecking yes", "IdentitiesOnly yes", "ControlMaster auto", "ForwardAgent no", "ForwardX11 no", "GlobalKnownHostsFile /dev/null"} {
		if !strings.Contains(config, want) {
			t.Fatal("missing SSH safeguard " + want)
		}
	}
}
func TestEditorSSHConfigRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	target := filepath.Join(home, "shared")
	_ = os.WriteFile(target, []byte("original"), 0600)
	if e := os.Symlink(target, filepath.Join(home, ".ssh", "config")); e != nil {
		t.Fatal(e)
	}
	if includeEditorConfig(home, filepath.Join(home, "editor")) == nil {
		t.Fatal("accepted symlink")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "original" {
		t.Fatal("shared file changed")
	}
}
