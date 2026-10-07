package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBeamDevelopmentTrustRemainsOptInAndLocal(t *testing.T) {
	for _, env := range []string{"production", "development", "test"} {
		data, allowed, err := (Config{Env: env}).BeamDevelopmentTrust()
		if err != nil || allowed || len(data) != 0 {
			t.Fatal("default trust changed")
		}
	}
	for _, c := range []Config{{Env: "production", BeamDevAllowLoopback: true, BeamDevPublicCAFile: "/private/fixture"}, {Env: "test", BeamDevAllowLoopback: true, BeamDevPublicCAFile: "/private/fixture"}, {Env: "development", BeamDevAllowLoopback: true}, {Env: "development", BeamDevPublicCAFile: "/private/fixture"}, {Env: "development", BeamDevAllowLoopback: true, BeamDevPublicCAFile: "relative.pem"}} {
		if _, _, err := c.BeamDevelopmentTrust(); err == nil {
			t.Fatal("unsafe or incomplete development configuration accepted")
		}
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "roots.pem")
	if err = os.WriteFile(path, []byte("fixture bytes validated by the CA-only inspector factory"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{Env: "development", BeamDevAllowLoopback: true, BeamDevPublicCAFile: path}
	data, allowed, err := c.BeamDevelopmentTrust()
	if err != nil || !allowed || !strings.HasPrefix(string(data), "fixture bytes") {
		t.Fatal("fixed local trust file not loaded")
	}
	link := filepath.Join(dir, "link.pem")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	c.BeamDevPublicCAFile = link
	if _, _, err = c.BeamDevelopmentTrust(); err == nil {
		t.Fatal("symlink trust path accepted")
	}
	c.BeamDevPublicCAFile = path
	if err = os.WriteFile(path, make([]byte, (64<<10)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.BeamDevelopmentTrust(); err == nil {
		t.Fatal("oversized trust file accepted")
	}
}

func TestBeamDevelopmentEnvironmentSettings(t *testing.T) {
	t.Setenv("TUNNEX_ENV", "production")
	t.Setenv("TUNNEX_BEAM_DEV_ALLOW_LOOPBACK", "true")
	t.Setenv("TUNNEX_BEAM_DEV_PUBLIC_CA_FILE", "/private/fixture.pem")
	c := Load()
	if !c.BeamDevAllowLoopback || c.BeamDevPublicCAFile != "/private/fixture.pem" {
		t.Fatal("explicit configuration missing")
	}
	if _, _, err := c.BeamDevelopmentTrust(); err == nil {
		t.Fatal("production enabled development trust")
	}
}
