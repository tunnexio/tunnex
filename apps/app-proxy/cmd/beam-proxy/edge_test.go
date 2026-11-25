package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LS-UX-1 E.1: the edge refuses incomplete or unsafe configuration.
func TestEdgeListenerConfiguration(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "edge.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("ab", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	t.Setenv("TUNNEX_BEAM_PROXY_EDGE_TOKEN_FILE", token)
	if _, err := edgeListener(listen(), "share.test", "172.31.254.3:443"); err != nil {
		t.Fatal("valid edge refused", err)
	}
	if _, err := edgeListener(listen(), "share.test", "caddy"); err == nil {
		t.Fatal("target without port accepted")
	}
	t.Setenv("TUNNEX_BEAM_PROXY_EDGE_APP_ACCESS_DOMAIN", "apps.test")
	if _, err := edgeListener(listen(), "share.test", "172.31.254.3:443"); err == nil {
		t.Fatal("App Access route without target accepted")
	}
	t.Setenv("TUNNEX_BEAM_PROXY_EDGE_APP_ACCESS_TARGET", "app-proxy:8443")
	if _, err := edgeListener(listen(), "share.test", "172.31.254.3:443"); err != nil {
		t.Fatal("App Access route refused", err)
	}
	if err := os.Chmod(token, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeListener(listen(), "share.test", "172.31.254.3:443"); err == nil {
		t.Fatal("world-readable edge token accepted")
	}
}
