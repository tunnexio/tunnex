//go:build linux

package helper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLinuxPeerResolver exercises the real SO_PEERCRED → /proc/<pid>/exe path over
// a live unix socket. Both ends are this test process, so the resolved peer path
// must equal this test binary (/proc/self/exe). Verifies the getsockopt plumbing
// the other platforms mirror.
func TestLinuxPeerResolver(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	resolve := NewPeerResolver()
	got := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		p, err := resolve(c)
		if err != nil {
			errc <- err
			return
		}
		got <- p
	}()

	cc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	self, _ := os.Readlink("/proc/self/exe")
	select {
	case p := <-got:
		if p != self {
			t.Fatalf("resolved peer path %q != self %q", p, self)
		}
	case e := <-errc:
		t.Fatalf("resolve: %v", e)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}
