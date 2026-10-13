//go:build linux

package bgp

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessRefusesReplacedSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned native socket fixture")
	}
	// /root is a root-owned nonsymlink hierarchy, unlike world-writable /tmp.
	dir, e := os.MkdirTemp("/root", "tnx-bgp-ownership-")
	if e != nil {
		t.Skip(e)
	}
	defer os.RemoveAll(dir)
	info, e := os.Lstat(dir)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "bgpd.vty")
	socket, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	original, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	p := &Process{dir: dir, directory: info, owned: map[string]os.FileInfo{"bgpd.vty": original}}
	if !p.vtyOwned() {
		t.Fatal("owned socket refused")
	}
	if e = os.Rename(path, path+".original"); e != nil {
		t.Fatal(e)
	}
	replacement, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer replacement.Close()
	os.Chmod(path, 0600)
	if p.vtyOwned() {
		t.Fatal("replaced socket accepted")
	}
	if e = p.Close(); e == nil {
		t.Fatal("foreign socket cleanup accepted")
	}
	if _, e = os.Lstat(path); e != nil {
		t.Fatal("foreign socket removed")
	}
}
