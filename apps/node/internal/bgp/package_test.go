package bgp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProbeRefusesUnsafePackage(t *testing.T) {
	version := func(context.Context, string) (string, error) { t.Fatal("unsafe executable ran"); return "", nil }
	for _, path := range []string{"relative", "/does-not-exist/tunnex-bgpd"} {
		if probePackage(context.Background(), path, "arm64", version) == nil {
			t.Fatal("unsafe package accepted")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bgpd")
	if e := os.WriteFile(path, []byte("foreign binary"), 0777); e != nil {
		t.Fatal(e)
	}
	if probePackage(context.Background(), path, "arm64", version) == nil {
		t.Fatal("writable package accepted")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if probePackage(context.Background(), link, "arm64", version) == nil {
		t.Fatal("symlink package accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probePackage(ctx, path, "arm64", version) == nil {
		t.Fatal("canceled probe accepted")
	}
}
func TestVersionOutputBound(t *testing.T) {
	var out boundedOutput
	if _, e := out.Write(make([]byte, 4097)); e == nil {
		t.Fatal("unbounded daemon output")
	}
}

// Opt-in real package proof runs in the disposable Linux package image.
func TestBundledPackage(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_PACKAGE_TEST") != "1" {
		t.Skip("requires pinned Linux package image")
	}
	if err := ProbePackage(context.Background()); err != nil {
		t.Fatal(err)
	}
	badVersion := func(context.Context, string) (string, error) { return "bgpd version 10.7.0\n", nil }
	if probePackage(context.Background(), Executable, runtime.GOARCH, badVersion) == nil {
		t.Fatal("different FRR version accepted")
	}
	if err := os.Chmod(Executable, 0777); err != nil {
		t.Fatal(err)
	}
	if ProbePackage(context.Background()) == nil {
		t.Fatal("writable native binary accepted")
	}
	if err := os.Chmod(Executable, 0755); err != nil {
		t.Fatal(err)
	}
	backup := Executable + ".real"
	if err := os.Rename(Executable, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, Executable); err != nil {
		t.Fatal(err)
	}
	if ProbePackage(context.Background()) == nil {
		t.Fatal("native binary symlink accepted")
	}
	if err := os.Remove(Executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, Executable); err != nil {
		t.Fatal(err)
	}
	if probePackage(context.Background(), Executable, "unknown", packageVersion) == nil {
		t.Fatal("foreign architecture accepted")
	}
}
