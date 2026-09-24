//go:build linux

package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonProcessRejectsNonprivateDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := startDaemonProcess(context.Background(), dir, "/does/not/exist"); err != ErrDaemonProcess {
		t.Fatal("unsafe directory accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "strongswan.conf")); !os.IsNotExist(err) {
		t.Fatal("mutated before path validation")
	}
}
func TestDaemonProcessNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_PROCESS_LAB") != "1" {
		t.Skip("disposable namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !p.Alive() {
		t.Fatal("child not alive")
	}
	inventory, err := p.Client.Inspect(ctx)
	if err != nil || inventory.Version != "6.1.0" || len(inventory.SAs) != 0 {
		t.Fatal("native startup unavailable", err)
	}
	if _, err := StartDaemonProcess(ctx); err != ErrDaemonProcess {
		t.Fatal("second supervisor accepted")
	}
	if err = p.Close(); err != nil || p.Alive() {
		t.Fatal("owned child stop failed", err)
	}
	again, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("clean restart refused", err)
	}
	if err = again.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS dedicated native daemon private socket, exclusive ownership, stop and clean restart")
}
