//go:build linux

package ipsec

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// Exercise the actual supervisor-generated configuration, not a separate
	// test template. IKEv2 DPD uses this retry schedule, not dpd_timeout.
	config, err := os.ReadFile(filepath.Join(daemonRunDirectory, "strongswan.conf"))
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]float64{}
	for _, line := range strings.Split(string(config), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && strings.HasPrefix(fields[0], "retransmit_") && fields[1] == "=" {
			value, err := strconv.ParseFloat(fields[2], 64)
			if err != nil {
				t.Fatal("invalid retransmission setting", err)
			}
			settings[fields[0]] = value
		}
	}
	first, base, tries := settings["retransmit_timeout"], settings["retransmit_base"], settings["retransmit_tries"]
	if first < 1 || base < 1 || tries < 3 || tries > 5 || math.Trunc(tries) != tries {
		t.Fatal("missing bounded retry configuration or insufficient transient-loss tolerance")
	}
	var retrySeconds float64
	for attempt := 0; attempt <= int(tries); attempt++ {
		retrySeconds += first * math.Pow(base, float64(attempt))
	}
	if retrySeconds > 20 {
		t.Fatalf("IKEv2 silent-peer retry budget %.2fs exceeds 20s", retrySeconds)
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
