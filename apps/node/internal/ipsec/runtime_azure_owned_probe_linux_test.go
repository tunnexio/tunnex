//go:build linux

package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Read-only diagnostic of an already running owned gateway. Never starts a
// daemon, stages credentials, installs nft rules, or modifies the journal.
func TestAzureOwnedNativeProbeStages(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_PROBE") != "1" {
		t.Skip("explicit owned gateway diagnostic only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := NewDaemonClient(filepath.Join(daemonRunDirectory, "charon.vici"))
	if err != nil {
		t.Fatal("stage=daemon_client result=fail")
	}
	alive := func() bool { _, e := client.Inspect(ctx); return e == nil }
	probe, err := newRuntimePlatformProbe("/sbin/ip", "/usr/sbin/nft", client, alive)
	if err != nil {
		t.Fatal("stage=constructor result=fail")
	}
	failed := false
	report := func(name string, ok bool) {
		result := "pass"
		if !ok {
			result = "fail"
			failed = true
		}
		t.Logf("stage=%s result=%s", name, result)
	}
	ns, err := probe.namespace()
	report("namespace", err == nil && validKernelNamespace(ns))
	_, err = probe.clock()
	report("clock", err == nil)
	report("daemon_alive", probe.alive())
	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"privilege", probe.privilege}, {"packaged", probe.packaged},
		{"daemon", probe.daemon}, {"kernel", probe.kernel}, {"xfrm", probe.xfrm},
		{"environment", probe.environment}, {"nft", probe.nft},
	} {
		report(step.name, step.run(ctx) == nil)
	}
	if failed {
		t.Fatal("owned native probe refused one or more stages")
	}
}
