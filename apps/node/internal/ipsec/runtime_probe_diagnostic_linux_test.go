//go:build linux

package ipsec

import (
	"context"
	"testing"
)

// Test-only diagnostic: emits stage/error names, never material or daemon payloads.
func runtimeProbeDiagnose(t *testing.T, ctx context.Context, client *DaemonClient, alive func() bool) {
	t.Helper()
	p, e := newRuntimePlatformProbe("/sbin/ip", "/usr/sbin/nft", client, alive)
	if e != nil {
		t.Log("probe constructor refused")
		return
	}
	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{{"privilege", p.privilege}, {"package", p.packaged}, {"daemon", p.daemon}, {"kernel", p.kernel}, {"xfrm", p.xfrm}, {"environment", p.environment}, {"nft-check", p.nft}} {
		e := step.run(ctx)
		t.Logf("native platform probe stage=%s result=%v", step.name, e)
	}
	inventory, inspectErr := client.Inspect(ctx)
	t.Logf("native daemon metadata daemon=%s version=%s plugins=%v inspectError=%v", inventory.Daemon, inventory.Version, inventory.Plugins, inspectErr)
	rules, re := runKernelCommand(ctx, "/sbin/ip", "-j", "-4", "rule", "show")
	t.Logf("native rule census=%s error=%v", rules, re)
	nft, ne := runKernelCommand(ctx, "/usr/sbin/nft", "-j", "list", "ruleset")
	t.Logf("native hook census=%s error=%v", nft, ne)
	ns, e := p.namespace()
	t.Logf("native platform namespace=%s error=%v alive=%v", ns, e, p.alive())
	clock, e := p.clock()
	t.Logf("native platform clocks boot=%v monotonic=%v error=%v", clock.Boot, clock.Monotonic, e)
}
