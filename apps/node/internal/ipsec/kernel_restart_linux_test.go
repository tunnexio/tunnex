//go:build linux

package ipsec

import (
	"context"
	"os"
	"testing"
)

func TestKernelRestartRestoresOnlyCompleteAbsence(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_KERNEL_APPLY_LAB") != "1" {
		t.Skip("disposable namespace only")
	}
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	p := kernelPlanFixture()
	p.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	old, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := a.RestartNeedsRecreation(ctx, p, old)
	if err != nil || missing {
		t.Fatal("intact ownership must remain unchanged", err)
	}
	if _, err = a.run(ctx, "link", "del", p.Tunnels[0].Name); err != nil {
		t.Fatal(err)
	}
	if _, err = a.RestartNeedsRecreation(ctx, p, old); err == nil {
		t.Fatal("partial survivor accepted")
	}
	if _, err = a.run(ctx, "link", "del", p.Tunnels[1].Name); err != nil {
		t.Fatal(err)
	}
	missing, err = a.RestartNeedsRecreation(ctx, p, old)
	if err != nil || !missing {
		t.Fatal("complete absence not recognized", err)
	}
	got, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil || got == old {
		t.Fatal("exclusive recreation failed", err)
	}
	if _, err = a.RestartNeedsRecreation(ctx, p, old); err == nil {
		t.Fatal("new indices adopted as old ownership")
	}
	if _, err = a.run(ctx, "link", "set", "dev", p.Tunnels[0].Name, "name", "renamed-owned"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.RestartNeedsRecreation(ctx, p, got); err == nil {
		t.Fatal("renamed survivor accepted")
	}
}
