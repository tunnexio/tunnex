//go:build linux

package ipsec

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestKernelApplyLinuxOwnership(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_KERNEL_APPLY_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	p := kernelPlanFixture()
	p.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if _, err := a.run(ctx, args...); err != nil {
			t.Fatalf("fixture command %v", args)
		}
	}
	run("link", "add", "fixture-foreign", "type", "dummy")
	got, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil {
		for _, args := range [][]string{{"-j", "-d", "link", "show"}, {"-j", "addr", "show"}, {"-j", "-d", "-N", "-4", "route", "show", "table", "all"}, {"-j", "-d", "-N", "-6", "route", "show", "table", "all"}} {
			out, _ := a.run(ctx, args...)
			t.Logf("readback %v: %s", args, out)
		}
		t.Fatal(err)
	}
	assertMTU := func() {
		t.Helper()
		raw, err := a.run(ctx, "-j", "-d", "link", "show")
		if err != nil {
			t.Fatal(err)
		}
		objects, ok := kernelObjects(raw)
		if !ok {
			t.Fatal("invalid links")
		}
		for _, tunnel := range p.Tunnels {
			found := false
			for _, obj := range objects {
				name, _ := kernelString(obj, "ifname")
				if name != tunnel.Name {
					continue
				}
				mtu, ok := kernelNumber(obj["mtu"], 32)
				if !ok || mtu != 1422 {
					t.Fatalf("owned tunnel MTU = %d, want AWS NAT-T ceiling 1422", mtu)
				}
				found = true
			}
			if !found {
				t.Fatal("missing owned link")
			}
		}
	}
	assertMTU()
	// Legacy allocations had the kernel default; reapply must converge without
	// replacing their interface identity or changing unrelated interfaces.
	run("link", "set", "dev", p.Tunnels[0].Name, "mtu", "1500")
	again, err := a.Apply(ctx, p, got)
	if err != nil || got != again {
		t.Fatal("idempotent apply failed", err)
	}
	assertMTU()
	run("link", "set", "dev", p.Tunnels[0].Name, "mtu", "1300")
	if _, err = a.Apply(ctx, p, got); err != nil {
		t.Fatal(err)
	}
	raw, err := a.run(ctx, "-j", "-d", "link", "show", "dev", p.Tunnels[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	objects, ok := kernelObjects(raw)
	if !ok || len(objects) != 1 {
		t.Fatal("invalid MTU readback")
	}
	mtu, ok := kernelNumber(objects[0]["mtu"], 32)
	if !ok || mtu != 1300 {
		t.Fatal("raised a smaller operator-qualified MTU")
	}
	run("link", "set", "dev", p.Tunnels[0].Name, "alias", "foreign-owner")
	if _, err = a.Remove(ctx, p, got); err != ErrKernelApply {
		t.Fatal("foreign alias removed")
	}
	run("link", "set", "dev", p.Tunnels[0].Name, "alias", p.Tunnels[0].Alias)
	run("-4", "route", "add", "198.18.0.0/24", "dev", p.Tunnels[0].Name, "proto", "99")
	if _, err = a.Remove(ctx, p, got); err != ErrKernelApply {
		t.Fatal("foreign attached route removed")
	}
	run("-4", "route", "del", "198.18.0.0/24", "dev", p.Tunnels[0].Name, "proto", "99")
	absence, err := a.Remove(ctx, p, got)
	if err != nil || absence.Generation != p.Generation {
		t.Fatal("exact cleanup failed", err)
	}
	if _, err = a.Remove(ctx, p, got); err != nil {
		t.Fatal("cleanup retry failed", err)
	}
	run("link", "show", "dev", "fixture-foreign")
	t.Log("PASS exact native allocation, idempotency, foreign alias/route refusal, owned cleanup and unrelated link preservation")
}
