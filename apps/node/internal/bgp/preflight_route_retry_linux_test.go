//go:build linux

package bgp

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNativePreflightRouteInstabilityCleanupThenRetry(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_RETRY_ROUTE_LAB") != "1" {
		t.Skip("explicit isolated owned namespace only")
	}
	ctx := context.Background()
	parent, err := os.MkdirTemp("/run", "tunnex-bgp-route-retry-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(parent)
	const prefix = "198.18.254.0/24"
	changed := false
	defer func() {
		if changed {
			exec.Command("/sbin/ip", "route", "del", "unreachable", prefix).Run()
		}
	}()
	reads := 0
	actualRead := func(c context.Context) ([]byte, error) {
		reads++
		if reads == 2 {
			if err := exec.CommandContext(c, "/sbin/ip", "route", "add", "unreachable", prefix).Run(); err != nil {
				return nil, err
			}
			changed = true
		}
		return preflightRoutes(c)
	}
	receipt, err := qualifyPreflight(ctx, parent, actualRead)
	if receipt != nil || err == nil || !strings.Contains(err.Error(), ": routes-after-close") || !changed {
		t.Fatal("actual route mutation did not refuse qualification")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("closed observer retained empty cleanup directory")
	}
	if err := exec.Command("/sbin/ip", "route", "del", "unreachable", prefix).Run(); err != nil {
		t.Fatal("owned route cleanup failed")
	}
	changed = false
	receipt, err = QualifyPreflight(ctx, parent)
	if err != nil || receipt == nil || !receipt.Current() {
		t.Fatal("later stable native qualification refused")
	}
	entries, err = os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("retry retained observer cleanup")
	}
}
