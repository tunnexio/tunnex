//go:build linux

package reconcile

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestWGCtrlReadbackUsesOwnedRouteAndRuleEnumerators(t *testing.T) {
	ctx := context.Background()
	var calls []string
	backend := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "wg show wg0 dump":
			return "priv\tpub\t51820\toff\npeer-b\t(none)\t198.51.100.2:51820\t100.64.0.0/24,10.99.0.2/32\t0\t0\t0\t25\n", nil
		case "ip -4 route show dev wg0 proto static metric 8021":
			return "100.64.0.2 dev wg0 proto static metric 8021\n10.20.0.0/16 dev wg0 proto static metric 8021\n", nil
		case "ip -6 route show dev wg0 proto static metric 8021":
			return "2001:db8::2 dev wg0 proto static metric 8021\n", nil
		case "ip -4 rule show pref 100":
			return "100: from all to 10.99.0.7 lookup main\n100: from all fwmark 0x80 lookup main\n100: from all to 192.0.2.0/24 lookup 100\n", nil
		case "ip -6 rule show pref 100":
			return "100: from all to 2001:db8::/64 lookup main\n", nil
		default:
			return "", nil
		}
	}}

	got, err := backend.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || got.Peers[0].PublicKey != "peer-b" ||
		!reflect.DeepEqual(got.Peers[0].AllowedIPs, []string{"100.64.0.0/24", "10.99.0.2/32"}) ||
		got.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("peer readback = %+v", got.Peers)
	}
	wantRoutes := []string{"10.20.0.0/16", "100.64.0.2/32", "2001:db8::2/128"}
	if !reflect.DeepEqual(got.Routes, wantRoutes) {
		t.Fatalf("routes = %v, want %v", got.Routes, wantRoutes)
	}
	wantDetails := []OwnedRoute{
		{Family: "ipv4", Destination: "10.20.0.0/16", Device: "wg0", Protocol: "static", Metric: 8021},
		{Family: "ipv4", Destination: "100.64.0.2/32", Device: "wg0", Protocol: "static", Metric: 8021},
		{Family: "ipv6", Destination: "2001:db8::2/128", Device: "wg0", Protocol: "static", Metric: 8021},
	}
	if !reflect.DeepEqual(got.RouteDetails, wantDetails) {
		t.Fatalf("route details = %+v, want structured ownership proof %+v", got.RouteDetails, wantDetails)
	}
	wantRules := []ReturnRule{
		{Priority: 100, Destination: "10.99.0.7/32", Lookup: "main"},
		{Priority: 100, Destination: "2001:db8::/64", Lookup: "main"},
	}
	if !reflect.DeepEqual(got.ReturnRules, wantRules) {
		t.Fatalf("rules = %+v, want exact owned shapes %+v", got.ReturnRules, wantRules)
	}
	for _, want := range []string{
		"ip -4 route show dev wg0 proto static metric 8021",
		"ip -6 route show dev wg0 proto static metric 8021",
		"ip -4 rule show pref 100",
		"ip -6 rule show pref 100",
	} {
		if !containsString(calls, want) {
			t.Fatalf("readback did not use ApplyRoutes ownership enumeration %q; calls=%v", want, calls)
		}
	}
	for _, call := range calls {
		if strings.Contains(call, " route show ") &&
			!strings.Contains(call, " dev wg0 proto static metric 8021") {
			t.Fatalf("readback must not broaden route enumeration to unrelated routes: %q", call)
		}
	}
}

func TestWGCtrlReadbackRejectsRouteWithoutExactOwnershipAttributes(t *testing.T) {
	for _, listing := range []string{
		"10.20.0.0/16 dev wg1 proto static metric 8021\n",
		"10.20.0.0/16 dev wg0 proto boot metric 8021\n",
		"10.20.0.0/16 dev wg0 proto static metric 99\n",
		"10.20.0.0/16 dev wg0 proto static metric 8021 src 2001:db8::1\n",
	} {
		backend := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
			call := name + " " + strings.Join(args, " ")
			switch call {
			case "wg show wg0 dump":
				return "priv\tpub\t51820\toff\n", nil
			case "ip -4 route show dev wg0 proto static metric 8021":
				return listing, nil
			default:
				return "", nil
			}
		}}
		if _, err := backend.Readback(t.Context()); err == nil {
			t.Fatalf("route %q must fail closed", strings.TrimSpace(listing))
		}
	}
}

func TestWGCtrlReadbackSurfacesIncompleteIPv4Enumeration(t *testing.T) {
	ctx := context.Background()
	for _, failing := range []string{"route", "rule"} {
		t.Run(failing, func(t *testing.T) {
			backend := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
				call := name + " " + strings.Join(args, " ")
				if call == "wg show wg0 dump" {
					return "priv\tpub\t51820\toff\n", nil
				}
				if strings.HasPrefix(call, "ip -4 "+failing+" show") {
					return "", errors.New("enumeration unavailable")
				}
				return "", nil
			}}
			if _, err := backend.Readback(ctx); err == nil {
				t.Fatalf("incomplete IPv4 %s enumeration must fail readback", failing)
			}
		})
	}
}

func TestWGCtrlMissingInterfaceIsAlreadyWithdrawn(t *testing.T) {
	ctx := context.Background()
	var calls []string
	backend := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "wg show wg0 dump":
			return "Unable to access interface: No such device", errors.New("wg show wg0 dump: exit status 1: Unable to access interface: No such device")
		case "ip -4 route show dev wg0 proto static metric 8021",
			"ip -6 route show dev wg0 proto static metric 8021":
			return `Error: Device "wg0" does not exist.`, errors.New(`ip route show: exit status 1: Error: Device "wg0" does not exist.`)
		case "ip -4 rule show pref 100":
			return "100: from all to 10.99.0.0/24 lookup main\n", nil
		case "ip -6 rule show pref 100":
			return "", nil
		case "ip -4 rule del pref 100 to 10.99.0.0/24 lookup main":
			return "", nil
		default:
			return "", nil
		}
	}}

	got, err := backend.Readback(ctx)
	if err != nil {
		t.Fatalf("absent interface must be a valid zero WireGuard readback: %v", err)
	}
	if len(got.Peers) != 0 || len(got.Routes) != 0 || len(got.RouteDetails) != 0 || len(got.ReturnRules) != 1 {
		t.Fatalf("unexpected absent-interface readback: %+v", got)
	}
	if err := backend.ApplyPeers(ctx, nil); err != nil {
		t.Fatalf("withdrawing peers from an absent interface must be idempotent: %v", err)
	}
	if err := backend.ApplyRoutes(ctx, nil, ""); err != nil {
		t.Fatalf("withdrawing routes from an absent interface must be idempotent: %v", err)
	}
	if !containsString(calls, "ip -4 rule del pref 100 to 10.99.0.0/24 lookup main") {
		t.Fatalf("absent interface must not hide an owned return rule: calls=%v", calls)
	}
}

func TestWGCtrlMissingInterfaceDoesNotHideOtherFailures(t *testing.T) {
	backend := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
		if name == "wg" {
			return "permission denied", errors.New("exit status 1")
		}
		return "", nil
	}}
	if _, err := backend.Readback(t.Context()); err == nil {
		t.Fatal("an unproven readback failure must remain fatal")
	}
	if err := backend.ApplyPeers(t.Context(), nil); err == nil {
		t.Fatal("an unproven empty-peer apply failure must remain fatal")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
