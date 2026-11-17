package ipsec

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Only kernel reads are synthetic: all identity, return-route, no-SNAT and
// expiry checks run through the production desktop observer.
func retainedDesktopProofReader(t *testing.T, g GuardGrant, fault string, beforeRead func()) (*RuntimeController, func(string, ...string) ([]byte, error), *int) {
	t.Helper()
	c := &RuntimeController{}
	c.config.IPPath, c.config.NFTPath = "ip", "nft"
	reads := 0
	read := func(path string, args ...string) ([]byte, error) {
		reads++
		if beforeRead != nil {
			beforeRead()
			beforeRead = nil
		}
		switch command := path + " " + strings.Join(args, " "); command {
		case "wg show all allowed-ips":
			key := g.DesktopPublicKey
			if fault == "wrong key" {
				key = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
			}
			return []byte("wg0\t" + key + "\t" + g.Source.String() + "\n"), nil
		case "nft -j list table ip tunnex":
			rows := pendingNATFixture()
			if fault != "missing NAT" {
				rows = append(rows[:2], pendingNATExemption(g.Source.String(), g.Destination.String()), rows[2])
			}
			return pendingNATJSON(rows), nil
		case "ip -j -d link show dev wg0":
			return []byte(`[{"ifname":"wg0","ifindex":7777,"linkinfo":{"info_kind":"wireguard"},"flags":["UP"]}]`), nil
		case "ip -j -4 route get " + g.Source.Addr().String():
			iface := "wg0"
			if fault == "wrong route" {
				iface = "eth0"
			}
			return []byte(fmt.Sprintf(`[{"dst":%q,"dev":%q}]`, g.Source.Addr().String(), iface)), nil
		default:
			t.Fatalf("unexpected kernel read: %s", command)
			return nil, ErrRuntimeController
		}
	}
	c.desktopObserve = func(ctx context.Context, grants []GuardGrant) ([]GuardGrant, error) {
		return c.observeDesktopGrantsWithRead(ctx, grants, "wg", read)
	}
	return c, read, &reads
}

func retainedDesktopProofGrant(t *testing.T) GuardGrant {
	t.Helper()
	_, g, _ := desktopStaticFQDNFixture(t)
	g.DesktopIngressIndex = 7777
	g.FQDN.ExpiresAt = time.Now().UTC().Add(-time.Second)
	g.DesktopExpiresAt = g.FQDN.ExpiresAt
	return g
}

func TestRetainedDesktopProofPreservesExpiredDescriptorButNotFreshAdmission(t *testing.T) {
	g := retainedDesktopProofGrant(t)
	in := []GuardGrant{g}
	before := append([]GuardGrant(nil), in...)
	c, read, count := retainedDesktopProofReader(t, g, "", nil)
	if err := c.proveDesktopGrants(context.Background(), in); err != nil {
		t.Fatal("retained expired descriptor lost exact desktop ownership proof", err)
	}
	if *count != 5 || !reflect.DeepEqual(in, before) {
		t.Fatal("native ownership was skipped or caller grant/deadline changed", *count)
	}
	if _, err := c.observeDesktopGrantsWithRead(context.Background(), in, "wg", read); err == nil {
		t.Fatal("strict fresh tuple admission accepted an expired answer")
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("strict observer changed caller-owned grants")
	}
}

func TestRetainedDesktopProofRefusesIdentityAndDeadlineSubstitution(t *testing.T) {
	cases := []struct {
		name  string
		fault string
		edit  func(*GuardGrant)
	}{
		{name: "wrong key", fault: "wrong key"},
		{name: "wrong return route", fault: "wrong route"},
		{name: "missing exact NAT", fault: "missing NAT"},
		{name: "ordinary expired grant", edit: func(g *GuardGrant) { g.FQDNManaged = false; g.FQDN = FQDNGrantBinding{} }},
		{name: "malformed binding", edit: func(g *GuardGrant) { g.FQDN.RuleID = uuid.Nil }},
		{name: "mismatched deadline", edit: func(g *GuardGrant) { g.DesktopExpiresAt = g.DesktopExpiresAt.Add(time.Second) }},
		{name: "missing desktop deadline", edit: func(g *GuardGrant) { g.DesktopExpiresAt = time.Time{} }},
		{name: "future binding version", edit: func(g *GuardGrant) { g.FQDN.Version = 3 }},
		{name: "nonstatic resolver", edit: func(g *GuardGrant) { g.FQDN.ResolverKind = ""; g.FQDN.ResolverSourceAddress = "10.10.0.5" }},
		{name: "changed observed interface", edit: func(g *GuardGrant) { g.DesktopIngressIndex++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := retainedDesktopProofGrant(t)
			if tc.edit != nil {
				tc.edit(&g)
			}
			in := []GuardGrant{g}
			before := append([]GuardGrant(nil), in...)
			c, _, _ := retainedDesktopProofReader(t, g, tc.fault, nil)
			if err := c.proveDesktopGrants(context.Background(), in); err == nil {
				t.Fatal("invalid retained desktop proof accepted")
			}
			if !reflect.DeepEqual(in, before) {
				t.Fatal("refusal changed caller-owned grants/deadlines")
			}
		})
	}
}

func TestRetainedDesktopProofExpiryDuringKernelRead(t *testing.T) {
	g := retainedDesktopProofGrant(t)
	g.FQDN.ExpiresAt = time.Now().UTC().Add(40 * time.Millisecond)
	g.DesktopExpiresAt = g.FQDN.ExpiresAt
	in := []GuardGrant{g}
	before := append([]GuardGrant(nil), in...)
	crossed := false
	c, _, reads := retainedDesktopProofReader(t, g, "", func() {
		if delay := time.Until(g.FQDN.ExpiresAt); delay > 0 {
			time.Sleep(delay + time.Millisecond)
		}
		crossed = !g.FQDN.ExpiresAt.After(time.Now())
	})
	if err := c.proveDesktopGrants(context.Background(), in); err != nil || !crossed || *reads != 5 {
		t.Fatal("answer expiry during identity reads invalidated retained owner proof", err, crossed, *reads)
	}
	if !reflect.DeepEqual(in, before) || in[0].FQDN.ExpiresAt.After(time.Now()) {
		t.Fatal("retained proof revived or rewrote expired application authority")
	}
}
