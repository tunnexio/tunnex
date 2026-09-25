//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// Explicit opt-in is only set by the disconnected, disposable container harness.
func TestGuardLinuxReadback(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_GUARD_LAB") != "1" {
		t.Skip("isolated Linux guard lab only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := func(input string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
		if input != "" {
			cmd.Stdin = bytes.NewBufferString(input)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v: %s", args, err, out)
		}
		return out
	}
	// Refuse any existing firewall namespace: never flush unrelated objects.
	empty := run("", "-j", "list", "tables")
	if bytes.Contains(empty, []byte(`"table"`)) {
		t.Fatal("fixture contains an existing table")
	}
	reader, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := reader.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Links) != 2 {
		t.Fatal("fixture must contain exactly two XFRM interfaces")
	}
	intent := GuardIntent{OwnerID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Revision: 1, Connections: []GuardConnection{{ID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), Local: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}}}
	intent.Namespace = inv.Namespace
	for j := range intent.Connections[0].Tunnels {
		k := inv.Links[j]
		intent.Connections[0].Tunnels[j] = Ownership{Namespace: inv.Namespace, InterfaceName: k.Name, InterfaceIndex: k.Index, XFRMID: k.XFRMID}
	}
	intent.Connections[0].PermittedInterfaceIndices = nil
	intent.Connections[0].LocalIngressIndices = nil
	intent.Connections[0].Grants = nil
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	run(manifest.NFTJSON, "-j", "-f", "-")
	observed := run("", "-j", "list", "table", "inet", "tunnex_ipsec")
	after, err := reader.Read(ctx)
	if err != nil || !reflect.DeepEqual(inv, after) {
		t.Fatal("kernel identity changed during readback")
	}
	links := make([]GuardInterface, 0, len(inv.Links))
	for _, link := range inv.Links {
		links = append(links, GuardInterface{Name: link.Name, Index: link.Index})
	}
	if err := VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), observed, links); err != nil {
		t.Fatalf("actual nft readback differs: %v\nexpected=%s\nobserved=%s", err, manifest.ExpectedJSON, observed)
	}

	// Exercise a live timed member using the same renderer and actual JSON grammar.
	intent.Connections[0].PermittedInterfaceIndices = []int{inv.Links[0].Index}
	intent.Connections[0].ReplyIngressIndices = []int{inv.Links[0].Index, inv.Links[1].Index}
	intent.Connections[0].PermitFor = 30 * time.Second
	intent.Connections[0].Grants = []GuardGrant{{Source: netip.MustParsePrefix("10.10.0.10/32"), Destination: netip.MustParsePrefix("10.20.0.10/32"), Protocol: GuardTCP, PortLow: 443, PortHigh: 443, HostOrigin: true}}
	manifest, err = RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	run(manifest.NFTJSON, "-j", "-f", "-")
	observed = run("", "-j", "list", "table", "inet", "tunnex_ipsec")
	after, err = reader.Read(ctx)
	if err != nil || !reflect.DeepEqual(inv, after) {
		t.Fatal("kernel identity changed during timed readback")
	}
	if err := VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), observed, links); err != nil {
		t.Fatalf("actual timed nft readback differs: %v\nexpected=%s\nobserved=%s", err, manifest.ExpectedJSON, observed)
	}
	guardReader, err := NewGuardReader("/usr/sbin/nft")
	if err != nil || guardReader.Check(ctx, manifest) != nil {
		t.Fatal("bounded guard observer refused native table")
	}
	// flush table retains set objects: withdrawal must empty and retain every
	// declared lease set, then permit restoration without an extra-set mismatch.
	activeManifest := manifest
	refusal := intent
	refusal.Connections = append([]GuardConnection(nil), intent.Connections...)
	refusal.Connections[0] = GuardConnection{ID: intent.Connections[0].ID, PrefixOnly: true, Local: intent.Connections[0].Local, Remote: intent.Connections[0].Remote}
	refusal.Revision++
	refused, err := RenderGuard(refusal)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []GuardManifest{refused, activeManifest} {
		run(next.NFTJSON, "-j", "-f", "-")
		actual := run("", "-j", "list", "table", "inet", "tunnex_ipsec")
		if err := VerifyGuardReadbackWithInterfaces([]byte(next.ExpectedJSON), actual, links); err != nil {
			t.Fatalf("active-refusal-active readback differs: %v\nexpected=%s\nobserved=%s", err, next.ExpectedJSON, actual)
		}
		if err := guardReader.Check(ctx, next); err != nil {
			t.Fatal("native lifecycle readback", err)
		}
	}
	run("add rule inet tunnex_ipsec output_guard counter accept\n", "-f", "-")
	if VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), run("", "-j", "list", "table", "inet", "tunnex_ipsec"), links) == nil {
		t.Fatal("foreign appended permit accepted")
	}
	t.Log("actual kernel refusal table readback verified; extra permit refused")
}
