//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Run ONLY in the separately verified disconnected disposable NAT fixture. This
// test needs NET_ADMIN and a working ICMP ping implementation (normally NET_RAW).
func TestGuardLinuxDNATEscape(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_GUARD_LAB") != "1" || os.Getenv("TUNNEX_IPSEC_NAT_LAB") != "1" {
		t.Skip("isolated Linux DNAT lab only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := func(input, path string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		if input != "" {
			cmd.Stdin = strings.NewReader(input)
		}
		return cmd.CombinedOutput()
	}
	run := func(input, path string, args ...string) []byte {
		t.Helper()
		out, err := command(input, path, args...)
		if err != nil {
			t.Fatalf("fixture command %s %v: %v: %s", path, args, err, out)
		}
		return out
	}
	empty := run("", "/usr/sbin/nft", "-j", "list", "tables")
	if bytes.Contains(empty, []byte(`"table"`)) {
		t.Fatal("fixture must begin with no firewall tables")
	}
	reader, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	before, err := reader.Read(ctx)
	if err != nil || len(before.Links) != 2 {
		t.Fatal("fixture must have two independently read XFRM links", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 3 {
		t.Fatal("fixture must contain only loopback and two XFRM links", err)
	}
	allowed := map[int]bool{}
	for _, link := range before.Links {
		allowed[link.Index] = true
	}
	for _, iface := range interfaces {
		if iface.Name != "lo" && !allowed[iface.Index] {
			t.Fatal("unexpected fixture interface")
		}
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container marker required")
	}
	// Register cleanup only after empty-namespace/identity checks. No flush ruleset,
	// shared routes, host mounts or unrelated resources are ever removed.
	cleanup := func(path string, args ...string) {
		t.Cleanup(func() {
			cleanCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = exec.CommandContext(cleanCtx, path, args...).Run()
		})
	}
	run("", "/sbin/ip", "link", "set", "lo", "up")
	for _, address := range []string{"10.10.0.1/32", "10.30.0.1/32"} {
		run("", "/sbin/ip", "address", "add", address, "dev", "lo")
		cleanup("/sbin/ip", "address", "del", address, "dev", "lo")
	}
	run("", "/sbin/ip", "-4", "route", "add", "10.20.0.0/24", "dev", "lo", "src", "10.10.0.1")
	cleanup("/sbin/ip", "-4", "route", "del", "10.20.0.0/24", "dev", "lo")
	nat := `add table ip tunnex_ipsec_nat_lab
add chain ip tunnex_ipsec_nat_lab output_nat { type nat hook output priority -100; policy accept; }
add rule ip tunnex_ipsec_nat_lab output_nat ip daddr 10.20.0.1 counter dnat to 10.30.0.1
`
	run(nat, "/usr/sbin/nft", "-f", "-")
	cleanup("/usr/sbin/nft", "delete", "table", "ip", "tunnex_ipsec_nat_lab")
	ping := []string{"-n", "-c", "1", "-W", "1", "-I", "10.10.0.1", "10.20.0.1"}
	run("", "/bin/ping", ping...)
	natRead := run("", "/usr/sbin/nft", "-j", "list", "table", "ip", "tunnex_ipsec_nat_lab")
	if !natLabCounter(natRead, "output_nat", false) {
		t.Fatal("positive ping did not traverse DNAT rule")
	}
	intent := GuardIntent{Namespace: before.Namespace, OwnerID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Revision: 1, Connections: []GuardConnection{{ID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), Local: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}}}
	for i, link := range before.Links {
		intent.Connections[0].Tunnels[i] = Ownership{Namespace: before.Namespace, InterfaceName: link.Name, InterfaceIndex: link.Index, XFRMID: link.XFRMID}
	}
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	run(manifest.NFTJSON, "/usr/sbin/nft", "-j", "-f", "-")
	cleanup("/usr/sbin/nft", "delete", "table", "inet", "tunnex_ipsec")
	observed := run("", "/usr/sbin/nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	links := []GuardInterface{}
	for _, link := range before.Links {
		links = append(links, GuardInterface{Name: link.Name, Index: link.Index})
	}
	if err := VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), observed, links); err != nil {
		t.Fatal("production guard readback mismatch", err)
	}
	if output, err := command("", "/bin/ping", ping...); err == nil {
		t.Fatalf("DNAT escaped protected original tuple: %s", output)
	}
	observed = run("", "/usr/sbin/nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	if !natLabCounter(observed, "output_guard", true) {
		t.Fatal("failure did not hit exact original-destination DNAT refusal")
	}
	after, err := reader.Read(ctx)
	if err != nil || before.Namespace != after.Namespace || !reflect.DeepEqual(before.Links, after.Links) {
		t.Fatal("XFRM/namespace identity changed", err)
	}
	t.Log("DNAT baseline reached rewritten loopback; production original-tuple guard denied same path and exact refusal counter advanced")
}

func natLabCounter(raw []byte, chain string, originalRefusal bool) bool {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, item := range doc.NFTables {
		var rule struct {
			Chain string                       `json:"chain"`
			Expr  []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(item["rule"], &rule) != nil || rule.Chain != chain {
			continue
		}
		original, status, drop, packets := false, false, false, uint64(0)
		for _, expr := range rule.Expr {
			if _, ok := expr["drop"]; ok {
				drop = true
			}
			if counter, ok := expr["counter"]; ok {
				var c struct {
					Packets uint64 `json:"packets"`
				}
				if json.Unmarshal(counter, &c) == nil {
					packets = c.Packets
				}
			}
			if match, ok := expr["match"]; ok {
				var m struct {
					Op   string `json:"op"`
					Left struct {
						CT struct {
							Key string `json:"key"`
							Dir string `json:"dir"`
						} `json:"ct"`
					} `json:"left"`
					Right json.RawMessage `json:"right"`
				}
				if json.Unmarshal(match, &m) != nil {
					continue
				}
				if m.Op == "==" && m.Left.CT.Key == "ip daddr" && m.Left.CT.Dir == "original" {
					var p struct {
						Prefix struct {
							Addr string `json:"addr"`
							Len  int    `json:"len"`
						} `json:"prefix"`
					}
					if json.Unmarshal(m.Right, &p) == nil && p.Prefix.Addr == "10.20.0.0" && p.Prefix.Len == 24 {
						original = true
					}
				}
				if m.Op == "in" && m.Left.CT.Key == "status" && string(m.Right) == `"dnat"` {
					status = true
				}
			}
		}
		if packets > 0 && (!originalRefusal || (original && status && drop)) {
			return true
		}
	}
	return false
}
