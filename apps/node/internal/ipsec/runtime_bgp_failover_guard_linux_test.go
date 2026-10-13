//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This proves native nft syntax/readback only. CHILD health and the remaining
// lease are explicit component inputs; this is not CP or encrypted packet proof.
func TestNativeBGPHealthyDownGuardReadback(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_BGP_PARTIAL_GUARD_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	for _, profile := range []string{"aws", "gcp-ha"} {
		t.Run(profile, func(t *testing.T) { nativeBGPHealthyDownGuardReadback(t, profile) })
	}
}

func nativeBGPHealthyDownGuardReadback(t *testing.T, profile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(path string, args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("native command refused: %v %s", err, out)
		}
		return out
	}
	run("/sbin/ip", "link", "add", "tnxbpartial", "type", "dummy")
	defer run("/sbin/ip", "link", "delete", "tnxbpartial")
	run("/sbin/ip", "link", "set", "tnxbpartial", "up")
	var rows []struct {
		Index int      `json:"ifindex"`
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(run("/sbin/ip", "-j", "-d", "link", "show", "dev", "tnxbpartial"), &rows); err != nil || len(rows) != 1 {
		t.Fatal("owned component underlay readback refused")
	}
	up := false
	for _, f := range rows[0].Flags {
		up = up || f == "UP"
	}
	underlay := rows[0].Index
	if underlay <= 0 || rows[0].Name != "tnxbpartial" || rows[0].Info.Kind != "dummy" || !up {
		t.Fatal("owned component underlay identity refused")
	}
	e := bgpEntryFixture(t)
	if profile == "gcp-ha" {
		m := gcpMaterialFixture()
		var err error
		e, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
		if err != nil {
			t.Fatal(err)
		}
	}
	e.Allocation.Namespace, _ = os.Readlink("/proc/self/ns/net")
	for i := range e.Engines {
		e.Engines[i].ReqID = e.Engines[i].XFRMID
	}
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	e.Observed, err = a.Apply(ctx, e.Allocation, [2]Ownership{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := a.Remove(ctx, e.Allocation, e.Observed); err != nil {
			t.Error(err)
		}
	}()
	links := []GuardInterface{{Name: "tnxbpartial", Index: underlay}, {Name: e.Observed[0].InterfaceName, Index: e.Observed[0].InterfaceIndex}, {Name: e.Observed[1].InterfaceName, Index: e.Observed[1].InterfaceIndex}}
	var last GuardManifest
	for down := -1; down < 2; down++ {
		c := &RuntimeController{recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string {
			states := [2]string{"up", "up"}
			if down >= 0 {
				states[down] = "down"
			}
			return states
		}}
		active := runtimeActive{Entry: e, Environment: RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{InterfaceIndex: underlay, OuterMTU: 1500}, {InterfaceIndex: underlay, OuterMTU: 1500}}}}
		g, err := c.bgpGuard(ctx, active, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := RenderGuard(GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: e.Engines[0].Binding.GatewayID, Revision: int64(down + 2), Connections: []GuardConnection{g}})
		if err != nil {
			t.Fatal(err)
		}
		if down >= 0 {
			run("/usr/sbin/nft", "delete", "table", "inet", "tunnex_ipsec")
		}
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(manifest.NFTJSON)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native partial-health guard: %v %s", err, out)
		}
		raw := run("/usr/sbin/nft", "-j", "list", "table", "inet", "tunnex_ipsec")
		if VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), raw, links) != nil {
			t.Fatalf("native exact partial-health readback refused expected=%s observed=%s", manifest.ExpectedJSON, raw)
		}
		if down >= 0 {
			peer := e.Allocation.Tunnels[down].BGP.Peer.String()
			for _, line := range strings.Split(manifest.NFT, "\n") {
				if strings.Contains(line, peer) && strings.Contains(line, "counter accept") {
					t.Fatal("down peer gained permission")
				}
			}
		}
		last = manifest
	}
	for _, health := range [][2]string{{"down", "down"}, {"unknown", "up"}, {"up", "unknown"}} {
		c := &RuntimeController{recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return health }}
		active := runtimeActive{Entry: e, Environment: RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{InterfaceIndex: underlay, OuterMTU: 1460}, {InterfaceIndex: underlay, OuterMTU: 1460}}}}
		if _, err := c.bgpGuard(ctx, active, 30*time.Second); err != ErrRuntimeController {
			t.Fatal("unproven health gained grant", health, err)
		}
	}
	raw := run("/usr/sbin/nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	if VerifyGuardReadbackWithInterfaces([]byte(last.ExpectedJSON), raw, links) != nil {
		t.Fatalf("cleanup ownership proof refused expected=%s observed=%s", last.ExpectedJSON, raw)
	}
	run("/usr/sbin/nft", "delete", "table", "inet", "tunnex_ipsec")
	t.Log("native exact healthy/down guard readback and scoped cleanup; synthetic health/lease, no SAs or CP authority")
}
