//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type gcpDaemonRequest struct {
	ProfileID string
	Role      string
	Phase     string
	PSKs      [2]string
}

func gcpDaemonTunnels(r gcpDaemonRequest) ([2]EngineTunnel, int, bool) {
	var empty [2]EngineTunnel
	if r.Role != "gateway" && r.Role != "peer" {
		return empty, 0, false
	}
	count := 2
	switch r.ProfileID {
	case GCPHABGPProfile:
	case GCPClassicStaticProfile:
		count = 1
	default:
		return empty, 0, false
	}
	if count == 1 && r.PSKs[1] != "" {
		return empty, 0, false
	}
	out := engineLabTunnels(r.Role)
	for i := 0; i < count; i++ {
		local, remote := "198.18.222.10", "198.18.222."+strconv.Itoa(20+i)
		if r.Role == "peer" {
			local, remote = remote, local
		}
		out[i].LocalAddress, out[i].RemoteAddress = netip.MustParseAddr(local), netip.MustParseAddr(remote)
		out[i].LocalIdentity, out[i].RemoteIdentity = out[i].LocalAddress, out[i].RemoteAddress
		out[i].ProfileID = r.ProfileID
		out[i].BGP = count == 2
		out[i].ReqID = out[i].XFRMID
		if !validEngineTunnel(out[i]) {
			return empty, 0, false
		}
	}
	if count == 1 {
		out[1] = EngineTunnel{}
	}
	return out, count, true
}

// Dedicated disposable daemon component only. The caller owns actual underlay
// peers and XFRM links. No grant, lease, journal, enrollment or delivery is forged.
// Passing this fixture does not establish controller or GCP cloud acceptance.
func TestGCPDaemonComponentPhase(t *testing.T) {
	if os.Getenv("TUNNEX_GCP_DAEMON_COMPONENT_LAB") != "1" {
		t.Skip("owned disposable daemon component only")
	}
	var r gcpDaemonRequest
	d := json.NewDecoder(io.LimitReader(os.Stdin, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		t.Fatal("bounded component input refused")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("trailing component input")
	}
	configs, count, ok := gcpDaemonTunnels(r)
	if !ok {
		t.Fatal("component profile/cardinality refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	client, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal(err)
	}
	inspect := func() DaemonInventory {
		t.Helper()
		inv, err := client.Inspect(ctx)
		if err != nil {
			t.Fatal("actual daemon observation", err)
		}
		return inv
	}
	verify := func(payload bool) DaemonInventory {
		t.Helper()
		inv := inspect()
		if len(inv.SAs) != count {
			t.Fatal("actual IKE cardinality", len(inv.SAs), count)
		}
		xr, err := NewXFRMReader("/sbin/ip")
		if err != nil {
			t.Fatal(err)
		}
		kernel, err := xr.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(kernel.States) != count*2 || len(kernel.Policies) != count*3 {
			t.Fatal("actual kernel cardinality", len(kernel.States), len(kernel.Policies))
		}
		for _, cfg := range configs[:count] {
			found := false
			for _, sa := range inv.SAs {
				if sa.Name != engineName(cfg) {
					continue
				}
				if found || !sa.Established || sa.LocalAddress != cfg.LocalAddress || sa.RemoteAddress != cfg.RemoteAddress || len(sa.Children) != 1 {
					t.Fatal("ambiguous actual IKE binding")
				}
				child := sa.Children[0]
				if !child.Installed || child.IfIDIn != cfg.XFRMID || child.IfIDOut != cfg.XFRMID || child.ReqID != cfg.ReqID || !sameEnginePrefixes(child.LocalPrefixes, engineTransportPrefixes(cfg, true)) || !sameEnginePrefixes(child.RemotePrefixes, engineTransportPrefixes(cfg, false)) {
					t.Fatal("actual route-based CHILD binding")
				}
				engineLabKernelSA(t, cfg, child, kernel)
				if payload && (child.BytesIn == 0 || child.BytesOut == 0) {
					t.Fatal("bidirectional encrypted payload evidence absent")
				}
				found = true
			}
			if !found {
				t.Fatal("owned actual SA absent")
			}
		}
		return inv
	}
	switch r.Phase {
	case "stage", "stage-bad-proposal":
		if r.Phase == "stage-bad-proposal" {
			request := client.request
			client.request = func(ctx context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
				// Explicit disposable fault injection; production stage config is reused.
				if command == "load-conn" {
					for name, conn := range m {
						conn.section["proposals"] = viciList("aes128-sha256-modp2048")
						m[name] = conn
					}
				}
				return request(ctx, command, event, m)
			}
		}
		namespace, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		guard, err := RenderGuard(GuardIntent{Namespace: namespace, OwnerID: configs[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: configs[0].Binding.ConnectionID, PrefixOnly: true, Local: configs[0].LocalPrefixes, Remote: configs[0].RemotePrefixes}}})
		if err != nil {
			t.Fatal("component permanent refusal", err)
		}
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(guard.NFTJSON)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("component permanent refusal: %v %s", err, out)
		}
		reader, err := NewGuardReader("/usr/sbin/nft")
		if err != nil || reader.Check(ctx, guard) != nil {
			t.Fatal("component refusal exact readback")
		}
		if len(inspect().SAs) != 0 {
			t.Fatal("preexisting SA refused")
		}
		for i, cfg := range configs[:count] {
			if client.stageTunnel(ctx, cfg, []byte(r.PSKs[i])) != nil {
				t.Fatal("provider stage refused", i+1)
			}
		}
	case "initiate":
		for i, cfg := range configs[:count] {
			if client.initiateTunnel(ctx, cfg) != nil {
				t.Fatal("provider negotiation refused", i+1)
			}
		}
		verify(false)
	case "observe":
		verify(false)
	case "payload":
		verify(true)
	case "rekey":
		before := verify(false)
		for _, cfg := range configs[:count] {
			if client.success(ctx, "rekey", viciMessage{"child": viciText(engineName(cfg)), "force": viciText("yes")}) != nil {
				t.Fatal("actual CHILD rekey refused")
			}
		}
		// The rekey command is asynchronous; wait for the old overlap to retire.
		deadline := time.Now().Add(12 * time.Second)
		changed := false
		for time.Now().Before(deadline) {
			inv := inspect()
			changed = len(inv.SAs) == count
			for _, old := range before.SAs {
				found := false
				for _, sa := range inv.SAs {
					if sa.Name == old.Name && len(sa.Children) == 1 && sa.Children[0].SPIIn != old.Children[0].SPIIn && sa.Children[0].SPIOut != old.Children[0].SPIOut {
						found = true
					}
				}
				changed = changed && found
			}
			if changed {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !changed {
			t.Fatal("actual rekey SPI replacement absent")
		}
		verify(false)
	case "refused":
		for _, cfg := range configs[:count] {
			if client.initiateTunnel(ctx, cfg) == nil {
				t.Fatal("wrong key unexpectedly negotiated")
			}
		}
		inv := inspect()
		xr, err := NewXFRMReader("/sbin/ip")
		if err != nil {
			t.Fatal(err)
		}
		kernel, err := xr.Read(ctx)
		if err != nil || len(inv.SAs) != 0 || len(kernel.States) != 0 || len(kernel.Policies) != 0 {
			t.Fatal("authentication refusal left installed SA")
		}
	case "cleanup":
		for _, cfg := range configs[:count] {
			if client.removeTunnel(ctx, cfg) != nil {
				t.Fatal("exact component cleanup refused")
			}
		}
		inv := inspect()
		xr, err := NewXFRMReader("/sbin/ip")
		if err != nil {
			t.Fatal(err)
		}
		kernel, err := xr.Read(ctx)
		if err != nil || len(inv.SAs) != 0 || len(inv.Connections) != 0 || len(inv.SharedKeys) != 0 || len(kernel.States) != 0 || len(kernel.Policies) != 0 {
			t.Fatal("component cleanup incomplete")
		}
	default:
		t.Fatal("unknown component phase")
	}
	t.Log("actual managed strongSwan component", r.ProfileID, r.Role, r.Phase, "tunnels", count, "no CP acceptance claim")
}

func TestGCPDaemonComponentContract(t *testing.T) {
	for _, profile := range []string{GCPHABGPProfile, GCPClassicStaticProfile} {
		r := gcpDaemonRequest{ProfileID: profile, Role: "gateway"}
		tunnels, count, ok := gcpDaemonTunnels(r)
		if !ok || count != engineTunnelCount(tunnels) {
			t.Fatal("component contract refused")
		}
		if count == 1 && !reflect.DeepEqual(tunnels[1], EngineTunnel{}) {
			t.Fatal("fake second component tunnel")
		}
	}
	for _, r := range []gcpDaemonRequest{{ProfileID: "unknown", Role: "gateway"}, {ProfileID: GCPHABGPProfile, Role: "unknown"}, {ProfileID: GCPClassicStaticProfile, Role: "gateway", PSKs: [2]string{"", "inactive"}}} {
		if _, _, ok := gcpDaemonTunnels(r); ok {
			t.Fatal("invalid component contract accepted")
		}
	}
}

// Keep the production daemon supervisor alive for independent phase invocations.
func TestGCPDaemonComponentServe(t *testing.T) {
	if os.Getenv("TUNNEX_GCP_DAEMON_COMPONENT_LAB") != "1" {
		t.Skip("owned disposable daemon only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("managed component daemon", err)
	}
	defer daemon.Close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	t.Log("GCP_COMPONENT_DAEMON_READY")
	select {
	case <-stop:
	case <-ctx.Done():
		t.Fatal("component deadline reached")
	}
}
