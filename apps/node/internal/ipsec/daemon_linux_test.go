//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

type engineLabRequest struct {
	Role         string
	Phase        string
	PSKs         [2]string
	Forwarded    bool
	LeaseSeconds int
}

func engineLabTunnels(role string) [2]EngineTunnel {
	gateway := role == "gateway"
	local, remote := "10.10.0.0/24", "10.20.0.0/24"
	if !gateway {
		local, remote = remote, local
	}
	var out [2]EngineTunnel
	for i := range out {
		la, ra := "198.19.240.10", "198.19.240."+strconv.Itoa(20+i)
		xid := uint32(701 + i)
		if !gateway {
			la, ra = ra, la
			xid += 100
		}
		out[i] = EngineTunnel{Binding: Binding{OrgID: uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001"), GatewayID: uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000001"), ConnectionID: uuid.MustParse("cccccccc-0000-0000-0000-000000000001"), DesiredRevision: 1, ConfigurationRevision: 1, PolicyRevision: 1}, TunnelID: uuid.MustParse("dddddddd-0000-0000-0000-00000000000" + strconv.Itoa(i+1)), SecretRevision: 1, XFRMID: xid, LocalAddress: netip.MustParseAddr(la), RemoteAddress: netip.MustParseAddr(ra), LocalIdentity: netip.MustParseAddr(la), RemoteIdentity: netip.MustParseAddr(ra), LocalPrefixes: []netip.Prefix{netip.MustParsePrefix(local)}, RemotePrefixes: []netip.Prefix{netip.MustParsePrefix(remote)}}
	}
	return out
}
func engineLabGuard(t *testing.T, configs [2]EngineTunnel, permit, forwarded bool, leaseSeconds int) {
	t.Helper()
	path, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal("missing lab ip")
	}
	reader, err := NewKernelReader(path)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	underlay, err := net.InterfaceByName("eth0")
	if err != nil || underlay.Index <= 0 {
		t.Fatal("lab underlay identity unavailable")
	}
	var lan *net.Interface
	if forwarded {
		lan, err = net.InterfaceByName("eth1")
		if err != nil || lan.Index <= 0 {
			t.Fatal("lab LAN identity unavailable")
		}
	}
	intent := GuardIntent{Namespace: inventory.Namespace, OwnerID: configs[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: configs[0].Binding.ConnectionID, Local: configs[0].LocalPrefixes, Remote: configs[0].RemotePrefixes}}}
	if forwarded {
		intent.Connections[0].LocalIngressIndices = []int{lan.Index}
	}
	for i, cfg := range configs {
		found := false
		for _, link := range inventory.Links {
			if link.XFRMID == cfg.XFRMID {
				intent.Connections[0].Tunnels[i] = Ownership{Namespace: inventory.Namespace, InterfaceName: link.Name, InterfaceIndex: link.Index, XFRMID: link.XFRMID}
				if permit {
					intent.Connections[0].PermittedInterfaceIndices = append(intent.Connections[0].PermittedInterfaceIndices, link.Index)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing owned lab interface")
		}
	}
	var kernelSAs XFRMInventory
	var xfrmReader *XFRMReader
	if permit {
		xfrmReader, err = NewXFRMReader(path)
		if err != nil {
			t.Fatal(err)
		}
		kernelSAs, err = xfrmReader.Read(context.Background())
		if err != nil || kernelSAs.Namespace != inventory.Namespace || len(kernelSAs.States) != 4 || len(kernelSAs.Policies) != 6 {
			t.Fatal("unexpected kernel XFRM inventory")
		}
		client, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
		if err != nil {
			t.Fatal(err)
		}
		observed, err := client.Inspect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for i, cfg := range configs {
			found := false
			for _, sa := range observed.SAs {
				if sa.Name != engineName(cfg) {
					continue
				}
				if found || !sa.Established || sa.LocalAddress != cfg.LocalAddress || sa.RemoteAddress != cfg.RemoteAddress || len(sa.Children) != 1 {
					t.Fatal("ambiguous encrypted egress")
				}
				child := sa.Children[0]
				if !child.Installed || child.IfIDIn != cfg.XFRMID || child.IfIDOut != cfg.XFRMID || !sameEnginePrefixes(child.LocalPrefixes, cfg.LocalPrefixes) || !sameEnginePrefixes(child.RemotePrefixes, cfg.RemotePrefixes) {
					t.Fatal("encrypted egress ownership mismatch")
				}
				engineLabKernelSA(t, cfg, child, kernelSAs)
				intent.Connections[0].EncryptedEgress = append(intent.Connections[0].EncryptedEgress, GuardEncryptedEgress{TunnelInterfaceIndex: intent.Connections[0].Tunnels[i].InterfaceIndex, ReqID: child.ReqID, Peer: sa.RemoteAddress, UnderlayInterfaceIndex: underlay.Index})
				found = true
			}
			if !found {
				t.Fatal("missing encrypted egress SA")
			}
		}
		if leaseSeconds == 0 {
			leaseSeconds = 30
		}
		intent.Connections[0].PermitFor = time.Duration(leaseSeconds) * time.Second
		intent.Connections[0].Grants = []GuardGrant{{Source: configs[0].LocalPrefixes[0], Destination: configs[0].RemotePrefixes[0], Protocol: GuardAny, HostOrigin: true}}
		if forwarded {
			intent.Connections[0].Grants = []GuardGrant{
				{Source: configs[0].LocalPrefixes[0], Destination: configs[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 18080, PortHigh: 18080},
				{Source: configs[0].LocalPrefixes[0], Destination: configs[0].RemotePrefixes[0], Protocol: GuardUDP, PortLow: 18081, PortHigh: 18081},
			}
		}
	}
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("missing lab nft")
	}
	command := exec.Command(nft, "-j", "-f", "-")
	command.Stdin = bytes.NewBufferString(manifest.NFTJSON)
	if command.Run() != nil {
		t.Fatal("lab refusal/permit transaction failed")
	}
	actual, err := exec.Command(nft, "-j", "list", "table", "inet", "tunnex_ipsec").Output()
	if err != nil {
		t.Fatal("lab guard read failed")
	}
	after, err := reader.Read(context.Background())
	if err != nil || after.Namespace != inventory.Namespace || !reflect.DeepEqual(after.Links, inventory.Links) {
		t.Fatal("lab namespace/interface identity changed")
	}
	if permit {
		afterSAs, e := xfrmReader.Read(context.Background())
		if e != nil || !reflect.DeepEqual(kernelSAs, afterSAs) {
			t.Fatal("kernel XFRM inventory changed during permit")
		}
	}
	underlayAfter, err := net.InterfaceByName("eth0")
	if err != nil || !reflect.DeepEqual(underlay, underlayAfter) {
		t.Fatal("lab underlay changed")
	}
	interfaces := []GuardInterface{{Name: underlay.Name, Index: underlay.Index}}
	if forwarded {
		lanAfter, e := net.InterfaceByName("eth1")
		if e != nil || !reflect.DeepEqual(lan, lanAfter) {
			t.Fatal("lab LAN changed")
		}
		interfaces = append(interfaces, GuardInterface{Name: lan.Name, Index: lan.Index})
	}
	for _, link := range inventory.Links {
		interfaces = append(interfaces, GuardInterface{Name: link.Name, Index: link.Index})
	}
	if VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), actual, interfaces) != nil {
		t.Log("nonsecret expected guard:", manifest.ExpectedJSON, "observed:", string(actual))
		t.Fatal("lab guard exact readback failed")
	}
	t.Log("actual renderer/readback verified; permit=", permit)
}
func TestDaemonEncryptedLabPhase(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_ENCRYPTED_LAB") != "1" {
		t.Skip("isolated synthetic traffic qualification only")
	}
	var request engineLabRequest
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 4097))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || (request.Role != "gateway" && request.Role != "peer") {
		t.Fatal("invalid bounded lab input")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		t.Fatal("trailing lab input")
	}
	configs := engineLabTunnels(request.Role)
	client, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal(err)
	}
	switch request.Phase {
	case "stage":
		engineLabGuard(t, configs, false, request.Forwarded, request.LeaseSeconds)
		for i, cfg := range configs {
			if client.stageTunnel(context.Background(), cfg, []byte(request.PSKs[i])) != nil {
				t.Fatal("stage failed for tunnel", i+1)
			}
		}
	case "initiate":
		engineLabGuard(t, configs, false, request.Forwarded, request.LeaseSeconds)
		for i, cfg := range configs {
			if client.initiateTunnel(context.Background(), cfg) != nil {
				t.Fatal("initiate failed for tunnel", i+1)
			}
		}
	case "allow", "observe":
		inventory, err := client.Inspect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(inventory.SAs) != 2 {
			t.Fatal("expected exactly two real IKE SAs")
		}
		var totalIn, totalOut uint64
		for _, cfg := range configs {
			found := false
			for _, sa := range inventory.SAs {
				if sa.Name == engineName(cfg) && sa.Established && len(sa.Children) == 1 {
					child := sa.Children[0]
					if child.Installed && child.IfIDIn == cfg.XFRMID && child.IfIDOut == cfg.XFRMID && len(child.LocalPrefixes) == 1 && child.LocalPrefixes[0] == cfg.LocalPrefixes[0] && len(child.RemotePrefixes) == 1 && child.RemotePrefixes[0] == cfg.RemotePrefixes[0] {
						found = true
						totalIn += child.BytesIn
						totalOut += child.BytesOut
					}
				}
			}
			if !found {
				t.Fatal("real SA ownership/selector mismatch")
			}
		}
		if request.Phase == "allow" {
			if request.Role == "peer" {
				engineLabPeerACL(t, request.Forwarded)
			} else {
				engineLabGuard(t, configs, true, request.Forwarded, request.LeaseSeconds)
			}
		} else if totalIn == 0 || totalOut == 0 {
			t.Fatal("no encrypted payload byte evidence")
		}
		t.Log("two real installed CHILD SAs; bytes in/out", totalIn, totalOut)
	case "inject-sa-loss":
		// Explicit fault injection inside the disposable lab only, never a controller action.
		inventory, e := client.Inspect(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		cfg := configs[1]
		found := false
		path, e := exec.LookPath("ip")
		if e != nil {
			t.Fatal(e)
		}
		reader, e := NewXFRMReader(path)
		if e != nil {
			t.Fatal(e)
		}
		kernel, e := reader.Read(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		for _, sa := range inventory.SAs {
			if sa.Name != engineName(cfg) {
				continue
			}
			if found || len(sa.Children) != 1 {
				t.Fatal("ambiguous fault target")
			}
			child := sa.Children[0]
			engineLabKernelSA(t, cfg, child, kernel)
			faultCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(faultCtx, path, "xfrm", "state", "delete", "src", cfg.LocalAddress.String(), "dst", cfg.RemoteAddress.String(), "proto", "esp", "spi", fmt.Sprintf("0x%x", child.SPIOut))
			faultErr := cmd.Run()
			cancel()
			if faultErr != nil {
				t.Fatal("owned SA fault injection failed")
			}
			found = true
		}
		if !found {
			t.Fatal("owned fault target missing")
		}
	case "initiate-refused":
		for _, cfg := range configs {
			if client.initiateTunnel(context.Background(), cfg) == nil {
				t.Fatal("wrong PSK unexpectedly established")
			}
		}
		fallthrough
	case "no-kernel-sa":
		path, e := exec.LookPath("ip")
		if e != nil {
			t.Fatal(e)
		}
		reader, e := NewXFRMReader(path)
		if e != nil {
			t.Fatal(e)
		}
		inventory, e := reader.Read(context.Background())
		if e != nil || len(inventory.States) != 0 || len(inventory.Policies) != 0 {
			t.Fatal("unexpected kernel SA after authentication refusal")
		}
	case "deny":
		engineLabGuard(t, configs, false, request.Forwarded, request.LeaseSeconds)
	case "cleanup-first":
		engineLabGuard(t, configs, false, request.Forwarded, request.LeaseSeconds)
		if client.removeTunnel(context.Background(), configs[0]) != nil {
			t.Fatal("targeted cleanup failed")
		}
		inventory, err := client.Inspect(context.Background())
		if err != nil || len(inventory.SAs) != 1 || inventory.SAs[0].Name != engineName(configs[1]) || !containsString(inventory.Connections, engineName(configs[1])) || !containsString(inventory.SharedKeys, engineName(configs[1])) {
			t.Fatal("other tunnel was not preserved")
		}
	case "cleanup-all":
		engineLabGuard(t, configs, false, request.Forwarded, request.LeaseSeconds)
		for _, cfg := range configs {
			if client.removeTunnel(context.Background(), cfg) != nil {
				t.Fatal("cleanup failed")
			}
		}
		inventory, err := client.Inspect(context.Background())
		if err != nil || len(inventory.SAs) != 0 || len(inventory.Connections) != 0 || len(inventory.SharedKeys) != 0 {
			t.Fatal("negative daemon inventory incomplete")
		}
	default:
		t.Fatal("unknown lab phase")
	}
}

// The peer emulates an external VPN endpoint, not Tunnex host-inbound policy.
// Its test-only ICMP ACL permits requests arriving on independently observed
// XFRM interfaces. The gateway always exercises the actual production renderer.
func engineLabPeerACL(t *testing.T, forwarded bool) {
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewKernelReader(ip)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	indices := map[uint32]int{}
	for _, link := range inventory.Links {
		if link.Up {
			indices[link.XFRMID] = link.Index
		}
	}
	a, b := indices[801], indices[802]
	if a <= 0 || b <= 0 || a == b {
		t.Fatal("peer XFRM identity unavailable")
	}
	rules := fmt.Sprintf(`flush chain inet tunnex_ipsec input_guard
flush chain inet tunnex_ipsec output_guard
flush chain inet tunnex_ipsec forward_guard
flush chain inet tunnex_ipsec postrouting_guard
add rule inet tunnex_ipsec input_guard meta iif { %d, %d } ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/24 ip protocol icmp icmp type echo-request accept
add rule inet tunnex_ipsec input_guard ip saddr 10.10.0.0/24 drop
add rule inet tunnex_ipsec output_guard meta oif { %d, %d } ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 ip protocol icmp icmp type echo-reply accept
add rule inet tunnex_ipsec output_guard ip daddr 10.10.0.0/24 drop
`, a, b, a, b)
	if forwarded {
		lan, e := net.InterfaceByName("eth1")
		if e != nil || lan.Index <= 0 {
			t.Fatal("peer LAN unavailable")
		}
		for _, protocol := range []string{"tcp", "udp"} {
			port := 18080
			if protocol == "udp" {
				port = 18081
			}
			rules += fmt.Sprintf("add rule inet tunnex_ipsec forward_guard meta iif { %d, %d } meta oif %d ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/24 %s dport %d accept\n", a, b, lan.Index, protocol, port)
			rules += fmt.Sprintf("add rule inet tunnex_ipsec forward_guard meta iif %d meta oif { %d, %d } ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 %s sport %d ct state established accept\n", lan.Index, a, b, protocol, port)
		}
		rules += "add rule inet tunnex_ipsec forward_guard ip saddr 10.10.0.0/24 drop\nadd rule inet tunnex_ipsec forward_guard ip daddr 10.10.0.0/24 drop\n"
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rules)
	if cmd.Run() != nil {
		t.Fatal("peer test ACL failed")
	}
	after, err := reader.Read(context.Background())
	if err != nil || after.Namespace != inventory.Namespace || !reflect.DeepEqual(after.Links, inventory.Links) {
		t.Fatal("peer interface scope changed")
	}
	t.Log("external peer test-only ICMP ACL installed; no Tunnex inbound-policy claim")
}

func engineLabKernelSA(t *testing.T, cfg EngineTunnel, child DaemonChild, inventory XFRMInventory) {
	t.Helper()
	states, policies := 0, 0
	for _, state := range inventory.States {
		if state.IfID != cfg.XFRMID {
			continue
		}
		states++
		if state.ReqID != child.ReqID {
			t.Fatal("kernel reqid mismatch")
		}
		outgoing := state.Source == cfg.LocalAddress && state.Destination == cfg.RemoteAddress && state.SPI == child.SPIOut
		incoming := state.Source == cfg.RemoteAddress && state.Destination == cfg.LocalAddress && state.SPI == child.SPIIn
		if !outgoing && !incoming {
			t.Fatal("kernel SA endpoint/SPI mismatch")
		}
	}
	seen := map[string]bool{}
	for _, policy := range inventory.Policies {
		if policy.IfID != cfg.XFRMID {
			continue
		}
		policies++
		if policy.ReqID != child.ReqID || seen[policy.Direction] {
			t.Fatal("kernel policy identity mismatch")
		}
		seen[policy.Direction] = true
		local, remote := cfg.LocalPrefixes[0], cfg.RemotePrefixes[0]
		src, dst := cfg.LocalAddress, cfg.RemoteAddress
		spi := child.SPIOut
		if policy.Direction != "out" {
			local, remote = remote, local
			src, dst = dst, src
			spi = child.SPIIn
		}
		if policy.Source != local || policy.Destination != remote || policy.TemplateSource != src || policy.TemplateDestination != dst || (policy.TemplateSPI != 0 && policy.TemplateSPI != spi) {
			t.Fatal("kernel policy ownership mismatch")
		}
	}
	if states != 2 || policies != 3 || !seen["out"] || !seen["in"] || !seen["fwd"] {
		t.Fatal("incomplete kernel SA/policy proof")
	}
}
