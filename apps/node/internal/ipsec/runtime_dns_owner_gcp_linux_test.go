//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// Component only: the caller supplies a fresh owned network namespace, private
// material on stdin, actual GCP-shaped peers and LAN/resolver addresses. The
// lease responder is synthetic and cannot establish CP or cloud acceptance.
// No c.prove, source, route, guard or BGP observation is substituted.
func TestDNSOwnerViewGCPNative(t *testing.T) {
	if os.Getenv("TUNNEX_GCP_DNS_OWNER_COMPONENT") != "1" {
		t.Skip("explicit owned disposable component only")
	}
	marker, err := os.ReadFile("/run/gcp-dns-owner-component")
	if err != nil || string(marker) != "owned disposable namespace\n" {
		t.Fatal("missing explicit component namespace marker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	scan := bufio.NewScanner(io.LimitReader(os.Stdin, 1<<20))
	scan.Buffer(make([]byte, 4096), 512<<10)
	if !scan.Scan() {
		t.Fatal("missing bounded private material")
	}
	var m RuntimeMaterial
	if json.Unmarshal(scan.Bytes(), &m) != nil {
		t.Fatal("invalid component material")
	}
	if m.Manifest.ProfileID != GCPClassicStaticProfile && m.Manifest.ProfileID != GCPHABGPProfile {
		t.Fatal("GCP profile required")
	}
	count, err := runtimeMaterialTransportContract(m)
	if err != nil || len(m.Policy.DNSResolverGrants) != 1 {
		t.Fatal("exact GCP DNS component contract required")
	}
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	for _, text := range append([]string{m.Manifest.CustomerOutsideAddress}, func() []string {
		var a []string
		for _, tunnel := range m.Manifest.Tunnels[:count] {
			a = append(a, tunnel.OutsideAddress)
		}
		return a
	}()...) {
		address, err := netip.ParseAddr(text)
		if err != nil || !(address.IsPrivate() || benchmark.Contains(address)) {
			t.Fatal("component underlay must be private or benchmark scope")
		}
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns); err != nil {
		t.Fatal("invalid native component material")
	}
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("native daemon startup", err)
	}
	defer daemon.Close()
	inventory, err := daemon.Client.Inspect(ctx)
	if err != nil || len(inventory.SAs) != 0 || len(inventory.Connections) != 0 || len(inventory.SharedKeys) != 0 {
		t.Fatal("component must start with empty daemon ownership")
	}
	environment, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRuntimeController(RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: t.TempDir(), IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: daemon.Client, DaemonAlive: daemon.Alive, Environment: environment}, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(ctx); err != nil {
		t.Fatal("component startup", err)
	}
	qualification, err := ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", daemon.Client, daemon.Alive)
	if err != nil {
		t.Fatal("actual native platform proof", err)
	}
	if err = c.AttachQualification(qualification); err != nil {
		t.Fatal(err)
	}
	if count == 2 {
		receipt, err := bgpengine.QualifyPreflight(ctx, t.TempDir())
		if err != nil {
			t.Fatal("actual no-peer BGP qualification refused", err)
		}
		if err = c.AttachBGPQualification(receipt); err != nil {
			t.Fatal("actual BGP receipt attach refused", err)
		}
	}
	g := m.Policy.DNSResolverGrants[0]
	config := fqdnrpc.ResolverConfig{ID: g.ContextConfigID.String(), Version: g.ContextConfigVersion, ProfileID: g.ProfileID.String(), MatchedSuffix: "localemulated.gcp.lab.test", Endpoints: []fqdnrpc.ResolverEndpoint{{Address: g.ResolverAddress, Port: 53, Transport: "udp"}}, IPsecPath: &fqdnrpc.IPsecPath{ConnectionID: g.ConnectionID.String(), ConfigurationRevision: g.ConfigurationRevision, SourceAddress: g.SourceAddress}}
	// Actual IKE and HA BGP negotiation can require several normal reconciles.
	applied := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		if _, err = c.Apply(ctx, m); err == nil {
			if _, proofErr := c.proveResolverDNS(ctx, config, config.Endpoints[0]); proofErr == nil {
				status, statusErr := c.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
				allUp := statusErr == nil
				for _, tunnel := range status.Tunnels[:count] {
					allUp = allUp && tunnel.Status == "up"
				}
				if count == 2 {
					allUp = allUp && status.BGP != nil
					if status.BGP != nil {
						for _, peer := range status.BGP.Peers {
							allUp = allUp && peer.State == "established"
						}
					}
				}
				if allUp {
					applied = true
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("native apply deadline")
		case <-time.After(time.Second):
		}
	}
	if !applied {
		t.Fatal("actual native GCP apply refused", err)
	}
	entries, err := c.journal.Entries()
	if err != nil || len(entries) != 1 || entries[0].Allocation.activeTunnelCount() != count {
		t.Fatal("actual cardinality missing")
	}
	inventory, err = daemon.Client.Inspect(ctx)
	if err != nil || len(inventory.SAs) != count {
		t.Fatal("actual native SA cardinality missing", err)
	}
	status, err := c.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
	if err != nil {
		t.Fatal("native public status refused", err)
	}
	for _, tunnel := range status.Tunnels[:count] {
		if tunnel.Status != "up" {
			t.Fatal("native component tunnel not Up")
		}
	}
	e := entries[0]
	if count == 1 && e.Observed[1] != (Ownership{}) {
		t.Fatal("Classic invented inactive ownership")
	}
	if count == 2 && (e.ContractVersion != 3 || !validBGPRoutes(e) || e.BGPRoutes == nil || len(e.BGPRoutes.Owned) == 0) {
		t.Fatal("actual HA owned BGP route missing")
	}
	proofCtx, proofCancel := context.WithTimeout(ctx, 5*time.Second)
	// Real native proof must not wait on the serial controller mutex.
	c.mu.Lock()
	proof, proofErr := c.proveResolverDNS(proofCtx, config, config.Endpoints[0])
	c.mu.Unlock()
	proofCancel()
	if proofErr != nil || proof.Slot < 1 || int(proof.Slot) > count {
		t.Fatal("actual SA/route/source/fullguard DNS proof refused", proofErr)
	}
	fmt.Println("GCP_DNS_OWNER_NATIVE_PROOF")
	// The external receiver may now be queried; this is an actual bound socket,
	// with fresh independent production checks before and after its response.
	if !scan.Scan() || scan.Text() != "exchange" {
		t.Fatal("missing component exchange control")
	}
	queryMessage := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.localemulated.gcp.lab.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	query, err := queryMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}

	for _, transport := range []string{"udp", "tcp"} {
		endpoint := config.Endpoints[0]
		endpoint.Transport = transport
		config.Endpoints = []fqdnrpc.ResolverEndpoint{endpoint}
		response, err := c.exchangeResolverDNS(ctx, config, endpoint, query)
		var message dnsmessage.Message
		if err != nil || message.Unpack(response) != nil || message.ID != 0x1234 || !message.Response || message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 1 {
			t.Fatal("actual bound component DNS A response refused", transport, err)
		}
		answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || netip.AddrFrom4(answer.A).String() != g.ResolverAddress {
			t.Fatal("owned receiver exact A answer missing")
		}
	}
	fmt.Println("GCP_DNS_OWNER_NATIVE_EXCHANGE")
	if !scan.Scan() || scan.Text() != "cleanup" {
		t.Fatal("missing component cleanup control")
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: m.DesiredRevision + 1, Kind: "cleanup", CoversDeliveryRevision: m.DesiredRevision, Manifest: m.Manifest}, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	raw, _ := json.Marshal(cleanup.Lineage)
	digest := sha256.Sum256(raw)
	cleanup.OwnershipDigest = hex.EncodeToString(digest[:])
	if _, err = c.Cleanup(ctx, cleanup); err != nil {
		t.Fatal("native exact cleanup refused", err)
	}
	if _, err = c.proveResolverDNS(ctx, config, config.Endpoints[0]); err == nil {
		t.Fatal("cleaned native epoch retained DNS authority")
	}
	fmt.Println("GCP_DNS_OWNER_NATIVE_CLEANUP_DENIED")
}
