//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type nativeRuntimeLease struct{}

func (nativeRuntimeLease) RenewIPsecLease(_ context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
	return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}, nil
}

// The isolated harness supplies synthetic credentials on stdin. It drives real
// peers and application payload externally while this test holds the controller.
// The CP lease responder is synthetic; HTTP+DB authorization has separate tests.
func TestRuntimeControllerNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_CONTROLLER_LAB") != "1" {
		t.Skip("isolated native controller fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scan := bufio.NewScanner(os.Stdin)
	if !scan.Scan() {
		t.Fatal("missing private fixture input")
	}
	var input struct{ PSKs [2]string }
	if json.Unmarshal(scan.Bytes(), &input) != nil {
		t.Fatal("invalid private fixture input")
	}
	org, node, site, connection := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	m := RuntimeMaterial{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: 2, Kind: "apply", Manifest: RuntimeManifest{OrgID: org, NodeID: node, SiteID: site, ConnectionID: connection, DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1", CustomerOutsideAddress: "198.19.240.10", LocalPrefixes: []string{"10.10.0.0/24"}, RemotePrefixes: []string{"10.20.0.0/24"}}}, Policy: RuntimePolicy{Hash: strings.Repeat("a", 64)}}
	for i := range m.Manifest.Tunnels {
		id := uuid.New()
		m.Manifest.Tunnels[i] = RuntimeTunnel{ID: id, Slot: i + 1, SecretRevision: 1, LinkName: KernelTunnelName(id), XFRMID: KernelTunnelID(id), ReqID: KernelTunnelID(id), OutsideAddress: []string{"198.19.240.20", "198.19.240.21"}[i], InsideCIDR: []string{"169.254.10.0/30", "169.254.10.4/30"}[i], CustomerInsideAddress: []string{"169.254.10.1", "169.254.10.5"}[i], CloudInsideAddress: []string{"169.254.10.2", "169.254.10.6"}[i], RouteTable: 254, RouteProtocol: 242, RouteMetric: uint32(50001 + i), Selected: i == 0}
		m.Secrets[i] = RuntimeSecret{TunnelID: id, Revision: 1, PSK: input.PSKs[i]}
		input.PSKs[i] = ""
	}
	for _, protocol := range []string{"tcp", "udp"} {
		port := uint16(18080)
		if protocol == "udp" {
			port = 18081
		}
		m.Policy.Grants = append(m.Policy.Grants, RuntimeGrant{Source: "10.10.0.0/24", Destination: "10.20.0.0/24", Protocol: protocol, PortLow: port, PortHigh: port, RuleID: uuid.NewString()})
	}
	raw, _ := json.Marshal(m.Manifest)
	sum := sha256.Sum256(raw)
	m.OwnershipDigest = hex.EncodeToString(sum[:])
	process, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("supervisor startup", err)
	}
	defer process.Close()
	environment, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	if _, _, err := runtimeMaterialEntry(m, org, node, ns); err != nil {
		t.Fatal("fixture material invalid")
	}
	dir := "/run/controller-journal"
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := RuntimeControllerConfig{OrgID: org, GatewayID: node, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: environment}
	controller, err := NewRuntimeController(config, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	controller.prove = func(c context.Context, entry RuntimeJournalEntry, env RuntimeEnvironment) error {
		e := controller.proveRuntime(c, entry, env)
		if e != nil {
			d, de := process.Client.Inspect(c)
			t.Logf("native proof daemon SAs=%+v error=%v", d.SAs, de)
			kr, _ := NewKernelReader("/sbin/ip")
			k, ke := kr.Read(c)
			t.Logf("native proof kernel=%+v error=%v", k, ke)
			rawRoutes, _ := runKernelCommand(c, "/sbin/ip", "-j", "-d", "-N", "-4", "route", "show", "table", "all")
			t.Logf("native raw routes=%s", rawRoutes)
			xr, _ := NewXFRMReader("/sbin/ip")
			x, xe := xr.Read(c)
			t.Logf("native proof keyless XFRM=%+v error=%v", x, xe)
			for _, query := range [][]string{{"xfrm", "state", "list", "nokeys"}, {"xfrm", "policy", "list", "nosock"}} {
				raw, readErr := runKernelCommand(c, "/sbin/ip", query...)
				t.Logf("native keyless XFRM %v: %s error=%v", query, raw, readErr)
			}
		}
		return e
	}
	originalReplace := controller.replace
	controller.replace = func(c context.Context, intent GuardIntent) (GuardManifest, error) {
		v, e := originalReplace(c, intent)
		t.Logf("native guard replacement => %v", e)
		return v, e
	}
	defer func() { controller.Close() }()
	if err = controller.Start(ctx); err != nil {
		t.Fatal("controller startup", err)
	}
	qualification, probeErr := ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", process.Client, process.Alive)
	if probeErr != nil {
		t.Fatal("native platform probe", probeErr)
	}
	if err = controller.AttachQualification(qualification); err != nil {
		t.Fatal("native qualification attach", err)
	}
	if controller.Capability() != 1 {
		t.Fatal("qualified native controller capability missing")
	}
	if _, err = controller.Apply(ctx, m); err != nil {
		entries, je := controller.journal.Entries()
		for _, entry := range entries {
			t.Logf("native journal phase=%s observations=%v", entry.Phase, entry.Observed)
		}
		t.Logf("native journal read => %v", je)
		t.Fatal("controller apply", err)
	}
	before, err := process.Client.Inspect(ctx)
	if err != nil || len(before.SAs) != 2 {
		t.Fatal("SA baseline", err)
	}
	status, statusErr := controller.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
	if statusErr != nil || status.Tunnels[0].Status != "up" || status.Tunnels[1].Status != "up" || !status.Tunnels[0].Selected || status.Tunnels[1].Selected {
		t.Fatal("native two-tunnel Up observation", statusErr, status.Tunnels)
	}
	fmt.Println("RUNTIME_APPLIED")
	if !scan.Scan() || scan.Text() != "refresh" {
		t.Fatal("missing refresh control")
	}
	if _, err = controller.Apply(ctx, m); err != nil {
		t.Fatal("controller refresh", err)
	}
	after, err := process.Client.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := func(v DaemonInventory) map[string]uint64 {
		o := map[string]uint64{}
		for _, sa := range v.SAs {
			o[sa.Name] = sa.UniqueID
		}
		return o
	}
	if !reflect.DeepEqual(ids(before), ids(after)) {
		t.Fatal("routine renewal replaced live SAs")
	}
	fmt.Println("RUNTIME_REFRESHED")
	if !scan.Scan() || scan.Text() != "restart" {
		t.Fatal("missing restart control")
	}
	if err = controller.Close(); err != nil {
		t.Fatal(err)
	}
	controller, err = NewRuntimeController(config, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.Start(ctx); err != nil {
		t.Fatal("offline refusal restore", err)
	}
	entriesBeforeCleanup, e := controller.journal.Entries()
	if e != nil || len(entriesBeforeCleanup) != 1 {
		t.Fatal("native loss setup journal", e)
	}
	if e = process.Client.removeTunnel(ctx, entriesBeforeCleanup[0].Engines[1]); e != nil {
		t.Fatal("native second tunnel loss", e)
	}
	status, statusErr = controller.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
	if statusErr != nil || status.Tunnels[0].Status != "up" || status.Tunnels[1].Status != "down" {
		t.Fatal("native independent Up/Down observation", statusErr, status.Tunnels)
	}
	t.Log("native telemetry observes independent Up/Down while forwarding remains refused")
	fmt.Println("RUNTIME_RESTART_REFUSAL")
	if !scan.Scan() || scan.Text() != "cleanup" {
		t.Fatal("missing cleanup control")
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: 3, Kind: "cleanup", OwnershipDigest: m.OwnershipDigest, CoversDeliveryRevision: 2, Manifest: m.Manifest}, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	lineageRaw, _ := json.Marshal(cleanup.Lineage)
	lineageSum := sha256.Sum256(lineageRaw)
	cleanup.OwnershipDigest = hex.EncodeToString(lineageSum[:])
	receipt, err := controller.Cleanup(ctx, cleanup)
	if err != nil || !receipt.GuardRetained {
		t.Fatal("exact cleanup", err)
	}
	after, err = process.Client.Inspect(ctx)
	if err != nil || len(after.SAs) != 0 || len(after.Connections) != 0 || len(after.SharedKeys) != 0 {
		t.Fatal("daemon cleanup incomplete", err)
	}
	// A CP delivery checkpoint may survive a lost HTTP body: no local reservation
	// exists for this disjoint connection. Cleanup must prove absence, not adopt.
	lost := m.RuntimeDelivery
	lost.ID = uuid.New()
	lost.Manifest.ConnectionID = uuid.New()
	lost.Manifest.RemotePrefixes = []string{"10.30.0.0/24"}
	for i := range lost.Manifest.Tunnels {
		id := uuid.New()
		lost.Manifest.Tunnels[i].ID = id
		lost.Manifest.Tunnels[i].LinkName = KernelTunnelName(id)
		lost.Manifest.Tunnels[i].XFRMID = KernelTunnelID(id)
		lost.Manifest.Tunnels[i].ReqID = KernelTunnelID(id)
	}
	lostRaw, _ := json.Marshal(lost.Manifest)
	lostSum := sha256.Sum256(lostRaw)
	lost.OwnershipDigest = hex.EncodeToString(lostSum[:])
	lostCleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: 3, Kind: "cleanup", CoversDeliveryRevision: 2, Manifest: lost.Manifest}, RetainGuard: true, Lineage: []RuntimeDelivery{lost}}
	lostRaw, _ = json.Marshal(lostCleanup.Lineage)
	lostSum = sha256.Sum256(lostRaw)
	lostCleanup.OwnershipDigest = hex.EncodeToString(lostSum[:])
	if !runtimeCleanupValid(lostCleanup, org, node) {
		t.Fatal("fixture lost cleanup invalid")
	}
	if _, _, e := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: lost}, org, node, ns, false); e != nil {
		t.Fatal("fixture lost entry invalid", e)
	}
	postRestartReplace := controller.replace
	controller.replace = func(c context.Context, in GuardIntent) (GuardManifest, error) {
		v, e := postRestartReplace(c, in)
		t.Logf("native lost cleanup guard => %v", e)
		if e != nil {
			manifest, re := RenderGuard(in)
			t.Logf("lost guard render=%v expected=%s", re, manifest.ExpectedJSON)
			raw, _ := controller.guard.reader.run(c, "-j", "list", "table", "inet", "tunnex_ipsec")
			t.Logf("lost guard actual=%s", raw)
			templates, _, te := controller.journal.guardTemplates()
			t.Logf("lost guard templates=%+v error=%v", templates, te)
		}
		return v, e
	}
	lostReceipt, e := controller.Cleanup(ctx, lostCleanup)
	if e != nil || !lostReceipt.GuardRetained {
		entries, _ := controller.journal.Entries()
		for _, entry := range entries {
			t.Logf("lost cleanup phase=%s absenceOnly=%v", entry.Phase, entry.AbsenceOnly)
		}
		t.Fatal("lost response absence-only cleanup", e)
	}
	entries, e := controller.journal.Entries()
	if e != nil || len(entries) != 2 || !entries[1].AbsenceOnly || entries[1].Phase != RuntimeRetainedRefusal {
		t.Fatal("lost response retained journal proof", e)
	}
	t.Log("native missing-journal cleanup acknowledged only after independent object absence and retained denial")
	fmt.Println("RUNTIME_CLEANED_GUARD_RETAINED")
	if !scan.Scan() || scan.Text() != "done" {
		t.Fatal("missing final control")
	}
	t.Log("PASS real controller apply, SA-preserving renewal, offline refusal restoration and exact retained-guard cleanup; CP lease mocked")
}
