//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Read-only native helper. A private output file is the only accepted output;
// raw VICI, XFRM encryption keys and journal payloads never reach test logs.
func TestAzureOwnedScheduledRekeySnapshot(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_SNAPSHOT") != "1" {
		t.Skip("explicit owned scheduler diagnostic only")
	}
	fail := func() { t.Helper(); t.Fatal("owned_scheduler_snapshot_refused") }
	expected := os.Getenv("TUNNEX_AZURE_EXPECTED_NODE_SHA256")
	exe, e := os.ReadFile("/proc/1/exe")
	if os.Geteuid() != 0 || e != nil || !validDigest(expected) || remediationSHA(exe) != expected {
		fail()
		return
	}
	raw, st, e := remediationRead("/var/lib/tunnex-node/ipsec/journal.json")
	if e != nil {
		fail()
		return
	}
	var envelope runtimeJournalEnvelope
	if json.Unmarshal(raw, &envelope) != nil || !validJournalPayload(envelope.Payload) || journalChecksum(envelope.Payload) != envelope.Checksum {
		fail()
		return
	}
	var expectedBinding azureSchedulerBinding
	if json.Unmarshal([]byte(os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_BINDING")), &expectedBinding) != nil {
		fail()
		return
	}
	entry, retainedIdentity, e := azureSchedulerEntry(envelope.Payload, expectedBinding)
	if e != nil {
		fail()
		return
	}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil || entry.Allocation.Namespace != ns {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pidRaw, e := os.ReadFile("/run/tunnex-ipsec/charon.pid")
	charonPID, e2 := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if e != nil || e2 != nil || charonPID <= 1 {
		fail()
		return
	}
	charonBinary, e := os.ReadFile(daemonExecutable)
	if e != nil {
		fail()
		return
	}
	charonSHA := remediationSHA(charonBinary)
	charonStat, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", charonPID))
	if e != nil {
		fail()
		return
	}
	charonFields := strings.Fields(string(charonStat)[strings.LastIndex(string(charonStat), ")")+1:])
	if len(charonFields) <= 19 {
		fail()
		return
	}
	daemon, e := azureSchedulerOwnedDaemon(charonPID, charonSHA, charonStat)
	if e != nil {
		fail()
		return
	}
	probe, e := newRuntimePlatformProbe("/sbin/ip", "/usr/sbin/nft", daemon, func() bool { return true })
	if e != nil || probe.packaged(ctx) != nil {
		fail()
		return
	}
	d, e := daemon.Inspect(ctx)
	if e != nil {
		fail()
		return
	}
	kr, e := NewKernelReader("/sbin/ip")
	if e != nil {
		fail()
		return
	}
	k, e := kr.Read(ctx)
	if e != nil {
		fail()
		return
	}
	xr, e := NewXFRMReader("/sbin/ip")
	if e != nil {
		fail()
		return
	}
	x, e := xr.Read(ctx)
	routeProof, routeErr := NewKernelApplier("/sbin/ip")
	if e != nil || routeErr != nil || azureSchedulerNativeProof(ctx, entry, d, k, x, routeProof) != nil {
		fail()
		return
	}
	gr, e := NewGuardReader("/usr/sbin/nft")
	if e != nil {
		fail()
		return
	}
	// A journal can retain the alternate template of a guarded replacement.
	// Exactly one complete template must match the actual combined guard. Never
	// drop retained denial objects or synthesize a smaller active-only template.
	if azureSchedulerCombinedGuard(envelope.Payload.Guards, ns, func(g runtimeGuardTemplate) bool {
		return gr.Check(ctx, GuardManifest{Namespace: g.Namespace, Revision: g.Revision, Digest: g.Digest, ExpectedJSON: g.ExpectedJSON}) == nil
	}) != nil {
		fail()
		return
	}
	count := entry.Allocation.activeTunnelCount()
	engines := entry.Engines[:count]
	if len(d.Connections) != count || len(d.SAs) != count || len(d.SharedKeys) != count {
		fail()
		return
	}
	children := []map[string]any{}
	for _, engine := range engines {
		sa, child, retired, e := ownedRuntimeChildren(engine, d)
		if e != nil || sa == nil || !sa.Established || child == nil || !child.Installed {
			fail()
			return
		}
		in, out, e := ownedRuntimeSPIStates(engine, child, retired, x)
		if e != nil || in != 1 || out != 1 {
			fail()
			return
		}
		children = append(children, map[string]any{"name": engineName(engine), "child_id": child.UniqueID, "spi_in": child.SPIIn, "spi_out": child.SPIOut, "retired": retired != nil})
	}
	if azureSchedulerVerifyLoaded(ctx, daemon, engines, os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_TIMER_MODE")) != nil {
		fail()
		return
	}
	config, e := azureSchedulerConfig(engines)
	if e != nil {
		fail()
		return
	}
	after, ast, e := remediationRead("/var/lib/tunnex-node/ipsec/journal.json")
	if e != nil || ctx.Err() != nil || st.Dev != ast.Dev || st.Ino != ast.Ino || !bytes.Equal(raw, after) {
		fail()
		return
	}
	output := os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_OUTPUT")
	if !strings.HasPrefix(output, "/run/tunnex-ipsec/azure-scheduler-") || strings.Contains(output, "..") || strings.ContainsAny(output, "\n\r") {
		fail()
		return
	}
	file, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		fail()
		return
	}
	defer file.Close()
	if ctx.Err() != nil {
		fail()
		return
	}
	if json.NewEncoder(file).Encode(map[string]any{"retained_identity": retainedIdentity, "retained_count": len(envelope.Payload.Entries) - 1, "charon_start_ticks": charonFields[19], "charon_pid": charonPID, "charon_sha": charonSHA, "profile": entry.Allocation.ProfileID, "delivery": entry.DeliveryID, "binding": engines[0].Binding, "engines": engines, "config": config, "children": children, "strict_native": true, "full_guard": true}) != nil || file.Sync() != nil || ctx.Err() != nil {
		fail()
	}
}

func azureSchedulerOwnedDaemon(charonPID int, charonSHA string, charonStat []byte) (*DaemonClient, error) {
	daemon, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		return nil, e
	}
	transport := viciTransport{dial: func(ctx context.Context) (net.Conn, error) {
		conn, e := dialOwnedVICI(ctx, "/run/tunnex-ipsec/charon.vici")
		if e != nil {
			return nil, e
		}
		socket, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, ErrDaemonProtocol
		}
		fd, e := socket.SyscallConn()
		if e != nil {
			conn.Close()
			return nil, e
		}
		var credential *unix.Ucred
		var ce error
		e = fd.Control(func(value uintptr) {
			credential, ce = unix.GetsockoptUcred(int(value), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
		binary, be := os.ReadFile(fmt.Sprintf("/proc/%d/exe", charonPID))
		stat, se := os.ReadFile(fmt.Sprintf("/proc/%d/stat", charonPID))
		// Only stable start ticks, not changing counters, identify the process.
		sameStart := func(a, b []byte) bool {
			as := strings.Fields(string(a)[strings.LastIndex(string(a), ")")+1:])
			bs := strings.Fields(string(b)[strings.LastIndex(string(b), ")")+1:])
			return len(as) > 19 && len(bs) > 19 && as[19] == bs[19]
		}
		if e != nil || ce != nil || credential == nil || credential.Uid != 0 || int(credential.Pid) != charonPID || be != nil || se != nil || remediationSHA(binary) != charonSHA || !sameStart(charonStat, stat) {
			conn.Close()
			return nil, ErrDaemonProtocol
		}
		return conn, nil
	}}
	daemon.request = transport.call
	return daemon, nil
}

// Default-off, private fixed-action request. No arbitrary VICI command, config
// file, key input, socket path, or caller-provided connection name is accepted.
func TestAzureOwnedScheduledRekeyControl(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_CONTROL") != "1" {
		t.Skip("explicit owned scheduler control only")
	}
	stage := "request-path"
	fail := func() { t.Helper(); t.Fatal("owned_scheduler_control_refused", stage) }
	path := os.Getenv("TUNNEX_AZURE_SCHEDULED_REKEY_REQUEST")
	if !strings.HasPrefix(path, "/run/tunnex-ipsec/azure-scheduler-request-") || strings.Contains(path, "..") || strings.ContainsAny(path, "\n\r") {
		fail()
		return
	}
	stage = "request-private-read"
	raw, st, err := remediationRead(path)
	if err != nil || st.Mode&0777 != 0600 || st.Uid != 0 {
		fail()
		return
	}
	stage = "request-decode"
	var request struct {
		Binding                                                  azureSchedulerBinding
		Delivery                                                 string
		RetainedIdentity                                         string
		CharonPID                                                int
		CharonSHA, CharonStart, NodeSHA, ConfigSHA, Action, Mode string
		Slot                                                     int
		WatchdogMonotonicDeadlineNS                              int64
		BootID                                                   string
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		fail()
		return
	}
	stage = "request-ceiling"
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	offsets, offsetsErr := os.ReadFile("/proc/self/timens_offsets")
	if bootErr != nil || offsetsErr != nil || !azureSchedulerClockBinding(request.BootID, strings.TrimSpace(string(boot)), string(offsets)) {
		fail()
		return
	}
	var clock unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock) != nil {
		fail()
		return
	}
	budget, budgetErr := azureSchedulerControlBudget(clock.Nano(), request.WatchdogMonotonicDeadlineNS)
	if budgetErr != nil {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	stage = "node-identity"
	node, err := os.ReadFile("/proc/1/exe")
	if os.Geteuid() != 0 || err != nil || !validDigest(request.NodeSHA) || remediationSHA(node) != request.NodeSHA || request.CharonPID <= 1 || !validDigest(request.CharonSHA) {
		fail()
		return
	}
	stage = "journal-read"
	journal, jst, err := remediationRead("/var/lib/tunnex-node/ipsec/journal.json")
	var envelope runtimeJournalEnvelope
	if err != nil || json.Unmarshal(journal, &envelope) != nil || journalChecksum(envelope.Payload) != envelope.Checksum {
		fail()
		return
	}
	stage = "binding-history"
	entry, retained, err := azureSchedulerEntry(envelope.Payload, request.Binding)
	if err != nil || entry.DeliveryID.String() != request.Delivery || retained != request.RetainedIdentity {
		fail()
		return
	}
	stage = "render-identity"
	config, configErr := azureSchedulerConfig(entry.Engines[:entry.Allocation.activeTunnelCount()])
	if configErr != nil || !validDigest(request.ConfigSHA) || remediationSHA([]byte(config)) != request.ConfigSHA {
		fail()
		return
	}
	stage = "namespace"
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != entry.Allocation.Namespace {
		fail()
		return
	}
	stage = "daemon-identity"
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", request.CharonPID))
	fields := strings.Fields(string(stat)[strings.LastIndex(string(stat), ")")+1:])
	binary, be := os.ReadFile(daemonExecutable)
	if err != nil || be != nil || len(fields) <= 19 || fields[19] != request.CharonStart || remediationSHA(binary) != request.CharonSHA {
		fail()
		return
	}
	stage = "guard-read"
	daemon, err := azureSchedulerOwnedDaemon(request.CharonPID, request.CharonSHA, stat)
	guard, ge := NewGuardReader("/usr/sbin/nft")
	if err != nil || ge != nil || azureSchedulerCombinedGuard(envelope.Payload.Guards, ns, func(g runtimeGuardTemplate) bool {
		return guard.Check(ctx, GuardManifest{Namespace: g.Namespace, Revision: g.Revision, Digest: g.Digest, ExpectedJSON: g.ExpectedJSON}) == nil
	}) != nil {
		fail()
		return
	}
	stage = "journal-bracket"
	after, ast, err := remediationRead("/var/lib/tunnex-node/ipsec/journal.json")
	stage = azureSchedulerJournalStage(err, ctx.Err(), err == nil && jst.Dev == ast.Dev && jst.Ino == ast.Ino, journal, after)
	if stage != "" {
		fail()
		return
	}
	controlErr := azureSchedulerControl(ctx, daemon, entry.Engines[:entry.Allocation.activeTunnelCount()], request.Action, request.Mode, request.Slot)
	stage = azureSchedulerFixedStage(controlErr)
	if ctx.Err() != nil {
		stage = "action-context"
	}
	if controlErr != nil || ctx.Err() != nil {
		fail()
		return
	}
}
