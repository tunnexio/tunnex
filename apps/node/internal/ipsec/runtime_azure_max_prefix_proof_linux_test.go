//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"golang.org/x/sys/unix"
)

const azureProofJournal = "/var/lib/tunnex-node/ipsec/journal.json"
const azureProofVICI = "/run/tunnex-ipsec/charon.vici"
const azureProofBindingPath = "/run/tunnex-qualification/max-prefix-binding.json"

type azureProofProcess struct {
	PID        int
	ParentPID  int
	Ticks      uint64
	Namespace  string
	Executable bgpengine.FileIdentity
	Hash       string
}
type azureProofDaemon struct {
	Node, Charon    azureProofProcess
	ConfigSHA       string
	Config, Socket  bgpengine.FileIdentity
	Boot, Namespace string
	Device, Inode   uint64
}

func azureProofFileIdentity(st os.FileInfo) (bgpengine.FileIdentity, error) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 {
		return bgpengine.FileIdentity{}, fmt.Errorf("root_file_identity_refused")
	}
	return bgpengine.FileIdentity{Device: uint64(s.Dev), Inode: s.Ino, Mode: uint32(st.Mode())}, nil
}
func azureProofParents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("canonical_path_refused")
	}
	for p := filepath.Dir(path); p != "/"; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("protected_parent_refused")
		}
		if _, e = azureProofFileIdentity(st); e != nil {
			return e
		}
	}
	return nil
}
func azureProofRead(path string, limit int64) ([]byte, os.FileInfo, error) {
	if azureProofParents(path) != nil {
		return nil, nil, fmt.Errorf("private_parent_refused")
	}
	f, e := journalOpenNoFollow(path, false)
	if e != nil {
		return nil, nil, fmt.Errorf("private_file_refused")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !journalPrivate(st, false) || st.Size() > limit {
		return nil, nil, fmt.Errorf("private_bound_refused")
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, nil, fmt.Errorf("private_read_refused")
	}
	return raw, st, nil
}
func azureProofProc(pid int) (azureProofProcess, error) {
	var p azureProofProcess
	p.PID = pid
	stat, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil || len(stat) > 65536 {
		return p, fmt.Errorf("process_stat_refused")
	}
	end := strings.LastIndex(string(stat), ") ")
	if end < 0 {
		return p, fmt.Errorf("process_stat_refused")
	}
	fields := strings.Fields(string(stat)[end+2:])
	if len(fields) < 20 || fields[0] == "Z" {
		return p, fmt.Errorf("process_state_refused")
	}
	p.ParentPID, e = strconv.Atoi(fields[1])
	if e != nil || p.ParentPID < 0 {
		return p, fmt.Errorf("process_parent_refused")
	}
	p.Ticks, e = strconv.ParseUint(fields[19], 10, 64)
	if e != nil || p.Ticks == 0 {
		return p, fmt.Errorf("process_ticks_refused")
	}
	p.Namespace, e = os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if e != nil {
		return p, fmt.Errorf("process_namespace_refused")
	}
	st, e := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if e != nil {
		return p, fmt.Errorf("process_executable_refused")
	}
	p.Executable, e = azureProofFileIdentity(st)
	if e != nil {
		return p, e
	}
	f, e := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if e != nil {
		return p, fmt.Errorf("process_executable_refused")
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if e != nil || len(raw) > 64<<20 {
		return p, fmt.Errorf("process_executable_bound")
	}
	p.Hash = remediationSHA(raw)
	return p, nil
}
func azureProofPeer(ctx context.Context, path string, wanted int) (net.Conn, int, error) {
	st, e := os.Lstat(path)
	if e != nil || st.Mode() != os.ModeSocket|0600 || azureProofParents(path) != nil {
		return nil, 0, fmt.Errorf("private_socket_refused")
	}
	if _, e = azureProofFileIdentity(st); e != nil {
		return nil, 0, e
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return nil, 0, fmt.Errorf("socket_dial_refused")
	}
	fail := func() (net.Conn, int, error) { conn.Close(); return nil, 0, fmt.Errorf("socket_peer_refused") }
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fail()
	}
	fd, e := uc.SyscallConn()
	if e != nil {
		return fail()
	}
	var cred *unix.Ucred
	var ce error
	if fd.Control(func(v uintptr) { cred, ce = unix.GetsockoptUcred(int(v), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || ce != nil || cred == nil || cred.Uid != 0 || cred.Pid <= 0 || wanted > 0 && int(cred.Pid) != wanted {
		return fail()
	}
	return conn, int(cred.Pid), nil
}
func azureProofBoundPeer(ctx context.Context, path string, pid int, expected bgpengine.FileIdentity) (net.Conn, error) {
	check := func() bool {
		st, err := os.Lstat(path)
		if err != nil {
			return false
		}
		id, err := azureProofFileIdentity(st)
		return err == nil && azureProofSocketMatches(id, expected)
	}
	if !check() {
		return nil, fmt.Errorf("socket_identity_refused")
	}
	conn, _, err := azureProofPeer(ctx, path, pid)
	if err != nil {
		return nil, err
	}
	if !check() {
		conn.Close()
		return nil, fmt.Errorf("socket_identity_changed")
	}
	return conn, nil
}

func azureProofDaemonIdentity(ctx context.Context, b azureMaxProofBinding) (azureProofDaemon, error) {
	var result azureProofDaemon
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return result, fmt.Errorf("namespace_refused")
	}
	result.Namespace = ns
	st, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		return result, fmt.Errorf("namespace_stat_refused")
	}
	s := st.Sys().(*syscall.Stat_t)
	result.Device = uint64(s.Dev)
	result.Inode = s.Ino
	if result.Device != b.NamespaceDevice || result.Inode != b.NamespaceInode {
		return result, fmt.Errorf("attested_namespace_refused")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return result, fmt.Errorf("boot_refused")
	}
	result.Boot = strings.TrimSpace(string(boot))
	result.Node, e = azureProofProc(1)
	if e != nil || !validDigest(b.NodeExecutableSHA256) || result.Node.Hash != b.NodeExecutableSHA256 || result.Node.Namespace != ns {
		return result, fmt.Errorf("attested_node_refused")
	}
	conn, pid, e := azureProofPeer(ctx, azureProofVICI, 0)
	if e != nil {
		return result, e
	}
	conn.Close()
	result.Charon, e = azureProofProc(pid)
	if e != nil || result.Charon.Namespace != ns || !azureProofParentMatches(result.Charon.ParentPID, result.Node.PID) {
		return result, fmt.Errorf("managed_charon_process_refused")
	}
	packageRaw, e := os.ReadFile(daemonExecutable)
	if e != nil || remediationSHA(packageRaw) != result.Charon.Hash {
		return result, fmt.Errorf("managed_charon_package_refused")
	}
	conf, cst, e := azureProofRead("/run/tunnex-ipsec/strongswan.conf", 65536)
	if e != nil {
		return result, e
	}
	result.Config, e = azureProofFileIdentity(cst)
	if e != nil {
		return result, e
	}
	result.ConfigSHA = remediationSHA(conf)
	st, e = os.Lstat(azureProofVICI)
	if e != nil {
		return result, fmt.Errorf("socket_refused")
	}
	result.Socket, e = azureProofFileIdentity(st)
	return result, e
}
func azureProofChildAbsent(child bgpengine.ChildIdentity) bool {
	raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.PID))
	if os.IsNotExist(e) {
		return true
	}
	if e != nil || len(raw) > 65536 {
		return false
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(raw)[end+2:])
	if len(fields) < 20 {
		return false
	}
	ticks, e := strconv.ParseUint(fields[19], 10, 64)
	return e == nil && (ticks != child.StartTicks || fields[0] == "Z")
}
func azureProofRetiredProcess(p bgpengine.ProcessIdentity, boot string) error {
	if p.Stage != "cleaned" || azureProofParents(p.Directory) != nil {
		return fmt.Errorf("retired_process_scope_refused")
	}
	st, e := os.Lstat(p.Directory)
	if e != nil || !journalPrivate(st, true) {
		return fmt.Errorf("retired_directory_refused")
	}
	id, e := azureProofFileIdentity(st)
	if e != nil || id != p.DirectoryFile {
		return fmt.Errorf("retired_directory_identity_refused")
	}
	entries, e := os.ReadDir(p.Directory)
	if e != nil || len(entries) != 0 {
		return fmt.Errorf("retired_artifacts_remain")
	}
	if p.BootID == boot {
		for _, c := range p.Children {
			if !azureProofChildAbsent(c) {
				return fmt.Errorf("retired_child_remains")
			}
		}
	}
	return nil
}
func azureProofBGPIdentity(ctx context.Context, p bgpengine.ProcessIdentity, boot, ns string, node azureProofProcess) error {
	if p.Stage != "ready" || p.BootID != boot || p.Namespace != ns || p.Supervisor.PID != node.PID || p.Supervisor.StartTicks != node.Ticks || p.Supervisor.Executable != node.Executable || len(p.Children) != 2 || azureProofParents(p.Directory) != nil {
		return fmt.Errorf("bgp_process_scope_refused")
	}
	st, e := os.Lstat(p.Directory)
	if e != nil || !journalPrivate(st, true) {
		return fmt.Errorf("bgp_directory_refused")
	}
	id, e := azureProofFileIdentity(st)
	if e != nil || id != p.DirectoryFile {
		return fmt.Errorf("bgp_directory_identity_refused")
	}
	names, e := os.ReadDir(p.Directory)
	if e != nil || len(names) != len(p.Files) {
		return fmt.Errorf("bgp_artifact_set_refused")
	}
	// Directory metadata is checked; no locks/artifacts are acquired or modified.
	expected := map[string]bgpengine.FileIdentity{}
	for _, file := range p.Files {
		expected[file.Name] = file.File
		st, e = os.Lstat(filepath.Join(p.Directory, file.Name))
		if e != nil {
			return fmt.Errorf("bgp_file_missing")
		}
		id, e = azureProofFileIdentity(st)
		if e != nil || id != file.File {
			return fmt.Errorf("bgp_file_identity_refused")
		}
	}
	for _, entry := range names {
		if entry.Name() == ".qualification" {
			return fmt.Errorf("unexpected_bgp_artifact")
		}
		if _, ok := expected[entry.Name()]; !ok && entry.Name() != "supervisor.lock" {
			return fmt.Errorf("unexpected_bgp_artifact")
		}
	}
	for _, child := range p.Children {
		observed, e := azureProofProc(child.PID)
		if e != nil || observed.Ticks != child.StartTicks || observed.Executable != child.Executable || observed.Namespace != ns {
			return fmt.Errorf("bgp_child_identity_refused")
		}
		executable := "/opt/tunnex-bgp/" + child.Name
		raw, e := os.ReadFile(executable)
		if e != nil || remediationSHA(raw) != observed.Hash {
			return fmt.Errorf("bgp_child_package_refused")
		}
	}
	conn, _, e := azureProofPeer(ctx, filepath.Join(p.Directory, "bgpd.vty"), p.Children[1].PID)
	if e != nil {
		return e
	}
	return conn.Close()
}
func azureProofProcesses(ctx context.Context, p runtimeJournalPayload, e RuntimeJournalEntry, identity azureProofDaemon, baseline bool, historical map[uuid.UUID]bool) error {
	live := map[int]bool{}
	for _, entry := range p.Entries {
		if historical[entry.DeliveryID] {
			continue
		} // Exact archived identity discharged by distinct verified host boot.
		duties := append([]bgpengine.ProcessIdentity(nil), entry.BGPProcessRetired...)
		if entry.Phase == RuntimeRetainedRefusal && entry.BGPProcess != nil {
			duties = append(duties, *entry.BGPProcess)
		}
		for _, duty := range duties {
			if azureProofRetiredProcess(duty, identity.Boot) != nil {
				return fmt.Errorf("retired_process_proof_refused")
			}
		}
	}
	if baseline {
		if e.BGPProcess == nil || azureProofBGPIdentity(ctx, *e.BGPProcess, identity.Boot, identity.Namespace, identity.Node) != nil {
			return fmt.Errorf("active_bgp_process_refused")
		}
		for _, child := range e.BGPProcess.Children {
			live[child.PID] = true
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 8192 {
		return fmt.Errorf("process_inventory_refused")
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return fmt.Errorf("process_deadline_refused")
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("process_inventory_refused")
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if (exe == "/opt/tunnex-bgp/bgpd" || exe == "/opt/tunnex-bgp/zebra") && !live[pid] {
			return fmt.Errorf("unbound_managed_bgp_process")
		}
	}
	return nil
}

func azureProofVTY(ctx context.Context, e RuntimeJournalEntry, limitPeers *[2]azureProofLimitPeer) (bgpengine.Status, []bgpengine.LearnedRoute, error) {
	cfg, err := runtimeBGPProcessConfig(e)
	if err != nil || e.BGPProcess == nil {
		return bgpengine.Status{}, nil, fmt.Errorf("bgp_config_refused")
	}
	text, err := bgpengine.RenderConfig(cfg)
	if err != nil {
		return bgpengine.Status{}, nil, fmt.Errorf("bgp_config_refused")
	}
	actual, _, err := azureProofRead(filepath.Join(e.BGPProcess.Directory, "bgpd.conf"), 65536)
	if err != nil || string(actual) != text {
		return bgpengine.Status{}, nil, fmt.Errorf("bgp_config_content_refused")
	}
	var socket bgpengine.FileIdentity
	for _, f := range e.BGPProcess.Files {
		if f.Name == "bgpd.vty" {
			socket = f.File
		}
	}
	read := func(command string, limit int) ([]byte, error) {
		child, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		conn, err := azureProofBoundPeer(child, filepath.Join(e.BGPProcess.Directory, "bgpd.vty"), e.BGPProcess.Children[1].PID, socket)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		deadline, _ := child.Deadline()
		if conn.SetDeadline(deadline) != nil {
			return nil, fmt.Errorf("vty_deadline_refused")
		}
		return azureProofVTYWire(conn, command, limit)
	}
	summary, err := read("show bgp ipv4 unicast summary json", 65536)
	if err != nil {
		return bgpengine.Status{}, nil, err
	}
	status, err := bgpengine.ParseSummary(summary, cfg)
	if err != nil {
		return status, nil, fmt.Errorf("summary_parser_refused")
	}
	if limitPeers != nil {
		*limitPeers, err = azureProofLimitSummary(summary, cfg)
		if err != nil {
			return status, nil, err
		}
	}
	rib, err := read("show bgp ipv4 unicast json", 1<<20)
	if err != nil {
		return status, nil, err
	}
	routes, err := bgpengine.ParseRoutes(rib, cfg, status)
	if err != nil {
		return status, nil, fmt.Errorf("rib_parser_refused")
	}
	return status, routes, nil
}

// Opt-in root-owned container observer only. Normal test runs perform no live reads.
func TestAzureOwnedMaxPrefixNativeProof(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_MAX_PREFIX_NATIVE_PROOF") != "1" {
		t.Skip("explicit owned native read-only proof only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root_required")
	}
	bindingRaw, _, err := azureProofRead(azureProofBindingPath, 32768)
	if err != nil {
		t.Fatal("binding_read_refused")
	}
	var binding azureMaxProofBinding
	decoder := json.NewDecoder(bytes.NewReader(bindingRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&binding) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("binding_shape_refused")
	}
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	first, err := azureProofDaemonIdentity(ctx, binding)
	if err != nil {
		t.Fatal("initial_process_binding_refused")
	}
	raw, st, err := azureProofRead(azureProofJournal, runtimeJournalLimit)
	if err != nil {
		t.Fatal("journal_read_refused")
	}
	payload, err := decodeRuntimeJournalSnapshot(raw)
	if err != nil {
		t.Fatal("whole_journal_checksum_refused")
	}
	historical := map[uuid.UUID]bool{}
	if binding.HistoricalBoot != nil {
		proofRaw, _, err := azureProofRead("/run/tunnex-qualification/historical-reboot-proof.json", 8192)
		if err != nil {
			t.Fatal("historical_proof_read_refused")
		}
		stoppedRaw, _, err := azureProofRead("/run/tunnex-qualification/historical-stopped-journal.json", runtimeJournalLimit)
		if err != nil {
			t.Fatal("historical_journal_read_refused")
		}
		historical, err = azureProofHistoricalEntries(payload, proofRaw, stoppedRaw, *binding.HistoricalBoot, first.Boot, first.Namespace, time.Now())
		if err != nil {
			t.Fatal("historical_boot_binding_refused")
		}
	}
	entry, err := azureMaxProofEntryHistory(payload, binding, first.Namespace, historical)
	if err != nil {
		t.Fatal("whole_journal_scope_refused")
	}
	kr, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal("kernel_reader_refused")
	}
	xr, err := NewXFRMReader("/sbin/ip")
	if err != nil {
		t.Fatal("xfrm_reader_refused")
	}
	gr, err := NewGuardReader("/usr/sbin/nft")
	if err != nil {
		t.Fatal("guard_reader_refused")
	}
	transport := viciTransport{dial: func(ctx context.Context) (net.Conn, error) {
		conn, e := azureProofBoundPeer(ctx, azureProofVICI, first.Charon.PID, first.Socket)
		return conn, e
	}}
	daemon := &DaemonClient{request: transport.call}
	guard := payload.Guards[0]
	manifest := GuardManifest{Namespace: guard.Namespace, Revision: guard.Revision, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON}
	limitFrames := [][2]azureProofLimitPeer{}
	collect := func() (DaemonInventory, KernelInventory, XFRMInventory, bgpengine.Status, []bgpengine.LearnedRoute) {
		if azureProofProcesses(ctx, payload, entry, first, binding.Mode != "absence", historical) != nil {
			t.Fatal("all_process_duties_refused")
		}
		if gr.Check(ctx, manifest) != nil {
			t.Fatal("whole_guard_refused")
		}
		d, e := daemon.Inspect(ctx)
		if e != nil {
			t.Fatal("managed_vici_refused")
		}
		k, e := kr.Read(ctx)
		if e != nil {
			t.Fatal("kernel_inventory_refused")
		}
		x, e := xr.Read(ctx)
		if e != nil {
			t.Fatal("xfrm_inventory_refused")
		}
		var status bgpengine.Status
		var routes []bgpengine.LearnedRoute
		if binding.Mode != "absence" {
			var frame [2]azureProofLimitPeer
			var frameTarget *[2]azureProofLimitPeer
			if binding.Mode == "post-limit" {
				frameTarget = &frame
			}
			status, routes, e = azureProofVTY(ctx, entry, frameTarget)
			if e != nil {
				t.Fatal("independent_frr_read_refused")
			}
			if binding.Mode == "baseline" {
				if azureMaxProofBaseline(entry, d, k, x, status, routes) != nil {
					t.Fatal("baseline_native_binding_refused")
				}
			} else {
				if azureMaxProofPostLimit(entry, d, k, x, status, routes, frame) != nil {
					t.Fatal("post_limit_native_binding_refused")
				}
				links, err := gr.interfaces()
				if err != nil {
					t.Fatal("post_limit_guard_interfaces_refused")
				}
				observed, err := gr.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
				if err != nil || VerifyGuardWithdrawal([]byte(guard.ExpectedJSON), observed, links) != nil || azureProofNoForwardGrants(observed, links) != nil {
					t.Fatal("post_limit_guard_withdrawal_refused")
				}
				limitFrames = append(limitFrames, frame)
			}
		} else {
			if azureMaxProofAbsenceHistory(payload, d, k, x, historical) != nil {
				t.Fatal("all_retained_absence_refused")
			}
			links, e := gr.interfaces()
			if e != nil {
				t.Fatal("guard_interfaces_refused")
			}
			observed, e := gr.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
			if e != nil || VerifyGuardWithdrawal([]byte(guard.ExpectedJSON), observed, links) != nil {
				t.Fatal("whole_withdrawal_refused")
			}
		}
		return d, k, x, status, routes
	}
	d, k, x, status, routes := collect()
	again, err := azureProofDaemonIdentity(ctx, binding)
	if err != nil || again != first {
		t.Fatal("process_bracket_changed")
	}
	da, ka, xa, statusAfter, routesAfter := collect()
	last, err := azureProofDaemonIdentity(ctx, binding)
	if err != nil || last != first {
		t.Fatal("process_bracket_changed")
	}
	if azureProofCanonical(d, k, x) != azureProofCanonical(da, ka, xa) {
		t.Fatal("native_identity_bracket_changed")
	}
	if !reflect.DeepEqual(status, statusAfter) || !reflect.DeepEqual(routes, routesAfter) {
		t.Fatal("bgp_bracket_changed")
	}
	if binding.Mode == "post-limit" && (len(limitFrames) != 2 || limitFrames[0] != limitFrames[1]) {
		t.Fatal("post_limit_frame_bracket_changed")
	}
	trafficAdvanced, err := azureProofTrafficCounters(d, da)
	if err != nil {
		t.Fatal("traffic_counter_bracket_refused")
	}
	after, ast, err := azureProofRead(azureProofJournal, runtimeJournalLimit)
	if err != nil || !os.SameFile(st, ast) || !bytes.Equal(raw, after) || ctx.Err() != nil {
		t.Fatal("journal_bracket_changed")
	}
	projection := azureMaxProofProjection(payload, entry, binding, time.Now(), remediationSHA(raw), da, ka, xa, statusAfter, routesAfter)
	// The receipt binds the actual process observed in every bracket, rather
	// than only a separately supplied expected executable hash.
	projection["node_executable_sha256"] = last.Node.Hash
	projection["historical_boot_entry_count"] = len(historical)
	projection["traffic_counters_monotonic_advanced"] = trafficAdvanced
	if binding.Mode == "post-limit" {
		projection["kind"] = "owned_max_prefix_shutdown_observation"
		projection["maximum_prefixes"] = entry.BGP.MaximumPrefixes
		projection["limit_peers"] = limitFrames[1]
		projection["approved_and_candidate_routes_absent"] = true
		projection["forward_grant_rules_absent"] = true
		projection["scope"] = "Exact owned PfxCt frames and independent route/forward-grant absence; no Azure NLRI, API ACK or packet inference"
	}
	if binding.HistoricalBoot != nil {
		projection["historical_proof_sha256"] = binding.HistoricalBoot.ProofSHA256
		projection["historical_stopped_journal_sha256"] = binding.HistoricalBoot.StoppedJournalSHA256
		projection["host_machine_identity_source"] = "external_root_attestation"
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal("typed_projection_refused")
	}
	fmt.Println("AZURE_MAX_PREFIX_NATIVE_PROOF " + string(encoded))
}
