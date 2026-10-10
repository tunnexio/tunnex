//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Read-only; outer operator binds CP identity. In-memory epochs are unobservable.
func TestAzureOwnedComponentTimingNative(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_COMPONENT_TIMING") != "1" {
		t.Skip("explicit owned read-only timing only")
	}
	const expected = "bd28fea088fde56134ce3ef745ffa997b94fb33530534eb2ee0f3670eee4d2a2"
	exe, e := os.ReadFile("/proc/1/exe")
	if os.Geteuid() != 0 || os.Getenv("TUNNEX_AZURE_EXPECTED_NODE_SHA256") != expected || e != nil || remediationSHA(exe) != expected {
		t.Fatal("exact_node_refused")
	}
	dir := "/var/lib/tunnex-node/ipsec"
	info, e := os.Lstat(dir)
	if e != nil || !journalPrivate(info, true) || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("private_parent_refused")
	}
	read := func() ([]byte, os.FileInfo) {
		f, e := journalOpenNoFollow(dir+"/journal.json", false)
		if e != nil {
			t.Fatal("private_journal_refused")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !journalPrivate(st, false) || st.Size() > runtimeJournalLimit {
			t.Fatal("private_journal_refused")
		}
		raw, e := io.ReadAll(io.LimitReader(f, runtimeJournalLimit+1))
		if e != nil || len(raw) > runtimeJournalLimit {
			t.Fatal("private_journal_refused")
		}
		return raw, st
	}
	raw, st := read()
	payload, e := decodeRuntimeJournalSnapshot(raw)
	if e != nil {
		t.Fatal("strict_journal_refused")
	}
	current := []RuntimeJournalEntry{}
	for _, entry := range payload.Entries {
		if entry.Phase != RuntimeRetainedRefusal {
			current = append(current, entry)
		}
	}
	if len(current) != 1 || len(payload.Guards) != 1 {
		t.Fatal("exact_current_entry_refused")
	}
	entry := current[0]
	ns, e := os.Readlink("/proc/self/ns/net")
	boot, be := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || be != nil || entry.Phase != RuntimeApplied || entry.ContractVersion != 3 || entry.Allocation.ProfileID != AzureActiveActiveBGPProfile || entry.Allocation.activeTunnelCount() != 2 || entry.Allocation.ConnectionID.String() != "9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99" || entry.Allocation.Namespace != ns || entry.Restoration == nil || entry.Restoration.BootID != strings.TrimSpace(string(boot)) || !validJournalBGP(entry) || !validBGPRoutes(entry) {
		t.Fatal("applied22_scope_refused")
	}
	for _, engine := range entry.Engines {
		if engine.Binding.DesiredRevision != 22 {
			t.Fatal("applied22_binding_refused")
		}
	}
	guard := payload.Guards[0]
	if guard.Namespace != ns {
		t.Fatal("guard_namespace_refused")
	}
	daemon, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		t.Fatal("daemon_reader_refused")
	}
	kernel, e := NewKernelReader("/sbin/ip")
	if e != nil {
		t.Fatal("kernel_reader_refused")
	}
	xreader, e := NewXFRMReader("/sbin/ip")
	if e != nil {
		t.Fatal("xfrm_reader_refused")
	}
	environment, e := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if e != nil {
		t.Fatal("environment_reader_refused")
	}
	reader, e := NewGuardReader("/usr/sbin/nft")
	if e != nil {
		t.Fatal("guard_reader_refused")
	}
	// Helper-only wrappers; residual includes unwrapped iptables census and validation.
	inspector, ok := environment.(*runtimeEnvironmentInspector)
	if !ok {
		t.Fatal("concrete_environment_refused")
	}
	type commandTiming struct {
		Count    int   `json:"count"`
		SummedMS int64 `json:"summed_ms"`
		MaxMS    int64 `json:"max_ms"`
		elapsed  time.Duration
	}
	commands := map[string]*commandTiming{}
	for _, name := range []string{"route_get", "rule", "link", "main_route", "address", "full_ruleset", "unexpected"} {
		commands[name] = &commandTiming{}
	}
	var wrappedElapsed time.Duration
	var firstNFT []byte
	wrap := func(run func(context.Context, ...string) ([]byte, error)) func(context.Context, ...string) ([]byte, error) {
		return func(ctx context.Context, args ...string) ([]byte, error) {
			name := "unexpected"
			for label, expected := range map[string][]string{"rule": {"-j", "-4", "rule", "show"}, "link": {"-j", "-d", "link", "show"}, "main_route": {"-j", "-4", "route", "show", "table", "main"}, "address": {"-j", "-4", "address", "show"}, "full_ruleset": {"-j", "list", "ruleset"}} {
				if reflect.DeepEqual(args, expected) {
					name = label
				}
			}
			if len(args) == 5 && reflect.DeepEqual(args[:4], []string{"-j", "-4", "route", "get"}) {
				name = "route_get"
			}
			start := time.Now()
			output, err := run(ctx, args...)
			elapsed := time.Since(start)
			if name == "full_ruleset" && firstNFT == nil && err == nil {
				firstNFT = append([]byte(nil), output...)
			}
			row := commands[name]
			row.Count++
			row.elapsed += elapsed
			row.SummedMS = row.elapsed.Milliseconds()
			if elapsed.Milliseconds() > row.MaxMS {
				row.MaxMS = elapsed.Milliseconds()
			}
			wrappedElapsed += elapsed
			return output, err
		}
	}
	inspector.ip = wrap(inspector.ip)
	inspector.nft = wrap(inspector.nft)
	var observeElapsed time.Duration
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows := []map[string]any{}
	timed := func(component string, call func() error) bool {
		start := time.Now()
		err := call()
		rows = append(rows, map[string]any{"component": component, "count": 1, "elapsed_ms": time.Since(start).Milliseconds(), "passed": err == nil, "context_active": ctx.Err() == nil})
		return err == nil
	}
	var finalChecks map[string]bool
	emit := func(stage string, counts map[string]int) {
		safe, _ := json.Marshal(map[string]any{"stage": stage, "measurements": rows, "counts": counts, "authority": false, "in_memory_epoch_observed": false, "final_checks": finalChecks, "environment_commands": commands, "residual_census_and_parse_ms": max(int64(0), (observeElapsed - wrappedElapsed).Milliseconds())})
		t.Log("AZURE_OWNED_COMPONENT_TIMING " + string(safe))
	}
	var d DaemonInventory
	var k KernelInventory
	var x XFRMInventory
	if !timed("daemon_inspect", func() error { var err error; d, err = daemon.Inspect(ctx); return err }) || !timed("kernel_read", func() error { var err error; k, err = kernel.Read(ctx); return err }) || !timed("xfrm_read", func() error { var err error; x, err = xreader.Read(ctx); return err }) {
		emit("initial_reader_refused", nil)
		t.Fatal("initial_reader_refused")
	}
	strict := func(d DaemonInventory, k KernelInventory, x XFRMInventory) bool {
		if runtimeTunnelStatuses(entry, d, k, x) != [2]string{"up", "up"} {
			return false
		}
		for _, engine := range entry.Engines {
			matches := 0
			for _, sa := range d.SAs {
				if sa.Name == engineName(engine) {
					matches++
					if len(sa.Children) != 1 || !sa.Children[0].Installed {
						return false
					}
				}
			}
			if matches != 1 {
				return false
			}
		}
		return k.Namespace == ns && x.Namespace == ns
	}
	counts := map[string]int{"daemon_sas": len(d.SAs), "sad": len(x.States), "spd": len(x.Policies), "links": len(k.Links), "routes": len(k.Routes)}
	if !strict(d, k, x) {
		emit("initial_native_refused", counts)
		t.Fatal("initial_native_refused")
	}
	environmentOK := timed("environment_observe", func() error {
		start := time.Now()
		_, err := environment.Observe(ctx, entry.Allocation, entry.Engines)
		observeElapsed = time.Since(start)
		return err
	})
	guardOK := timed("full_guard_check", func() error {
		return reader.Check(ctx, GuardManifest{Namespace: ns, Revision: guard.Revision, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON})
	})
	if !environmentOK || !guardOK {
		emit("component_refused", counts)
		t.Fatal("component_refused")
	}
	// Extra commands/parser calls are diagnostic only; Observe is unchanged.
	protected := append(append([]netip.Prefix{}, entry.Engines[0].LocalPrefixes...), entry.Engines[0].RemotePrefixes...)
	var listing []byte
	versionOK := timed("extra_iptables_version", func() error {
		version, err := runKernelCommand(ctx, "/usr/sbin/iptables-nft-save", "-V")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "iptables-nft-save v") || !strings.HasSuffix(strings.TrimSpace(string(version)), " (nf_tables)") {
			return ErrKernelRead
		}
		return nil
	})
	listingOK := timed("extra_iptables_nat", func() error {
		var err error
		listing, err = runKernelCommand(ctx, "/usr/sbin/iptables-nft-save", "-t", "nat")
		return err
	})
	hookOK := timed("captured_hook_parser", func() error {
		if !runtimeHookCensus(firstNFT, protected) {
			return ErrKernelRead
		}
		return nil
	})
	dockerOK := timed("captured_docker_parser", func() error {
		if !runtimeDockerDNSCensus(firstNFT, listing, protected) {
			return ErrKernelRead
		}
		return nil
	})
	if !versionOK || !listingOK || firstNFT == nil || hookOK || !dockerOK || ctx.Err() != nil {
		emit("extra_census_refused", counts)
		t.Fatal("extra_census_refused")
	}
	afterD, de := daemon.Inspect(ctx)
	afterK, ke := kernel.Read(ctx)
	afterX, xe := xreader.Read(ctx)
	after, ast := read()
	nativeReaderOK := de == nil && ke == nil && xe == nil
	finalChecks = map[string]bool{
		"native_reader_ok":      nativeReaderOK,
		"strict_native_ok":      nativeReaderOK && strict(afterD, afterK, afterX),
		"kernel_snapshot_equal": nativeReaderOK && reflect.DeepEqual(connectionKernelSnapshot(entry, k), connectionKernelSnapshot(entry, afterK)),
		"xfrm_snapshot_equal":   nativeReaderOK && reflect.DeepEqual(connectionXFRMSnapshot(entry, x), connectionXFRMSnapshot(entry, afterX)),
		"journal_same_inode":    os.SameFile(st, ast),
		"journal_same_bytes":    bytes.Equal(raw, after),
		"context_active":        ctx.Err() == nil,
	}
	stable := true
	for _, passed := range finalChecks {
		stable = stable && passed
	}
	if !stable {
		emit("final_native_or_journal_refused", counts)
		t.Fatal("final_native_or_journal_refused")
	}
	emit("read_only_measurement_complete", counts)
}
