//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type azure15RemediationBaseline struct {
	bgpRemediationBaseline
	NormalReadSHA256, NormalReadObservedAt string
	NormalReadDevice, NormalReadInode      uint64
}

func azure15NormalReadMatches(raw []byte, b azure15RemediationBaseline, now time.Time) bool {
	var read struct {
		ObservedAt string `json:"observed_at"`
		Connection struct {
			ID              string `json:"id"`
			DesiredRevision int64  `json:"desired_revision"`
			DesiredIntent   string `json:"desired_intent"`
			CleanupState    string `json:"cleanup_state"`
		} `json:"connection"`
	}
	if json.Unmarshal(raw, &read) != nil || read.Connection.ID != "9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99" || read.Connection.DesiredRevision != 15 || read.Connection.DesiredIntent != "disabled" || read.Connection.CleanupState != "pending" || read.ObservedAt != b.NormalReadObservedAt {
		return false
	}
	observed, err := time.Parse(time.RFC3339Nano, read.ObservedAt)
	return err == nil && !now.Before(observed) && now.Sub(observed) <= 60*time.Second
}

// One-shot explicitly owned lab remediation: normal disabled15 only. It preserves
// the frozen whole journal and calls only the reviewed negative daemon helper.
func TestAzureDisabled15CleanupRemediationNative(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_DISABLED15_CLEANUP_REMEDIATION") != "1" {
		t.Skip("explicit owned disabled cleanup remediation only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	raw, _, e := remediationRead("/run/azure-cleanup15-v2-baseline.json")
	if e != nil {
		t.Fatal(e)
	}
	var b azure15RemediationBaseline
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		t.Fatal("baseline refused")
	}
	if b.CPDesiredIntent != "disabled" || b.CPCleanupState != "pending" || b.CPDesiredRevision != 15 || b.DesiredRevision != 15 || !validDigest(b.NormalReadSHA256) {
		t.Fatal("exact Azure15 normal cleanup baseline refused")
	}
	verifyNormalRead := func() {
		raw, st, err := remediationRead("/run/azure-cleanup15-v2-normal-read.json")
		if err != nil || uint64(st.Dev) != b.NormalReadDevice || st.Ino != b.NormalReadInode || remediationSHA(raw) != b.NormalReadSHA256 {
			t.Fatal("normal API read evidence changed")
		}
		if !azure15NormalReadMatches(raw, b, time.Now()) {
			t.Fatal("normal API disabled15 evidence refused or stale")
		}
	}
	attestationOnly := os.Getenv("TUNNEX_AZURE_DISABLED15_ATTESTATION_ONLY") == "1"
	if !attestationOnly {
		verifyNormalRead()
	}
	verify := func() ([]byte, runtimeJournalPayload) {
		ns, e := os.Readlink("/proc/self/ns/net")
		if e != nil || ns != b.Namespace {
			t.Fatal("namespace changed")
		}
		boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if e != nil || strings.TrimSpace(string(boot)) != b.BootID {
			t.Fatal("boot changed")
		}
		stat, e := os.ReadFile("/proc/1/stat")
		if e != nil {
			t.Fatal(e)
		}
		tail := strings.LastIndex(string(stat), ") ")
		if tail < 0 {
			t.Fatal("node identity refused")
		}
		fields := strings.Fields(string(stat)[tail+2:])
		if len(fields) < 20 || fields[0] != "T" {
			t.Fatal("node must be genuinely SIGSTOP paused")
		}
		ticks, e := strconv.ParseUint(fields[19], 10, 64)
		if e != nil || ticks != b.NodeStartTicks {
			t.Fatal("node start identity changed")
		}
		exe, e := os.ReadFile("/proc/1/exe")
		if e != nil || remediationSHA(exe) != b.NodeExecutableSHA256 {
			t.Fatal("node executable changed")
		}
		path := "/var/lib/tunnex-node/ipsec/journal.json"
		parent, e := filepath.EvalSymlinks(filepath.Dir(path))
		if e != nil || parent != filepath.Dir(path) {
			t.Fatal("journal path refused")
		}
		journal, st, e := remediationRead(path)
		if e != nil || uint64(st.Dev) != b.JournalDevice || st.Ino != b.JournalInode || remediationSHA(journal) != b.JournalSHA256 {
			t.Fatal("frozen journal identity changed")
		}
		org, node, e := ReadRuntimeJournalIdentity(filepath.Dir(path))
		if e != nil || org.String() != b.OrgID || node.String() != b.OwnerID {
			t.Fatal("strict journal identity refused")
		}
		var envelope runtimeJournalEnvelope
		if json.Unmarshal(journal, &envelope) != nil || !validJournalPayload(envelope.Payload) || journalChecksum(envelope.Payload) != envelope.Checksum {
			t.Fatal("strict journal payload refused")
		}
		return journal, envelope.Payload
	}
	verifyDaemon := func() {
		if b.CharonPID <= 1 {
			t.Fatal("managed charon PID refused")
		}
		raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", b.CharonPID))
		if e != nil {
			t.Fatal(e)
		}
		at := strings.LastIndex(string(raw), ") ")
		if at < 0 {
			t.Fatal("charon identity refused")
		}
		fields := strings.Fields(string(raw)[at+2:])
		if len(fields) < 20 || fields[1] != "1" || (fields[0] == "Z" || fields[0] == "T" || fields[0] == "t" || fields[0] == "X") {
			t.Fatal("managed node child identity refused")
		}
		ticks, e := strconv.ParseUint(fields[19], 10, 64)
		if e != nil || ticks != b.CharonStartTicks {
			t.Fatal("charon start identity changed")
		}
		ns, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", b.CharonPID))
		if e != nil || ns != b.Namespace {
			t.Fatal("charon namespace changed")
		}
		exe, e := os.ReadFile(fmt.Sprintf("/proc/%d/exe", b.CharonPID))
		if e != nil || remediationSHA(exe) != b.CharonExecutableSHA256 {
			t.Fatal("charon executable changed")
		}
		pkg, e := os.ReadFile(daemonExecutable)
		if e != nil || !bytes.Equal(exe, pkg) {
			t.Fatal("charon package differs")
		}
		conf, st, e := remediationRead("/run/tunnex-ipsec/strongswan.conf")
		if e != nil || uint64(st.Dev) != b.CharonConfigDevice || st.Ino != b.CharonConfigInode || remediationSHA(conf) != b.CharonConfigSHA256 {
			t.Fatal("managed daemon config changed")
		}
		socketInfo, e := os.Lstat("/run/tunnex-ipsec/charon.vici")
		if e != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0600 {
			t.Fatal("private daemon socket refused")
		}
		socketStat := socketInfo.Sys().(*syscall.Stat_t)
		if socketStat.Uid != 0 || uint64(socketStat.Dev) != b.SocketDevice || socketStat.Ino != b.SocketInode {
			t.Fatal("daemon socket identity changed")
		}
		parentInfo, e := os.Lstat("/run/tunnex-ipsec")
		if e != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0077 != 0 || parentInfo.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatal("daemon_socket_parent_census_refused")
		}
		socketCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		started := time.Now()
		conn, e := dialOwnedVICI(socketCtx, "/run/tunnex-ipsec/charon.vici")
		category := azureVICIDialError(e)
		if errors.Is(e, ErrDaemonProtocol) {
			category = "protocol_refused"
		}
		t.Logf("AZURE15_FIRST_ATTESTATION_DIAL category=%s context=%s elapsed_ms=%d euid_root=%t", category, azureVICIDialError(socketCtx.Err()), time.Since(started).Milliseconds(), os.Geteuid() == 0)
		if e != nil {
			t.Fatal("daemon_socket_connect_refused")
		}
		defer conn.Close()
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			t.Fatal("unix daemon socket required")
		}
		fd, e := uc.SyscallConn()
		if e != nil {
			t.Fatal(e)
		}
		var cred *unix.Ucred
		var ce error
		if fd.Control(func(v uintptr) { cred, ce = unix.GetsockoptUcred(int(v), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || ce != nil || cred == nil || int(cred.Pid) != b.CharonPID || cred.Uid != 0 {
			t.Fatal("socket peer must be exact managed charon")
		}
	}
	verifyDaemon()
	if attestationOnly {
		t.Log("AZURE15_READ_ONLY_ATTESTATION_COMPLETE no VICI command or native mutation")
		return
	}
	journal, payload := verify()
	if len(payload.Guards) != 1 {
		t.Fatal("exact one full guard required")
	}
	current := []RuntimeJournalEntry{}
	for _, candidate := range payload.Entries {
		if candidate.Phase != RuntimeRetainedRefusal {
			current = append(current, candidate)
		}
	}
	if len(current) != 1 {
		t.Fatal("exact one current Azure cleanup entry required")
	}
	entry := current[0]
	if entry.DeliveryID.String() != b.DeliveryID || entry.CleanupID.String() != b.CleanupID || entry.CleanupDesiredRevision != 15 || entry.CoveredDeliveryRevision != 14 || entry.Engines[0].Binding.DesiredRevision != 14 || entry.Allocation.ConnectionID.String() != "9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99" || entry.Phase != RuntimeCleanupPending || entry.ContractVersion != 3 || entry.Allocation.ProfileID != AzureActiveActiveBGPProfile || entry.Allocation.activeTunnelCount() != 2 || entry.Allocation.Namespace != b.Namespace || entry.BGPProcess != nil || entry.BGPRoutes != nil || len(entry.BGPProcessRetired) != 0 || entry.BGPProcessHistory != nil {
		t.Fatal("exact Azure15 current cleanup duty refused")
	}
	verifyKernel := func() {
		reader, e := NewKernelReader("/sbin/ip")
		if e != nil {
			t.Fatal(e)
		}
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		inventory, e := reader.Read(ctx)
		if e != nil || inventory.Namespace != b.Namespace {
			t.Fatal("actual kernel census refused")
		}
		for _, route := range inventory.Routes {
			for _, engine := range entry.Engines {
				for _, prefix := range engine.RemotePrefixes {
					if route.Destination == prefix {
						t.Fatal("learned payload route still present")
					}
				}
			}
			for i, tunnel := range entry.Allocation.Tunnels {
				if route.Protocol == 242 && route.OutputInterface == entry.Observed[i].InterfaceIndex && route.Destination != netip.PrefixFrom(tunnel.BGP.Peer, 32) {
					t.Fatal("unexpected owned-interface payload route")
				}
			}
		}
	}
	verifyKernel()
	guard := payload.Guards[0]
	if guard.Namespace != b.Namespace || remediationSHA([]byte(guard.ExpectedJSON)) != b.GuardExpectedSHA256 {
		t.Fatal("guard baseline changed")
	}
	var nft struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(guard.ExpectedJSON), &nft) != nil {
		t.Fatal("guard decode refused")
	}
	for _, v := range nft.NFTables {
		if _, ok := v["element"]; ok {
			t.Fatal("live permit elements refused")
		}
		if raw, ok := v["set"]; ok {
			var s struct {
				Elem []json.RawMessage `json:"elem"`
			}
			if json.Unmarshal(raw, &s) != nil || len(s.Elem) != 0 {
				t.Fatal("live permit set refused")
			}
		}
	}
	for _, engine := range entry.Engines {
		if !engine.BGP {
			t.Fatal("BGP only remediation")
		}
		for _, prefix := range engine.RemotePrefixes {
			for _, check := range [][2]string{{"forward_guard", "daddr"}, {"postrouting_guard", "daddr"}, {"forward_guard", "saddr"}, {"input_guard", "saddr"}} {
				if !remediationDrop([]byte(guard.ExpectedJSON), check[0], check[1], prefix) {
					t.Fatal("protected prefix denial absent")
				}
			}
		}
	}
	for _, tunnel := range entry.Allocation.Tunnels {
		if tunnel.BGP == nil {
			t.Fatal("BGP peer identity absent")
		}
		peer := netip.PrefixFrom(tunnel.BGP.Peer, 32)
		if !remediationDrop([]byte(guard.ExpectedJSON), "input_guard", "saddr", peer) || !remediationDrop([]byte(guard.ExpectedJSON), "output_guard", "daddr", peer) {
			t.Fatal("BGP peer denial absent")
		}
	}
	reader, e := NewGuardReader("/usr/sbin/nft")
	if e != nil {
		t.Fatal(e)
	}
	manifest := GuardManifest{Namespace: guard.Namespace, Revision: guard.Revision, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if reader.Check(ctx, manifest) != nil {
		t.Fatal("actual product NFT denial differs")
	}
	transport := viciTransport{dial: func(ctx context.Context) (net.Conn, error) {
		verifyDaemon()
		conn, err := dialOwnedVICI(ctx, "/run/tunnex-ipsec/charon.vici")
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, ErrDaemonProtocol
		}
		fd, err := uc.SyscallConn()
		var cred *unix.Ucred
		var ce error
		if err != nil || fd.Control(func(v uintptr) { cred, ce = unix.GetsockoptUcred(int(v), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || ce != nil || cred == nil || int(cred.Pid) != b.CharonPID || cred.Uid != 0 {
			conn.Close()
			return nil, ErrDaemonProtocol
		}
		verifyDaemon()
		return conn, nil
	}}
	client := &DaemonClient{request: func(ctx context.Context, command, event string, message viciMessage) (viciMessage, []viciMessage, error) {
		verifyDaemon()
		response, events, err := transport.call(ctx, command, event, message)
		verifyDaemon()
		return response, events, err
	}}
	for slot := range entry.Engines[:entry.Allocation.activeTunnelCount()] {
		verifyNormalRead()
		verifyDaemon()
		verifyKernel()
		before, _ := verify()
		if !bytes.Equal(before, journal) || reader.Check(ctx, manifest) != nil {
			t.Fatal("pre-removal frozen denial changed")
		}
		if client.removeAzureCleanupTunnel(ctx, entry, slot, b.Namespace) != nil {
			t.Fatal("actual production daemon cleanup refused")
		}
		verifyNormalRead()
		verifyDaemon()
		verifyKernel()
		after, _ := verify()
		if !bytes.Equal(after, journal) || reader.Check(ctx, manifest) != nil {
			t.Fatal("post-removal frozen denial changed")
		}
	}
	inventory, e := client.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, engine := range entry.Engines {
		if containsString(inventory.Connections, engineName(engine)) {
			t.Fatal("connection remains")
		}
		for _, sa := range inventory.SAs {
			if sa.Name == engineName(engine) {
				t.Fatal("SA remains")
			}
		}
	}
	t.Log("AZURE15_DISABLED_DAEMON_REMEDIATION_ONLY journal unchanged; no route, lease, grant, capability or journal mutation; normal controller must finish cleanup")
}

func TestAzure15NormalReadEvidenceFreshAndExact(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := azure15RemediationBaseline{NormalReadObservedAt: now.Format(time.RFC3339Nano)}
	raw := []byte(`{"observed_at":"2026-10-10T12:00:00Z","connection":{"id":"9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99","desired_revision":15,"desired_intent":"disabled","cleanup_state":"pending"}}`)
	if !azure15NormalReadMatches(raw, b, now) {
		t.Fatal("exact synthetic normal read refused")
	}
	for _, changed := range [][]byte{bytes.Replace(raw, []byte(`"disabled"`), []byte(`"enabled"`), 1), bytes.Replace(raw, []byte(`:15`), []byte(`:16`), 1), bytes.Replace(raw, []byte(`"pending"`), []byte(`"retained_guard"`), 1), bytes.Replace(raw, []byte(`9bfa4090`), []byte(`9bfa4091`), 1), append(append([]byte(nil), raw...), []byte(`{}`)...)} {
		if azure15NormalReadMatches(changed, b, now) {
			t.Fatal("changed normal read accepted")
		}
	}
	if azure15NormalReadMatches(raw, b, now.Add(61*time.Second)) || azure15NormalReadMatches(raw, b, now.Add(-time.Second)) {
		t.Fatal("stale or future read accepted")
	}
}
