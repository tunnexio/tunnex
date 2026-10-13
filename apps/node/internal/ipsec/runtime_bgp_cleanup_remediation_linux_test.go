//go:build linux

package ipsec

// This opt-in, one-shot lab remediation never changes journal, routes, leases,
// capability or policy. It only calls the production daemon cleanup method.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type bgpRemediationBaseline struct {
	CharonPID                                                        int
	CharonStartTicks                                                 uint64
	CharonExecutableSHA256, CharonConfigSHA256                       string
	CharonConfigDevice, CharonConfigInode, SocketDevice, SocketInode uint64
	JournalSHA256                                                    string
	JournalDevice, JournalInode                                      uint64
	Namespace, BootID, NodeExecutableSHA256                          string
	NodeStartTicks                                                   uint64
	OwnerID, OrgID, DeliveryID, CleanupID                            string
	DesiredRevision                                                  int64
	GuardExpectedSHA256                                              string
	CPDesiredIntent, CPCleanupState                                  string
	CPDesiredRevision                                                int64
}

func remediationRead(path string) ([]byte, syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, st, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if e = syscall.Fstat(fd, &st); e != nil || st.Uid != 0 || st.Mode&0777 != 0600 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > 2<<20 {
		return nil, st, fmt.Errorf("private file refused")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", fd))
	return b, st, e
}
func remediationSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func remediationDrop(raw []byte, chain, field string, prefix netip.Prefix) bool {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, v := range doc.NFTables {
		var r struct {
			Chain string                       `json:"chain"`
			Expr  []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(v["rule"], &r) != nil || r.Chain != chain || len(r.Expr) != 3 {
			continue
		}
		if _, ok := r.Expr[1]["counter"]; !ok {
			continue
		}
		if _, ok := r.Expr[2]["drop"]; !ok {
			continue
		}
		var match struct {
			Op   string `json:"op"`
			Left struct {
				Payload struct{ Protocol, Field string } `json:"payload"`
			}
			Right struct {
				Prefix struct {
					Addr string
					Len  int
				} `json:"prefix"`
			}
		}
		if json.Unmarshal(r.Expr[0]["match"], &match) == nil && match.Op == "==" && match.Left.Payload.Protocol == "ip" && match.Left.Payload.Field == field && match.Right.Prefix.Addr == prefix.Addr().String() && match.Right.Prefix.Len == prefix.Bits() {
			return true
		}
	}
	return false
}
func TestBGPDisabledCleanupRemediationNative(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_DISABLED_CLEANUP_REMEDIATION") != "1" {
		t.Skip("explicit owned disabled cleanup remediation only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	raw, _, e := remediationRead("/run/bgp-cleanup-remediation-v3-baseline.json")
	if e != nil {
		t.Fatal(e)
	}
	var b bgpRemediationBaseline
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		t.Fatal("baseline refused")
	}
	if b.CPDesiredIntent != "disabled" || b.CPCleanupState != "pending" || b.CPDesiredRevision != 3 || b.DesiredRevision != 3 || b.DeliveryID != "65171908-b2af-40fe-9203-a02d2281f4c3" || b.CleanupID != "eb6a2fa3-c0a7-41a3-ab5f-6ecf050a195f" {
		t.Fatal("normal CP cleanup baseline refused")
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
		path := "/state/ipsec/journal.json"
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
		if len(fields) < 20 || fields[1] != "1" || fields[0] == "Z" {
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
		socketCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		conn, e := dialOwnedVICI(socketCtx, "/run/tunnex-ipsec/charon.vici")
		if e != nil {
			t.Fatal(e)
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
	journal, payload := verify()
	if len(payload.Entries) != 1 || len(payload.Guards) != 1 {
		t.Fatal("exclusive fixture journal required")
	}
	entry := payload.Entries[0]
	if entry.DeliveryID.String() != b.DeliveryID || entry.CleanupID.String() != b.CleanupID || entry.CleanupDesiredRevision != b.DesiredRevision || entry.Phase != RuntimeCleanupPending || entry.ContractVersion != 3 || entry.Allocation.Namespace != b.Namespace || entry.BGPProcess == nil || entry.BGPProcess.Stage != "cleaned" || entry.BGPRoutes == nil || entry.BGPRoutes.Stage != "completed" || !entry.BGPRoutes.Withdrawal || len(entry.BGPRoutes.Owned) != 0 || len(entry.BGPRoutes.Target) != 0 {
		t.Fatal("retained BGP cleanup duty refused")
	}
	for _, p := range append(entry.BGPProcessRetired, *entry.BGPProcess) {
		if p.Stage != "cleaned" {
			t.Fatal("uncertain process duty refused")
		}
		info, e := os.Lstat(p.Directory)
		if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("private process directory refused")
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != 0 || uint64(st.Dev) != p.DirectoryFile.Device || st.Ino != p.DirectoryFile.Inode {
			t.Fatal("process directory identity changed")
		}
		items, e := os.ReadDir(p.Directory)
		if e != nil || len(items) != 0 {
			t.Fatal("process residue refused")
		}
		for _, c := range p.Children {
			v, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.PID))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			at := strings.LastIndex(string(v), ") ")
			if at < 0 {
				t.Fatal("child identity refused")
			}
			f := strings.Fields(string(v)[at+2:])
			if len(f) < 20 {
				t.Fatal("child identity refused")
			}
			tick, e := strconv.ParseUint(f[19], 10, 64)
			if e != nil || tick == c.StartTicks {
				t.Fatal("old child must be absent")
			}
		}
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
	client, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		t.Fatal(e)
	}
	for _, engine := range entry.Engines {
		verifyDaemon()
		verifyKernel()
		before, _ := verify()
		if !bytes.Equal(before, journal) || reader.Check(ctx, manifest) != nil {
			t.Fatal("pre-removal frozen denial changed")
		}
		if client.removeTunnel(ctx, engine) != nil {
			t.Fatal("actual production daemon cleanup refused")
		}
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
	t.Log("DISABLED_DAEMON_REMEDIATION_ONLY journal unchanged; no route, lease, grant, capability or journal mutation; normal controller must finish cleanup")
}

// The product protects remote payload destinations/sources; ordinary local LAN
// traffic is intentionally not subject to a blanket local-prefix DROP.
func TestRemediationDropValidatorMatchesRenderedGuard(t *testing.T) {
	intent := guardFixture()
	intent.Connections[0].PermitFor = 0
	intent.Connections[0].Grants = nil
	manifest, e := RenderGuard(intent)
	if e != nil {
		t.Fatal(e)
	}
	remote := intent.Connections[0].Remote[0]
	for _, check := range [][2]string{{"forward_guard", "daddr"}, {"postrouting_guard", "daddr"}, {"forward_guard", "saddr"}, {"input_guard", "saddr"}} {
		if !remediationDrop([]byte(manifest.ExpectedJSON), check[0], check[1], remote) {
			t.Fatal("actual product remote denial missed")
		}
	}
	if remediationDrop([]byte(manifest.ExpectedJSON), "forward_guard", "daddr", intent.Connections[0].Local[0]) {
		t.Fatal("local LAN blanket denial fabricated")
	}
	if remediationDrop([]byte(manifest.ExpectedJSON), "forward_guard", "daddr", netip.MustParsePrefix("10.21.0.0/24")) {
		t.Fatal("foreign prefix accepted")
	}
	bad := strings.ReplaceAll(manifest.ExpectedJSON, `"drop":null`, `"accept":null`)
	if remediationDrop([]byte(bad), "forward_guard", "daddr", remote) {
		t.Fatal("accept misread as denial")
	}
}
