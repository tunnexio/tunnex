//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func azureVICIDialError(err error) string {
	if err == nil {
		return "none"
	}
	for _, item := range []struct {
		err  error
		name string
	}{{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"}, {syscall.EACCES, "access"}, {syscall.EPERM, "permission"}, {syscall.ECONNREFUSED, "connection_refused"}, {syscall.ENOENT, "missing"}, {syscall.EAGAIN, "would_block"}, {syscall.ETIMEDOUT, "timeout"}, {syscall.EINTR, "interrupted"}} {
		if errors.Is(err, item.err) {
			return item.name
		}
	}
	return "other"
}

// Read-only: same captured original daemon, one bounded connect, no VICI commands.
func TestAzureOwnedVICIDialDiagnosticNative(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_VICI_DIAGNOSTIC") != "1" {
		t.Skip("explicit owned read-only diagnostic only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	raw, _, err := remediationRead("/run/azure-cleanup15-v2-baseline.json")
	if err != nil {
		t.Fatal("baseline_read_refused")
	}
	var b azure15RemediationBaseline
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || b.CharonPID <= 1 || !validDigest(b.CharonExecutableSHA256) {
		t.Fatal("baseline_decode_refused")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != b.Namespace {
		t.Fatal("namespace_refused")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != b.BootID {
		t.Fatal("boot_refused")
	}
	process := func() bool {
		raw, e := os.ReadFile("/proc/" + strconv.Itoa(b.CharonPID) + "/stat")
		if e != nil {
			return false
		}
		at := strings.LastIndex(string(raw), ") ")
		if at < 0 {
			return false
		}
		fields := strings.Fields(string(raw)[at+2:])
		if len(fields) < 20 || fields[1] != "1" || fields[0] == "Z" || fields[0] == "T" || fields[0] == "t" {
			return false
		}
		ticks, e := strconv.ParseUint(fields[19], 10, 64)
		if e != nil || ticks != b.CharonStartTicks {
			return false
		}
		exe, e := os.ReadFile("/proc/" + strconv.Itoa(b.CharonPID) + "/exe")
		childNS, ne := os.Readlink("/proc/" + strconv.Itoa(b.CharonPID) + "/ns/net")
		pkg, ke := os.ReadFile(daemonExecutable)
		return e == nil && ne == nil && ke == nil && childNS == b.Namespace && bytes.Equal(exe, pkg) && remediationSHA(exe) == b.CharonExecutableSHA256
	}
	if !process() {
		t.Fatal("daemon_identity_refused")
	}
	path := "/run/tunnex-ipsec/charon.vici"
	parent := filepath.Dir(path)
	resolved, resolveErr := filepath.EvalSymlinks(parent)
	pi, pe := os.Lstat(parent)
	si, se := os.Lstat(path)
	parentCensus := pe == nil && pi.IsDir() && pi.Mode()&os.ModeSymlink == 0 && pi.Mode().Perm()&0077 == 0 && ownedByCurrentUser(pi)
	socketCensus := se == nil && si.Mode()&os.ModeSocket != 0 && si.Mode()&os.ModeSymlink == 0 && si.Mode().Perm()&0077 == 0 && ownedByCurrentUser(si)
	socketBound := false
	if se == nil {
		st := si.Sys().(*syscall.Stat_t)
		socketBound = uint64(st.Dev) == b.SocketDevice && st.Ino == b.SocketInode
	}
	result := map[string]any{"resolved_parent_equal": resolveErr == nil && resolved == parent, "parent_census": parentCensus, "socket_census": socketCensus, "socket_bound": socketBound, "euid_root": os.Geteuid() == 0}
	if !socketBound {
		t.Fatal("socket_identity_refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	// Raw dial is diagnostic-only. Census results never authorize a command.
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	result["connect_category"] = azureVICIDialError(e)
	result["elapsed_ms"] = time.Since(start).Milliseconds()
	result["context_category"] = azureVICIDialError(ctx.Err())
	peerBound := false
	if e == nil {
		uc, ok := conn.(*net.UnixConn)
		if ok {
			fd, fe := uc.SyscallConn()
			var cred *unix.Ucred
			var ce error
			if fe == nil && fd.Control(func(v uintptr) { cred, ce = unix.GetsockoptUcred(int(v), unix.SOL_SOCKET, unix.SO_PEERCRED) }) == nil && ce == nil && cred != nil {
				peerBound = int(cred.Pid) == b.CharonPID && cred.Uid == 0
			}
		}
		conn.Close()
	}
	strictCtx, strictCancel := context.WithTimeout(context.Background(), time.Second)
	strictStart := time.Now()
	strictConn, strictErr := dialOwnedVICI(strictCtx, path)
	strictCategory := azureVICIDialError(strictErr)
	if errors.Is(strictErr, ErrDaemonProtocol) {
		strictCategory = "protocol_refused"
	}
	result["strict_connect_category"] = strictCategory
	result["strict_elapsed_ms"] = time.Since(strictStart).Milliseconds()
	result["strict_context_category"] = azureVICIDialError(strictCtx.Err())
	if strictConn != nil {
		strictConn.Close()
	}
	strictCancel()
	result["peer_bound"] = peerBound
	result["daemon_identity_after"] = process()
	safe, _ := json.Marshal(result)
	t.Log("AZURE_OWNED_VICI_DIAL_DIAGNOSTIC " + string(safe))
}

func TestAzureVICIDialErrorTaxonomy(t *testing.T) {
	for _, item := range []struct {
		err  error
		want string
	}{{nil, "none"}, {&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.EACCES}}, "access"}, {context.DeadlineExceeded, "deadline"}, {syscall.ECONNREFUSED, "connection_refused"}, {errors.New("private arbitrary text"), "other"}} {
		if got := azureVICIDialError(item.err); got != item.want {
			t.Fatalf("category %s wanted %s", got, item.want)
		}
	}
}
