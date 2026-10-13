//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func legacyDialOwnedVICI(ctx context.Context, path string) (net.Conn, error) {
	if ctx == nil || !filepath.IsAbs(path) {
		return nil, ErrDaemonProtocol
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, ErrDaemonProtocol
	}
	for _, entry := range []struct {
		path   string
		socket bool
	}{{parent, false}, {path, true}} {
		info, err := os.Lstat(entry.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return nil, ErrDaemonProtocol
		}
		if !ownedByCurrentUser(info) {
			return nil, ErrDaemonProtocol
		}
		if entry.socket {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, ErrDaemonProtocol
			}
		} else if !info.IsDir() {
			return nil, ErrDaemonProtocol
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrDaemonProtocol
	}
	return conn, nil
}

// Actual Linux AF_UNIX backlog saturation: legacy refuses EAGAIN; candidate waits without any command.
func TestOwnedVICIRealLinuxBacklogREDGREEN(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_VICI_BACKLOG_NATIVE") != "1" {
		t.Skip("explicit_isolated_native_only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root_required")
	}
	root := os.Getenv("TUNNEX_TEST_VICI_BACKLOG_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("fixture_root")
	}
	for dir := root; ; dir = filepath.Dir(dir) {
		info, e := os.Lstat(dir)
		if e != nil {
			t.Fatal("fixture_parent")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if e != nil || !ok || st.Uid != 0 || st.Gid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) || info.Mode().Perm()&0022 != 0 {
			t.Fatal("fixture_parent")
		}
		if dir == root && info.Mode().Perm() != 0700 {
			t.Fatal("fixture_mode")
		}
		if dir == "/" {
			break
		}
	}
	fixture := filepath.Join(root, "fixture")
	if os.Mkdir(fixture, 0700) != nil {
		t.Fatal("exclusive_fixture")
	}
	// Keep the exact fixture inode after success/failure; only known open descriptors are closed.
	path := filepath.Join(fixture, "vici")
	if len(path) > 100 {
		t.Fatal("unix_path_bound")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal("socket")
	}
	defer unix.Close(fd)
	if unix.Bind(fd, &unix.SockaddrUnix{Name: path}) != nil || unix.Listen(fd, 1) != nil || os.Chmod(path, 0600) != nil {
		t.Fatal("listener")
	}
	var queued []net.Conn
	defer func() {
		for _, c := range queued {
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	saturated := false
	for i := 0; i < 32; i++ {
		c, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if errors.Is(e, syscall.EAGAIN) {
			saturated = true
			break
		}
		if e != nil {
			t.Fatal("unexpected_connect")
		}
		queued = append(queued, c)
	}
	if !saturated {
		t.Fatal("backlog_not_saturated")
	}
	legacyRefused := false
	if c, e := legacyDialOwnedVICI(ctx, path); e == nil {
		c.Close()
		t.Fatal("legacy_did_not_refuse")
	} else {
		legacyRefused = true
	}
	calls := 0
	firstAgain := make(chan struct{}, 1)
	drained := make(chan error, 1)
	go func() {
		select {
		case <-firstAgain:
		case <-ctx.Done():
			drained <- ctx.Err()
			return
		}
		timer := time.NewTimer(30 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			drained <- ctx.Err()
			return
		}
		accepted, _, e := unix.Accept(fd)
		if e == nil {
			unix.Close(accepted)
		}
		drained <- e
	}()
	dial := func(c context.Context, n, p string) (net.Conn, error) {
		calls++
		conn, e := (&net.Dialer{}).DialContext(c, n, p)
		if errors.Is(e, syscall.EAGAIN) {
			select {
			case firstAgain <- struct{}{}:
			default:
			}
		}
		return conn, e
	}
	// Exercise the actual production cancelable 10ms wait, not an accept callback replacing it.
	got, e := dialOwnedVICIWith(ctx, path, dial, waitOwnedVICI)
	if e != nil || got == nil || calls < 2 {
		t.Fatal("candidate_not_connected")
	}
	got.Close()
	select {
	case e := <-drained:
		if e != nil {
			t.Fatal("drain")
		}
	case <-ctx.Done():
		t.Fatal("drain_deadline")
	}
	raw, _ := json.Marshal(struct {
		Kind                                                          string
		LegacyRefused, CandidateConnected, RealEAGAIN, ProductionWait bool
		ConnectAttempts, CommandsWritten                              int
	}{"isolated_unix_backlog_red_green", legacyRefused, true, saturated, true, calls, 0})
	fmt.Println("VICI_BACKLOG_RED_GREEN " + string(raw))
}
