package ipsec

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func viciEAGAINFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ve-")
	if err != nil {
		t.Fatal("temp")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal("canonical_temp")
	}
	p := filepath.Join(canonical, "vici")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	if os.Chmod(p, 0600) != nil {
		t.Fatal("mode")
	}
	return p
}
func TestOwnedVICIEAGAINConnectOnly(t *testing.T) {
	path := viciEAGAINFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	calls, waits := 0, 0
	dial := func(c context.Context, network, p string) (net.Conn, error) {
		calls++
		if p != path || network != "unix" || c != ctx {
			t.Fatal("scope")
		}
		if calls == 1 {
			return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.EAGAIN}
		}
		return a, nil
	}
	got, e := dialOwnedVICIWith(ctx, path, dial, func(context.Context) error { waits++; return nil })
	if e != nil || got != a || calls != 2 || waits != 1 {
		t.Fatal("retry_contract")
	}
	got.Close()
}
func TestOwnedVICINonEAGAINNeverRetries(t *testing.T) {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNREFUSED, syscall.ENOENT, syscall.EACCES, errors.New("unknown")} {
		path := viciEAGAINFixture(t)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		calls := 0
		_, err := dialOwnedVICIWith(ctx, path, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, e }, func(context.Context) error { t.Fatal("unexpected_wait"); return nil })
		cancel()
		if err != ErrDaemonProtocol || calls != 1 {
			t.Fatal("unexpected_retry")
		}
	}
}
func TestOwnedVICIEAGAINCancellationAndUnbounded(t *testing.T) {
	path := viciEAGAINFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	calls := 0
	_, e := dialOwnedVICIWith(ctx, path, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, syscall.EAGAIN }, func(c context.Context) error { <-c.Done(); return c.Err() })
	if e != ErrDaemonProtocol || calls != 1 || ctx.Err() != context.DeadlineExceeded {
		t.Fatal("deadline_extended")
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	cancel2()
	_, e = dialOwnedVICIWith(ctx2, path, func(context.Context, string, string) (net.Conn, error) { t.Fatal("canceled_dial"); return nil, nil }, waitOwnedVICI)
	if e != ErrDaemonProtocol {
		t.Fatal("canceled_accepted")
	}
	calls = 0
	_, e = dialOwnedVICIWith(context.Background(), path, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, syscall.EAGAIN }, func(context.Context) error { t.Fatal("unbounded_wait"); return nil })
	if e != ErrDaemonProtocol || calls != 1 {
		t.Fatal("unbounded_retry")
	}
}
func TestOwnedVICIEAGAINReplacementAndMetadata(t *testing.T) {
	for _, replace := range []bool{false, true} {
		path := viciEAGAINFixture(t)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		calls := 0
		_, e := dialOwnedVICIWith(ctx, path, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, syscall.EAGAIN }, func(context.Context) error {
			if replace {
				if os.Rename(path, path+"-old") != nil {
					t.Fatal("rename")
				}
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal("replace")
				}
				t.Cleanup(func() { l.Close() })
				os.Chmod(path, 0600)
			} else {
				os.Chmod(path, 0640)
			}
			return nil
		})
		cancel()
		if e != ErrDaemonProtocol || calls != 1 {
			t.Fatal("replacement_retry")
		}
	}
}
func TestOwnedVICIConnectPostcheckCloses(t *testing.T) {
	path := viciEAGAINFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	_, e := dialOwnedVICIWith(ctx, path, func(context.Context, string, string) (net.Conn, error) { os.Chmod(path, 0640); return a, nil }, waitOwnedVICI)
	if e != ErrDaemonProtocol {
		t.Fatal("changed_accepted")
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	_, e = b.Read(make([]byte, 1))
	if e == nil {
		t.Fatal("not_closed")
	}
}
