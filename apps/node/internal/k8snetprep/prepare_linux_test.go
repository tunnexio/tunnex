//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeCharDeviceInfo struct{}

func (fakeCharDeviceInfo) Name() string       { return "tun" }
func (fakeCharDeviceInfo) Size() int64        { return 0 }
func (fakeCharDeviceInfo) Mode() os.FileMode  { return os.ModeCharDevice }
func (fakeCharDeviceInfo) ModTime() time.Time { return time.Time{} }
func (fakeCharDeviceInfo) IsDir() bool        { return false }
func (fakeCharDeviceInfo) Sys() any           { return nil }

func TestPrepareHostAppliesAndReadsBackClosedPosture(t *testing.T) {
	procSys := t.TempDir()
	for _, key := range []string{
		"net/ipv4/ip_forward",
		"net/ipv4/conf/all/rp_filter",
		"net/ipv4/conf/default/rp_filter",
	} {
		path := filepath.Join(procSys, filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("9"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	nftChecks := 0
	report := prepareHost(t.Context(), hostPrepareDeps{
		procSys: procSys,
		tunPath: "/dev/net/tun",
		stat: func(string) (os.FileInfo, error) {
			return fakeCharDeviceInfo{}, nil
		},
		lookPath: func(name string) (string, error) {
			if name != "nft" {
				t.Fatalf("unexpected binary %q", name)
			}
			return "/usr/sbin/nft", nil
		},
		runNFT: func(_ context.Context, binary string, args ...string) error {
			nftChecks++
			if binary != "/usr/sbin/nft" || len(args) != 2 || args[0] != "list" || args[1] != "tables" {
				t.Fatalf("unexpected nft check: %s %v", binary, args)
			}
			return nil
		},
	})
	if !report.Ready() || len(report.Checks) != 5 {
		t.Fatalf("host preparation report = %+v", report)
	}
	if nftChecks != 1 {
		t.Fatalf("nft checks=%d, want 1", nftChecks)
	}
	for key, want := range map[string]string{
		"net/ipv4/ip_forward":             "1",
		"net/ipv4/conf/all/rp_filter":     "0",
		"net/ipv4/conf/default/rp_filter": "0",
	} {
		got, err := os.ReadFile(filepath.Join(procSys, filepath.FromSlash(key)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s=%q, want %q", key, got, want)
		}
	}
}

func TestPrepareHostReturnsAllBoundedBlockedChecks(t *testing.T) {
	report := prepareHost(t.Context(), hostPrepareDeps{
		procSys: t.TempDir(),
		tunPath: "/missing/tun",
		stat: func(string) (os.FileInfo, error) {
			return nil, errors.New("tun unavailable")
		},
		lookPath: func(string) (string, error) {
			return "", errors.New("nft unavailable")
		},
		runNFT: func(context.Context, string, ...string) error { return nil },
	})
	if report.Status != StateBlocked || len(report.Checks) != 5 {
		t.Fatalf("blocked report = %+v", report)
	}
	for _, check := range report.Checks {
		if check.State != StateBlocked {
			t.Fatalf("check should be blocked: %+v", check)
		}
		if len(check.Reason) > maxReasonBytes {
			t.Fatalf("unbounded reason (%d bytes): %q", len(check.Reason), check.Reason)
		}
	}
}
