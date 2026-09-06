//go:build linux

package k8snetprep

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type hostPrepareDeps struct {
	procSys  string
	tunPath  string
	stat     func(string) (os.FileInfo, error)
	lookPath func(string) (string, error)
	runNFT   func(context.Context, string, ...string) error
}

func defaultHostPrepareDeps() hostPrepareDeps {
	return hostPrepareDeps{
		procSys:  "/proc/sys",
		tunPath:  "/dev/net/tun",
		stat:     os.Stat,
		lookPath: exec.LookPath,
		runNFT: func(ctx context.Context, binary string, args ...string) error {
			out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("nft check: %w: %s", err, bounded(string(out), maxReasonBytes))
			}
			return nil
		},
	}
}

// PrepareHost applies and reads back the closed common host posture. There are
// intentionally no caller-provided paths, sysctl keys, values, or commands.
func PrepareHost(ctx context.Context) HostPrepareReport {
	return prepareHost(ctx, defaultHostPrepareDeps())
}

func prepareHost(ctx context.Context, deps hostPrepareDeps) HostPrepareReport {
	report := HostPrepareReport{SchemaVersion: 1, Operation: "k8s_host_prepare", Status: StateReady}
	appendCheck := func(name string, err error) {
		check := ComponentStatus{Name: name, State: StateReady}
		if err != nil {
			check.State = StateBlocked
			check.Reason = bounded(err.Error(), maxReasonBytes)
			report.Status = StateBlocked
		}
		report.Checks = append(report.Checks, check)
	}

	info, err := deps.stat(deps.tunPath)
	if err == nil && info.Mode()&os.ModeCharDevice == 0 {
		err = fmt.Errorf("%s is not a character device", deps.tunPath)
	}
	appendCheck("tun_device", err)

	appendCheck("ipv4_forwarding", applyAndReadSysctl(deps.procSys, "net/ipv4/ip_forward", "1"))
	appendCheck("rp_filter_all", applyAndReadSysctl(deps.procSys, "net/ipv4/conf/all/rp_filter", "0"))
	appendCheck("rp_filter_default", applyAndReadSysctl(deps.procSys, "net/ipv4/conf/default/rp_filter", "0"))

	nft, err := deps.lookPath("nft")
	if err == nil {
		err = deps.runNFT(ctx, nft, "list", "tables")
	}
	appendCheck("nftables", err)
	return report
}

func applyAndReadSysctl(procSys, key, desired string) error {
	path := filepath.Join(procSys, filepath.FromSlash(key))
	writeErr := os.WriteFile(path, []byte(desired), 0o644)
	value, readErr := os.ReadFile(path)
	if readErr == nil && strings.TrimSpace(string(value)) == desired {
		return nil
	}
	if writeErr != nil {
		return fmt.Errorf("%s is not %s and could not be applied: %w", key, desired, writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("read back %s: %w", key, readErr)
	}
	return fmt.Errorf("%s readback mismatch", key)
}
