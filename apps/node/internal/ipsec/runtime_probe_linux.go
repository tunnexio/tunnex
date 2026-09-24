//go:build linux

package ipsec

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func readRuntimeClock() (runtimeClock, error) {
	var boot, mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return runtimeClock{}, ErrRuntimeProbe
	}
	return runtimeClock{Boot: time.Duration(boot.Nano()), Monotonic: time.Duration(mono.Nano())}, nil
}
func runtimeProbePrivilege(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrRuntimeProbe
	}
	raw, e := os.ReadFile("/proc/self/status")
	if e != nil || len(raw) > 65536 {
		return ErrRuntimeProbe
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			mask, e := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			if e == nil && mask&(1<<unix.CAP_NET_ADMIN) != 0 {
				return nil
			}
		}
	}
	return ErrRuntimeProbe
}

func runtimeProbePackage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrRuntimeProbe
	}
	// This verifies the installed supported profile and bundled corresponding
	// source. It does not claim a reproducible ELF hash from a source archive.
	paths := []string{"/opt/tunnex-ipsec/libexec/ipsec/charon"}
	for _, plugin := range []string{"vici", "kernel-netlink", "socket-default", "openssl", "nonce", "random", "kdf"} {
		paths = append(paths, "/opt/tunnex-ipsec/lib/ipsec/plugins/libstrongswan-"+plugin+".so")
	}
	for _, path := range paths {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ownedByCurrentUser(info) {
			return ErrRuntimeProbe
		}
		f, e := elf.Open(path)
		if e != nil {
			return ErrRuntimeProbe
		}
		machine := f.Machine
		f.Close()
		if !(runtime.GOARCH == "arm64" && machine == elf.EM_AARCH64 || runtime.GOARCH == "amd64" && machine == elf.EM_X86_64) {
			return ErrRuntimeProbe
		}
	}
	path := "/usr/share/tunnex-ipsec/source/strongswan-6.1.0.tar.gz"
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ownedByCurrentUser(info) || info.Size() <= 0 || info.Size() > 32<<20 {
		return ErrRuntimeProbe
	}
	f, e := os.Open(path)
	if e != nil {
		return ErrRuntimeProbe
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return ErrRuntimeProbe
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, (32<<20)+1))
	if e != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != "d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963" || ctx.Err() != nil {
		return ErrRuntimeProbe
	}
	return nil
}
