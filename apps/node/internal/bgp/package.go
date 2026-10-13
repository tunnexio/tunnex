// Package bgp provides bounded FRR observations. Package presence is not a
// runtime capability and cannot authorize routes, sessions or forwarding.
package bgp

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const Executable = "/opt/tunnex-bgp/bgpd"
const Version = "10.6.1"

var ErrPackage = errors.New("qualified BGP package unavailable")

// ProbePackage only reads metadata and runs --version; it never starts a daemon.
// Full daemon/session/kernel qualification is a separate prerequisite.
func ProbePackage(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return ErrPackage
	}
	for _, path := range []string{"/opt/tunnex-bgp/zebra", "/opt/tunnex-bgp/vtysh"} {
		if secureExecutable(path, runtime.GOARCH) != nil {
			return ErrPackage
		}
	}
	if secureExecutable("/opt/tunnex-bgp/lib/libfrr.so.0.0.0", runtime.GOARCH) != nil {
		return ErrPackage
	}
	target, err := os.Readlink("/opt/tunnex-bgp/lib/libfrr.so.0")
	if err != nil || target != "libfrr.so.0.0.0" {
		return ErrPackage
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	zebra, err := packageVersion(child, "/opt/tunnex-bgp/zebra")
	if err != nil || !strings.HasPrefix(zebra, "zebra version "+Version+"\n") || !strings.Contains(zebra, "--disable-bfdd") || !strings.Contains(zebra, "--libdir=/opt/tunnex-bgp/lib") {
		return ErrPackage
	}
	cmd := exec.CommandContext(child, "/opt/tunnex-bgp/vtysh", "--help")
	var help boundedOutput
	cmd.Stdout = &help
	cmd.Stderr = &help
	if cmd.Run() != nil || !strings.Contains(help.String(), "Integrated shell for FRR (version "+Version+").") {
		return ErrPackage
	}
	return probePackage(ctx, Executable, runtime.GOARCH, packageVersion)
}
func probePackage(ctx context.Context, path, arch string, version func(context.Context, string) (string, error)) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) {
		return ErrPackage
	}
	if secureExecutable(path, arch) != nil {
		return ErrPackage
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, e := version(child, path)
	line := strings.SplitN(output, "\n", 2)[0]
	if e != nil || !(line == "bgpd version "+Version || strings.HasPrefix(line, "bgpd version "+Version+" ")) {
		return ErrPackage
	}
	return nil
}

func secureExecutable(path, arch string) error {
	// Reject symlinks in any component, not just the executable itself.
	for p := path; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrPackage
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return ErrPackage
		}
		if p == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0) {
			return ErrPackage
		}
		if p == "/" {
			break
		}
	}
	f, e := elf.Open(path)
	if e != nil {
		return ErrPackage
	}
	machine := f.Machine
	class, data := f.Class, f.Data
	f.Close()
	if class != elf.ELFCLASS64 || data != elf.ELFDATA2LSB {
		return ErrPackage
	}
	if !(arch == "arm64" && machine == elf.EM_AARCH64 || arch == "amd64" && machine == elf.EM_X86_64) {
		return ErrPackage
	}
	return nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, ErrPackage
	}
	return b.Buffer.Write(p)
}
func packageVersion(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
