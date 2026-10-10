// Command ipsec-reset-cleanup-receipt assembles a cleanup-only receipt after
// genuine externally supervised VM reboot. It neither reboots nor edits a
// journal nor removes native objects. Runtime independently proves absence.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

func privateRead(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errors.New("unsafe input")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("foreign input")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path || !filepath.IsAbs(path) {
		return nil, errors.New("input path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("input changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("input size")
	}
	return raw, nil
}
func main() {
	journal := flag.String("journal", "", "private unchanged stopped journal snapshot")
	cleanup := flag.String("cleanup", "", "private current normal mTLS cleanup response")
	proof := flag.String("proof", "", "private genuine external supervisor reboot evidence")
	outputDir := flag.String("output-dir", "", "existing root-owned 0700 journal directory; writes receipt only")
	flag.Parse()
	fail := func() { fmt.Fprintln(os.Stderr, "reset cleanup receipt assembly refused"); os.Exit(1) }
	if os.Geteuid() != 0 || flag.NArg() != 0 {
		fail()
	}
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		fail()
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		fail()
	}
	machineRaw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		fail()
	}
	boot, machine := strings.TrimSpace(string(bootRaw)), strings.TrimSpace(string(machineRaw))
	paths := []string{*journal, *cleanup, *proof}
	limits := []int64{16 << 20, 16 << 20, 8192}
	inputs := make([][]byte, 3)
	for i, path := range paths {
		inputs[i], err = privateRead(path, limits[i])
		if err != nil {
			fail()
		}
	}
	raw, err := ipsec.AssembleResetCleanupReceipt(inputs[0], inputs[1], inputs[2], boot, ns, machine, time.Now().UTC())
	if err != nil {
		fail()
	}
	var delivery ipsec.RuntimeCleanup
	if json.Unmarshal(inputs[1], &delivery) != nil {
		fail()
	}
	dir, err := os.Lstat(*outputDir)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		fail()
	}
	stat, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		fail()
	}
	resolved, err := filepath.EvalSymlinks(*outputDir)
	if err != nil || resolved != *outputDir || !filepath.IsAbs(*outputDir) {
		fail()
	}
	for i, path := range paths {
		again, e := privateRead(path, limits[i])
		if e != nil || !bytes.Equal(inputs[i], again) {
			fail()
		}
	}
	bootAfter, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	nsAfter, ne := os.Readlink("/proc/self/ns/net")
	if e != nil || ne != nil || strings.TrimSpace(string(bootAfter)) != boot || nsAfter != ns {
		fail()
	}
	current, e := os.Lstat(*outputDir)
	if e != nil || !os.SameFile(dir, current) {
		fail()
	}
	path := filepath.Join(*outputDir, "reset-cleanup-"+delivery.ID.String()+".json")
	fd, e := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		fail()
	}
	f := os.NewFile(uintptr(fd), path)
	_, e = f.Write(append(raw, '\n'))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		fail()
	}
	directory, e := os.Open(*outputDir)
	if e != nil {
		fail()
	}
	e = directory.Sync()
	ce = directory.Close()
	if e != nil || ce != nil {
		fail()
	}
	fmt.Println("reset cleanup receipt assembled; no native cleanup or journal mutation performed")
}
