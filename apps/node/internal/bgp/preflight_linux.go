//go:build linux

package bgp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func (q *PreflightQualification) Current() bool {
	if q == nil || !q.qualified {
		return false
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != q.bootID {
		return false
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != q.namespace {
		return false
	}
	files, err := preflightPackageIdentity()
	return err == nil && reflect.DeepEqual(files, q.packageFiles)
}
func preflightPackageIdentity() ([]preflightPackageFile, error) {
	files := []preflightPackageFile{}
	for _, path := range []string{Executable, "/opt/tunnex-bgp/zebra", "/opt/tunnex-bgp/vtysh", "/opt/tunnex-bgp/lib/libfrr.so.0.0.0"} {
		if secureExecutable(path, runtime.GOARCH) != nil {
			return nil, ErrPackage
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrPackage
		}
		id, err := fileIdentity(info)
		if err != nil {
			return nil, err
		}
		files = append(files, preflightPackageFile{Path: path, Identity: id, Size: info.Size(), Modified: info.ModTime().UnixNano()})
	}
	target, err := os.Readlink("/opt/tunnex-bgp/lib/libfrr.so.0")
	if err != nil || target != "libfrr.so.0.0.0" {
		return nil, ErrPackage
	}
	return files, nil
}

// QualifyPreflight starts only observer daemons with all TCP listeners disabled.
// No result survives a route change, failed readback or incomplete owned cleanup.
func QualifyPreflight(ctx context.Context, parentDir string) (result *PreflightQualification, resultErr error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || !filepath.IsAbs(parentDir) || filepath.Clean(parentDir) != parentDir || !privateAncestors(parentDir) {
		return nil, preflightRefused("input", fmt.Errorf("%w: input", ErrPackage))
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ProbePackage(bounded) != nil {
		return nil, preflightRefused("package", fmt.Errorf("%w: package", ErrPackage))
	}
	packageFiles, err := preflightPackageIdentity()
	if err != nil {
		return nil, preflightRefused("package-identity", fmt.Errorf("%w: package-identity", ErrPackage))
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, preflightRefused("identity", fmt.Errorf("%w: identity", ErrPackage))
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, preflightRefused("identity", fmt.Errorf("%w: identity", ErrPackage))
	}
	before, err := preflightRoutes(bounded)
	if err != nil {
		return nil, preflightRefused("routes-before", fmt.Errorf("%w: routes-before", ErrPackage))
	}
	dir, err := os.MkdirTemp(parentDir, "bgp-preflight-")
	if err != nil {
		return nil, preflightRefused("private-directory", fmt.Errorf("%w: private-directory", ErrPackage))
	}
	process, err := StartObserver(bounded, dir)
	if err != nil {
		return nil, preflightRefused("observer-start", fmt.Errorf("%w: observer-start: %v", ErrPackage, err))
	} // Failed owned startup retains any refusal residue.
	defer func() {
		if process.Close() != nil {
			result = nil
			resultErr = preflightRefused("observer-close", fmt.Errorf("%w: observer-close", ErrPackage))
			return
		}
		after, err := preflightRoutes(bounded)
		if err != nil || !bytes.Equal(before, after) {
			result = nil
			resultErr = preflightRefused("routes-after-close", fmt.Errorf("%w: routes-after-close", ErrPackage))
			return
		}
		if os.Remove(dir) != nil {
			result = nil
			resultErr = preflightRefused("private-directory-remove", fmt.Errorf("%w: private-directory-remove", ErrPackage))
			return
		}
		parent, err := os.Open(parentDir)
		if err != nil {
			result = nil
			resultErr = preflightRefused("private-parent-open", fmt.Errorf("%w: private-parent-open", ErrPackage))
			return
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil || closeErr != nil {
			result = nil
			resultErr = preflightRefused("private-parent-sync", fmt.Errorf("%w: private-parent-sync", ErrPackage))
			return
		}
		if result == nil {
			if resultErr == nil {
				resultErr = preflightRefused("missing-receipt", fmt.Errorf("%w: missing-receipt", ErrPackage))
			}
			return
		}
		if !result.Current() {
			result = nil
			resultErr = preflightRefused("receipt-current", fmt.Errorf("%w: receipt-current", ErrPackage))
		}
	}()
	if !process.Alive() {
		return nil, preflightRefused("observer-alive", fmt.Errorf("%w: observer-alive", ErrPackage))
	}
	identity, err := process.Identity()
	if err != nil || len(identity.Children) != 2 || identity.Namespace != ns || identity.BootID != strings.TrimSpace(string(boot)) {
		return nil, preflightRefused("children-identity", fmt.Errorf("%w: children-identity", ErrPackage))
	}
	if preflightNoListeners(identity.Children) != nil {
		return nil, preflightRefused("children-listeners", fmt.Errorf("%w: children-listeners", ErrPackage))
	}
	rib, err := process.PreflightRIB(bounded)
	if err != nil || !preflightEmptyRIB(rib) {
		text := string(rib)
		if len(text) > 256 {
			text = text[:256]
		}
		return nil, preflightRefused("observer-rib", fmt.Errorf("%w: observer-rib read=%v output=%q", ErrPackage, err, text))
	}
	if !process.Alive() || preflightNoListeners(identity.Children) != nil {
		return nil, preflightRefused("observer-listeners-recheck", fmt.Errorf("%w: observer-listeners-recheck", ErrPackage))
	}
	after, err := preflightRoutes(bounded)
	if err != nil || !bytes.Equal(before, after) {
		return nil, preflightRefused("routes-observed", fmt.Errorf("%w: routes-observed", ErrPackage))
	}
	return &PreflightQualification{namespace: ns, bootID: strings.TrimSpace(string(boot)), packageFiles: packageFiles, qualified: true}, nil
}
func preflightRoutes(ctx context.Context) ([]byte, error) {
	out := []byte{}
	for _, family := range []string{"-4", "-6"} {
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		cmd := exec.CommandContext(child, "/sbin/ip", "-j", "-d", "-N", family, "route", "show", "table", "all")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		var output boundedRIBResponse
		var stderr boundedOutput
		cmd.Stdout = &output
		cmd.Stderr = &stderr
		err := cmd.Run()
		cancel()
		if err != nil {
			return nil, ErrPackage
		}
		var routes []map[string]json.RawMessage
		if json.Unmarshal(output.Bytes(), &routes) != nil || routes == nil {
			return nil, ErrPackage
		}
		canonical, err := json.Marshal(routes)
		if err != nil {
			return nil, ErrPackage
		}
		out = append(out, canonical...)
		out = append(out, '\n')
	}
	return out, nil
}
func preflightEmptyRIB(raw []byte) bool {
	if len(raw) > 65536 {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return false
	}
	if len(doc) == 0 {
		return true
	}
	if _, exists := doc["error"]; exists {
		return false
	}
	if _, exists := doc["warning"]; exists {
		return false
	}
	routes, exists := doc["routes"]
	if !exists {
		return false
	}
	var prefixes map[string]json.RawMessage
	return json.Unmarshal(routes, &prefixes) == nil && prefixes != nil && len(prefixes) == 0
}
func preflightRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrPackage
	}
	return raw, nil
}
func preflightNoListeners(children []ChildIdentity) error {
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ErrPackage
	}
	owned := map[string]bool{}
	for _, child := range children {
		childNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", child.PID))
		if err != nil || childNamespace != namespace {
			return ErrPackage
		}
		actual, err := childIdentity(child.Name, child.PID)
		if err != nil || actual != child {
			return ErrPackage
		}
		status, err := preflightRead(fmt.Sprintf("/proc/%d/status", child.PID), 65536)
		if err != nil {
			return ErrPackage
		}
		for _, name := range []string{"CapEff:", "CapBnd:"} {
			found := false
			for _, line := range strings.Split(string(status), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == name {
					caps, err := strconv.ParseUint(fields[1], 16, 64)
					if err != nil || caps&(1<<21) != 0 {
						return ErrPackage
					}
					found = true
				}
			}
			if !found {
				return ErrPackage
			}
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", child.PID))
		if err != nil || len(fds) > 4096 {
			return ErrPackage
		}
		for _, fd := range fds {
			target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", child.PID, fd.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return ErrPackage
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
			}
		}
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := preflightRead(path, 1<<20)
		if err != nil {
			return ErrPackage
		}
		if !preflightTCPAbsent(raw, owned) {
			return ErrPackage
		}
	}
	for _, child := range children {
		childNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", child.PID))
		if err != nil || childNamespace != namespace {
			return ErrPackage
		}
		actual, err := childIdentity(child.Name, child.PID)
		if err != nil || actual != child {
			return ErrPackage
		}
	}
	return nil
}
func preflightTCPAbsent(raw []byte, owned map[string]bool) bool {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "local_address") || !strings.Contains(lines[0], "st") {
		return false
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return false
		}
		if _, err := strconv.ParseUint(fields[9], 10, 64); err != nil {
			return false
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 || state < 1 || state > 12 {
			return false
		}
		if fields[3] == "0A" && owned[fields[9]] {
			return false
		}
	}
	return true
}
