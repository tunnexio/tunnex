//go:build linux

package bgp

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProveCleanedProcessAbsent is read-only. Cleaned metadata alone is insufficient:
// the original directory must be unchanged and empty, and its daemons absent.
// bootDischarged is supplied only by the caller's verified reset/restoration duty.
func ProveCleanedProcessAbsent(ctx context.Context, id ProcessIdentity, bootDischarged bool) error {
	if ctx.Err() != nil || (id.Stage != "cleaned" && !bootDischarged) || !filepath.IsAbs(id.Directory) || filepath.Clean(id.Directory) != id.Directory || !privateAncestors(filepath.Dir(id.Directory)) {
		return ErrPackage
	}
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ErrPackage
	}
	boot := strings.TrimSpace(string(raw))
	if id.BootID != boot && !bootDischarged {
		return ErrPackage
	}
	if id.BootID == boot {
		for _, child := range id.Children {
			if !originalProcessAbsent(child) {
				return ErrPackage
			}
		}
	}
	if !directoryDaemonsAbsent(id) {
		return ErrPackage
	}
	info, err := os.Lstat(id.Directory)
	if err != nil || !rootPrivateDirectory(info) {
		return ErrPackage
	}
	actual, err := fileIdentity(info)
	if err != nil || actual != id.DirectoryFile {
		return ErrPackage
	}
	fd, err := os.Open(id.Directory)
	if err != nil {
		return ErrPackage
	}
	defer fd.Close()
	current, err := fd.Stat()
	if err != nil {
		return ErrPackage
	}
	currentID, err := fileIdentity(current)
	if err != nil || currentID != actual {
		return ErrPackage
	}
	entries, err := fd.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		return ErrPackage
	}
	after, err := os.Lstat(id.Directory)
	if err != nil {
		return ErrPackage
	}
	afterID, err := fileIdentity(after)
	if err != nil || afterID != actual || !directoryDaemonsAbsent(id) || ctx.Err() != nil {
		return ErrPackage
	}
	return nil
}

// ProveCleanedHistoryAbsent checks every extant compacted generation directory.
// Hash-chain tombstones are discharged history, never deletion/adoption authority.
func ProveCleanedHistoryAbsent(ctx context.Context, parent, prefix string, count uint64) error {
	return proveHistoryAbsent(ctx, parent, prefix, count, 0)
}

// ProveHistoryAbsentExcept permits only one independently verified live
// generation. Every other matching generation, including later orphan
// directories, must be empty and have no matching daemon.
func ProveHistoryAbsentExcept(ctx context.Context, parent, prefix string, liveGeneration uint64) error {
	if liveGeneration == 0 {
		return ErrPackage
	}
	return proveHistoryAbsent(ctx, parent, prefix, ^uint64(0), liveGeneration)
}

func proveHistoryAbsent(ctx context.Context, parent, prefix string, count, except uint64) error {
	if ctx.Err() != nil || count == 0 || !privateAncestors(parent) {
		return ErrPackage
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) > 8192 {
		return ErrPackage
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), prefix)
		generation, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != suffix {
			return ErrPackage
		}
		if generation > count || generation == except {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !rootPrivateDirectory(info) {
			return ErrPackage
		}
		before, err := fileIdentity(info)
		if err != nil {
			return ErrPackage
		}
		children, err := os.ReadDir(path)
		if err != nil || len(children) != 0 || !directoryDaemonsAbsent(ProcessIdentity{Directory: path}) {
			return ErrPackage
		}
		after, err := os.Lstat(path)
		if err != nil {
			return ErrPackage
		}
		afterID, err := fileIdentity(after)
		if err != nil || afterID != before || ctx.Err() != nil {
			return ErrPackage
		}
	}
	// Also inspect matching daemon arguments when a former directory is absent.
	processes, err := os.ReadDir("/proc")
	if err != nil || len(processes) > 8192 {
		return ErrPackage
	}
	for _, process := range processes {
		if ctx.Err() != nil {
			return ErrPackage
		}
		pid, err := strconv.Atoi(process.Name())
		if err != nil || pid <= 0 {
			continue
		}
		proc := fmt.Sprintf("/proc/%d", pid)
		exe, err := os.Readlink(proc + "/exe")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrPackage
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if exe != "/opt/tunnex-bgp/bgpd" && exe != "/opt/tunnex-bgp/zebra" {
			continue
		}
		file, err := os.Open(proc + "/cmdline")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrPackage
		}
		raw, err := io.ReadAll(io.LimitReader(file, 65537))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(raw) > 65536 {
			return ErrPackage
		}
		for _, arg := range strings.Split(string(raw), "\x00") {
			candidate := arg
			if filepath.Dir(candidate) != parent {
				candidate = filepath.Dir(candidate)
			}
			if filepath.Dir(candidate) != parent || !strings.HasPrefix(filepath.Base(candidate), prefix) {
				continue
			}
			generation, err := strconv.ParseUint(strings.TrimPrefix(filepath.Base(candidate), prefix), 10, 64)
			if err != nil || generation == 0 || generation <= count && generation != except {
				return ErrPackage
			}
		}
	}

	return nil
}
