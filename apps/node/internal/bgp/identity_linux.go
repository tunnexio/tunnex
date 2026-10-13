//go:build linux

package bgp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func fileIdentity(info os.FileInfo) (FileIdentity, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return FileIdentity{}, ErrPackage
	}
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino, Mode: uint32(info.Mode())}, nil
}
func childIdentity(name string, pid int) (ChildIdentity, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ChildIdentity{}, ErrPackage
	}
	tail := strings.LastIndex(string(raw), ") ")
	if tail < 0 {
		return ChildIdentity{}, ErrPackage
	}
	fields := strings.Fields(string(raw)[tail+2:])
	if len(fields) < 20 {
		return ChildIdentity{}, ErrPackage
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return ChildIdentity{}, ErrPackage
	}
	exe, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ChildIdentity{}, ErrPackage
	}
	id, err := fileIdentity(exe)
	if err != nil {
		return ChildIdentity{}, err
	}
	return ChildIdentity{Name: name, PID: pid, StartTicks: ticks, Executable: id}, nil
}
func (p *Process) identity(stage string) (ProcessIdentity, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProcessIdentity{}, ErrPackage
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ProcessIdentity{}, ErrPackage
	}
	directory, err := os.Lstat(p.dir)
	if err != nil || !os.SameFile(directory, p.directory) || !rootPrivateDirectory(directory) {
		return ProcessIdentity{}, ErrPackage
	}
	dirID, err := fileIdentity(directory)
	if err != nil {
		return ProcessIdentity{}, err
	}
	supervisor, err := childIdentity("supervisor", os.Getpid())
	if err != nil {
		return ProcessIdentity{}, err
	}
	id := ProcessIdentity{Supervisor: supervisor, Generation: 1, BootID: strings.TrimSpace(string(boot)), Namespace: ns, Directory: p.dir, Stage: stage, DirectoryFile: dirID, Files: []NamedFileIdentity{}, Children: []ChildIdentity{}}
	names := []string{}
	for name := range p.owned {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		current, e := os.Lstat(filepath.Join(p.dir, name))
		if e != nil || !os.SameFile(current, p.owned[name]) {
			return ProcessIdentity{}, ErrPackage
		}
		fi, e := fileIdentity(current)
		if e != nil {
			return ProcessIdentity{}, e
		}
		id.Files = append(id.Files, NamedFileIdentity{Name: name, File: fi})
	}
	for _, child := range p.children {
		ci, e := childIdentity(filepath.Base(child.cmd.Path), child.cmd.Process.Pid)
		if e != nil {
			return ProcessIdentity{}, e
		}
		id.Children = append(id.Children, ci)
	}
	return id, nil
}

// RecoverProcess requires independent child absence. It never adopts or signals
// a PID found in a journal; the kernel parent-death signal terminates our children.
func RecoverProcess(id ProcessIdentity) error {
	return recoverProcess(id, id.BootID, id.Namespace, false)
}

// RecoverRetiredProcess is callable only after an independently verified trusted
// runtime-termination receipt. It still refuses unknown or replaced artifacts.
func RecoverRetiredProcess(id ProcessIdentity, currentBoot, currentNamespace string) error {
	return recoverProcess(id, currentBoot, currentNamespace, true)
}
func recoverProcess(id ProcessIdentity, currentBoot, currentNamespace string, retired bool) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != currentBoot {
		return ErrPackage
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != currentNamespace {
		return ErrPackage
	}
	if !retired && (id.BootID != currentBoot || id.Namespace != currentNamespace) {
		return ErrPackage
	}
	if !filepath.IsAbs(id.Directory) || filepath.Clean(id.Directory) != id.Directory || !privateAncestors(filepath.Dir(id.Directory)) {
		return ErrPackage
	}
	directory, err := os.Lstat(id.Directory)
	if err != nil {
		return ErrPackage
	}
	current, err := fileIdentity(directory)
	if err != nil || current != id.DirectoryFile || !rootPrivateDirectory(directory) {
		return ErrPackage
	}
	for _, child := range id.Children {
		if retired && id.BootID != currentBoot {
			continue
		}
		raw, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.PID))
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return ErrPackage
		}
		tail := strings.LastIndex(string(raw), ") ")
		if tail < 0 {
			return ErrPackage
		}
		fields := strings.Fields(string(raw)[tail+2:])
		if len(fields) < 20 {
			return ErrPackage
		}
		start, parseErr := strconv.ParseUint(fields[19], 10, 64)
		if parseErr != nil {
			return ErrPackage
		}
		// Reused PID proves absence of the original child. A matching live child
		// must disappear before any residue is removed.
		if start == child.StartTicks && fields[0] != "Z" {
			return ErrPackage
		}
	}
	allowed := map[string]bool{"supervisor.lock": true, "bgpd.conf": true, "zebra.conf": true, "bgpd.pid": true, "zebra.pid": true, "bgpd.vty": true, "zebra.vty": true, "zserv.api": true}
	expected := map[string]FileIdentity{}
	for _, file := range id.Files {
		if !allowed[file.Name] || expected[file.Name].Inode != 0 {
			return ErrPackage
		}
		expected[file.Name] = file.File
	}
	entries, err := os.ReadDir(id.Directory)
	if err != nil {
		return ErrPackage
	}
	if len(entries) == 0 {
		return syncEmptyDirectory(id.Directory, id.DirectoryFile)
	}
	lockID, ok := expected["supervisor.lock"]
	if !ok {
		return ErrPackage
	}
	fd, err := syscall.Open(filepath.Join(id.Directory, "supervisor.lock"), syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPackage
	}
	lock := os.NewFile(uintptr(fd), "supervisor.lock")
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return ErrPackage
	}
	actual, err := fileIdentity(info)
	if err != nil || actual != lockID || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrPackage
	}
	entries, err = os.ReadDir(id.Directory)
	if err != nil {
		return ErrPackage
	}
	for _, entry := range entries {
		want, ok := expected[entry.Name()]
		if !ok {
			return ErrPackage
		}
		info, err := os.Lstat(filepath.Join(id.Directory, entry.Name()))
		if err != nil {
			return ErrPackage
		}
		actual, err := fileIdentity(info)
		if err != nil || actual != want {
			return ErrPackage
		}
	}
	// Delete the lock last so partial cleanup can reacquire the original inode.
	for _, entry := range entries {
		if entry.Name() == "supervisor.lock" {
			continue
		}
		path := filepath.Join(id.Directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return ErrPackage
		}
		actual, err := fileIdentity(info)
		if err != nil || actual != expected[entry.Name()] {
			return ErrPackage
		}
		if os.Remove(path) != nil {
			return ErrPackage
		}
	}
	remaining, err := os.ReadDir(id.Directory)
	if err != nil || len(remaining) != 1 || remaining[0].Name() != "supervisor.lock" {
		return ErrPackage
	}
	info, err = os.Lstat(filepath.Join(id.Directory, "supervisor.lock"))
	if err != nil {
		return ErrPackage
	}
	actual, err = fileIdentity(info)
	if err != nil || actual != lockID {
		return ErrPackage
	}
	if os.Remove(filepath.Join(id.Directory, "supervisor.lock")) != nil {
		return ErrPackage
	}
	return syncEmptyDirectory(id.Directory, id.DirectoryFile)
}

func syncEmptyDirectory(path string, expected FileIdentity) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPackage
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return ErrPackage
	}
	actual, err := fileIdentity(info)
	if err != nil || actual != expected {
		return ErrPackage
	}
	entries, err := directory.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		return ErrPackage
	}
	if directory.Sync() != nil {
		return ErrPackage
	}
	return nil
}

func originalProcessAbsent(child ChildIdentity) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.PID))
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	tail := strings.LastIndex(string(raw), ") ")
	if tail < 0 {
		return false
	}
	fields := strings.Fields(string(raw)[tail+2:])
	if len(fields) < 20 {
		return false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return false
	}
	return ticks != child.StartTicks || fields[0] == "Z"
}

// ProveUncertainRetirement preserves every artifact. Original supervisor absence
// proves kernel parent-death shutdown even for a child not yet checkpointed.
// Unknown files never acquire deletion authority from this proof.
func ProveUncertainRetirement(id ProcessIdentity) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != id.BootID {
		return ErrPackage
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != id.Namespace {
		return ErrPackage
	}
	if !originalProcessAbsent(id.Supervisor) {
		return ErrPackage
	}
	for _, child := range id.Children {
		if !originalProcessAbsent(child) {
			return ErrPackage
		}
	}
	if !directoryDaemonsAbsent(id) {
		return ErrPackage
	}
	if !privateAncestors(filepath.Dir(id.Directory)) {
		return ErrPackage
	}
	directory, err := os.Lstat(id.Directory)
	if err != nil || !rootPrivateDirectory(directory) {
		return ErrPackage
	}
	actual, err := fileIdentity(directory)
	if err != nil || actual != id.DirectoryFile {
		return ErrPackage
	}
	expected := map[string]FileIdentity{}
	for _, file := range id.Files {
		expected[file.Name] = file.File
	}
	for name, want := range expected {
		info, err := os.Lstat(filepath.Join(id.Directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrPackage
		}
		actual, err := fileIdentity(info)
		if err != nil || actual != want {
			return ErrPackage
		}
	}
	lockID, ok := expected["supervisor.lock"]
	if !ok {
		return ErrPackage
	}
	fd, err := syscall.Open(filepath.Join(id.Directory, "supervisor.lock"), syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPackage
	}
	lock := os.NewFile(uintptr(fd), "supervisor.lock")
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return ErrPackage
	}
	actual, err = fileIdentity(info)
	if err != nil || actual != lockID || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrPackage
	}
	if !directoryDaemonsAbsent(id) {
		return ErrPackage
	}
	boot, err = os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != id.BootID {
		return ErrPackage
	}
	ns, err = os.Readlink("/proc/self/ns/net")
	if err != nil || ns != id.Namespace {
		return ErrPackage
	}
	return nil
}

func RecoverUncertainProcess(id ProcessIdentity) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != id.BootID {
		return ErrPackage
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != id.Namespace || !originalProcessAbsent(id.Supervisor) || !directoryDaemonsAbsent(id) {
		return ErrPackage
	}
	if err := RecoverProcess(id); err != nil {
		return err
	}
	if !directoryDaemonsAbsent(id) {
		return ErrPackage
	}
	return nil
}

// directoryDaemonsAbsent is a bounded read-only census. It never signals or
// adopts uncheckpointed processes, and rejects any FRR still using this exact
// generation's private configuration/VTY directory.
func directoryDaemonsAbsent(id ProcessIdentity) bool {
	deadline := time.Now().Add(2 * time.Second)
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 8192 {
		return false
	}
	for _, entry := range entries {
		if time.Now().After(deadline) {
			return false
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		path := fmt.Sprintf("/proc/%d", pid)
		exe, err := os.Readlink(path + "/exe")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if exe != "/opt/tunnex-bgp/bgpd" && exe != "/opt/tunnex-bgp/zebra" {
			continue
		}
		file, err := os.Open(path + "/cmdline")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false
		}
		raw, err := io.ReadAll(io.LimitReader(file, 65537))
		closeErr := file.Close()
		if closeErr != nil {
			return false
		}
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || len(raw) > 65536 {
			return false
		}
		for _, arg := range strings.Split(string(raw), "\x00") {
			if arg == id.Directory || arg == filepath.Join(id.Directory, "bgpd.conf") || arg == filepath.Join(id.Directory, "zebra.conf") || arg == filepath.Join(id.Directory, "zserv.api") {
				return false
			}
		}
	}
	return true
}
