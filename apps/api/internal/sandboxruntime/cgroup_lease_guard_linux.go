//go:build linux

package sandboxruntime

import (
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
)

const cgroupMount = "/sys/fs/cgroup"

type nativeCgroupLeaseBackend struct {
	root   *os.Root
	parent string
	uid    uint32
}
type nativeCgroupLeaseNode struct {
	root         *os.Root
	parent       string
	freeze, kill *os.File
	frozen       bool
}

// NewActorCgroupLeaseGuard preserves the legacy qualification placement.
func NewActorCgroupLeaseGuard() (*ActorCgroupLeaseGuard, error) {
	return NewActorCgroupLeaseGuardAt(actorControlCgroup)
}

// NewActorCgroupLeaseGuardAt uses only trusted operator configuration. Exact
// actual placement, delegation ownership, aggregate limits and kernel controls
// remain mandatory. No workload request can supply or change this path.
func NewActorCgroupLeaseGuardAt(expectedControl string) (*ActorCgroupLeaseGuard, error) {
	return newNativeActorCgroupLeaseGuard(expectedControl)
}

func newNativeActorCgroupLeaseGuard(expectedControl string) (*ActorCgroupLeaseGuard, error) {
	uid := uint32(os.Geteuid())
	if uid == 0 || !ValidActorControlCgroup(expectedControl) || path.Clean(expectedControl) != expectedControl {
		return nil, ErrOwnership
	}
	actual, err := readUnifiedCgroup("/proc/self/cgroup")
	if err != nil || actual != expectedControl {
		return nil, ErrOwnership
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(cgroupMount, &fs) != nil || uint64(fs.Type) != 0x63677270 {
		return nil, ErrUnavailable
	}
	parent := path.Dir(actual)
	root, err := os.OpenRoot(cgroupMount + parent)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	if err = checkOwned(root, ".", uid, true); err != nil {
		return nil, err
	}
	if value, err := readCgroup(root, "cgroup.type"); err != nil || value != "domain" {
		return nil, ErrOwnership
	}
	if value, err := readCgroup(root, "cgroup.procs"); err != nil || value != "" {
		return nil, ErrOwnership
	}
	// Kernel delegation requires migration permission on the destination and
	// common ancestor. Check the exact empty actor root, never the slice/root.
	procs, err := ownedWritable(root, "cgroup.procs", uid)
	if err != nil {
		return nil, err
	}
	procs.Close()
	slice, err := os.OpenRoot(cgroupMount + path.Dir(parent))
	if err != nil {
		return nil, ErrOwnership
	}
	defer slice.Close()
	if checkOwned(slice, ".", 0, true) != nil {
		return nil, ErrOwnership
	}
	for name, expected := range map[string]string{"memory.max": "234881024", "memory.swap.max": "0", "pids.max": "256"} {
		value, err := readCgroup(slice, name)
		if err != nil || value != expected {
			return nil, ErrOwnership
		}
	}
	if err = enableControllers(root, uid); err != nil {
		return nil, err
	}
	b := &nativeCgroupLeaseBackend{root: root, parent: parent, uid: uid}
	root = nil
	return newCgroupLeaseGuard(b), nil
}

func checkOwned(root *os.Root, name string, uid uint32, directory bool) error {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || info.Mode().Perm()&0002 != 0 {
		return ErrOwnership
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return ErrOwnership
	}
	return nil
}
func readCgroup(root *os.Root, name string) (string, error) {
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return "", ErrUnavailable
	}
	return strings.TrimSpace(string(raw)), nil
}
func ownedWritable(root *os.Root, name string, uid uint32) (*os.File, error) {
	if checkOwned(root, name, uid, false) != nil {
		return nil, ErrOwnership
	}
	f, err := root.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	return f, nil
}
func writeCgroup(f *os.File, value string) error {
	count, err := f.WriteString(value)
	if err == nil && count != len(value) {
		err = io.ErrShortWrite
	}
	return err
}
func enableControllers(root *os.Root, uid uint32) error {
	available, err := readCgroup(root, "cgroup.controllers")
	if err != nil {
		return ErrUnavailable
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(" "+available+" ", " "+controller+" ") {
			return ErrUnavailable
		}
	}
	f, err := ownedWritable(root, "cgroup.subtree_control", uid)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeCgroup(f, "+cpu +memory +pids")
}
func (b *nativeCgroupLeaseBackend) Create(id uuid.UUID) (cgroupLeaseNode, error) {
	name := "sandbox-" + id.String()
	if err := b.root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	if checkOwned(b.root, name, b.uid, true) != nil {
		return nil, ErrOwnership
	}
	root, err := b.root.OpenRoot(name)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	if value, err := readCgroup(root, "cgroup.type"); err != nil || value != "domain" {
		return nil, ErrOwnership
	}
	if value, err := readCgroup(root, "cgroup.procs"); err != nil || value != "" {
		return nil, ErrOwnership
	}
	// A domain root may be empty while an unrelated retained descendant is
	// populated. Unknown UUID scopes must be wholly empty before adoption or
	// resource-limit writes. Actor failure then fences its complete owned tree.
	events, err := readCgroup(root, "cgroup.events")
	if err != nil || !strings.Contains("\n"+events+"\n", "\npopulated 0\n") {
		return nil, ErrOwnership
	}
	for file, value := range map[string]string{"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "100000 100000"} {
		f, err := ownedWritable(root, file, b.uid)
		if err != nil {
			return nil, err
		}
		err = writeCgroup(f, value)
		f.Close()
		if err != nil {
			return nil, ErrUnavailable
		}
		actual, err := readCgroup(root, file)
		if err != nil || actual != value {
			return nil, ErrOwnership
		}
	}
	if err = enableControllers(root, b.uid); err != nil {
		return nil, err
	}
	procs, err := ownedWritable(root, "cgroup.procs", b.uid)
	if err != nil {
		return nil, err
	}
	procs.Close()
	freeze, err := ownedWritable(root, "cgroup.freeze", b.uid)
	if err != nil {
		return nil, err
	}
	kill, err := ownedWritable(root, "cgroup.kill", b.uid)
	if err != nil {
		freeze.Close()
		return nil, err
	}
	value, err := readCgroup(root, "cgroup.freeze")
	if err != nil || (value != "0" && value != "1") {
		freeze.Close()
		kill.Close()
		return nil, ErrOwnership
	}
	node := &nativeCgroupLeaseNode{root: root, parent: b.parent + "/" + name, freeze: freeze, kill: kill, frozen: value == "1"}
	root = nil
	return node, nil
}
func (b *nativeCgroupLeaseBackend) Close() error { return b.root.Close() }
func (n *nativeCgroupLeaseNode) Parent() string  { return n.parent }
func (n *nativeCgroupLeaseNode) Frozen() bool    { return n.frozen }
func (n *nativeCgroupLeaseNode) Fence() error {
	// Attempt kill even when freeze fails. Never thaw or remove the parent.
	freezeErr := writeCgroup(n.freeze, "1")
	killErr := writeCgroup(n.kill, "1")
	return errors.Join(freezeErr, killErr)
}
func (n *nativeCgroupLeaseNode) Close() error {
	return errors.Join(n.freeze.Close(), n.kill.Close(), n.root.Close())
}
func (n *nativeCgroupLeaseNode) CheckRuntime(parent string, pid int, running bool) error {
	if parent != n.parent {
		return ErrOwnership
	}
	if !running {
		if pid != 0 {
			return ErrOwnership
		}
		return nil
	}
	if pid <= 0 {
		return ErrOwnership
	}
	actual, err := readUnifiedCgroup("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil || !strings.HasPrefix(actual, n.parent+"/") {
		return ErrOwnership
	}
	return nil
}
func readUnifiedCgroup(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return "", ErrUnavailable
	}
	var found string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			return "", ErrOwnership
		}
		value := strings.TrimPrefix(line, "0::")
		if found != "" || path.Clean(value) != value || strings.ContainsAny(value, "\x00\r") {
			return "", ErrOwnership
		}
		found = value
	}
	if found == "" {
		return "", ErrOwnership
	}
	return found, nil
}
