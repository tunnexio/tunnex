//go:build linux

package bgp

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type managedChild struct {
	cmd  *exec.Cmd
	done chan struct{}
	log  *safeDiagnostic
}
type Process struct {
	mu        sync.Mutex
	dir       string
	config    Config
	lock      *os.File
	children  []*managedChild
	closed    bool
	closeErr  error
	directory os.FileInfo
	owned     map[string]os.FileInfo
}

func StartProcess(ctx context.Context, dir string, c Config) (*Process, error) {
	return StartProcessWithCheckpoint(ctx, dir, c, nil)
}

func StartProcessWithCheckpoint(ctx context.Context, dir string, c Config, checkpoint func(ProcessIdentity) error) (*Process, error) {
	return startProcess(ctx, dir, c, checkpoint, false, nil)
}

// StartProcessWithCheckpointAndLocalExportProof requires a fresh caller-owned
// proof for the exact exported prefixes. Generic start methods remain strict.
func StartProcessWithCheckpointAndLocalExportProof(ctx context.Context, dir string, c Config, checkpoint func(ProcessIdentity) error, proof LocalExportProof) (*Process, error) {
	if proof == nil {
		return nil, ErrPackage
	}
	return startProcess(ctx, dir, c, checkpoint, false, proof)
}

// StartObserver has no configured BGP instance or peers and never listens on a
// BGP/TCP VTY port. It qualifies the installed engine without route authority.
func StartObserver(ctx context.Context, dir string) (*Process, error) {
	return startProcess(ctx, dir, Config{}, nil, true, nil)
}
func startProcess(ctx context.Context, dir string, c Config, checkpoint func(ProcessIdentity) error, observer bool, localExportProof LocalExportProof) (*Process, error) {
	if (!observer && !c.valid()) || ProbePackage(ctx) != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrPackage
	}
	if !observer {
		if err := ProbePeerReachability(ctx, c.Peers); err != nil {
			return nil, err
		}
		if err := proveProcessLocalExport(ctx, c.LocalPrefixes, localExportProof, ProbeLocalReachability); err != nil {
			return nil, err
		}
	}
	if !privateAncestors(filepath.Dir(dir)) {
		return nil, ErrPackage
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, ErrPackage
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrPackage
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil, ErrPackage
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return nil, ErrPackage
	}
	fd, e := syscall.Open(filepath.Join(dir, "supervisor.lock"), syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrPackage
	}
	lock := os.NewFile(uintptr(fd), "supervisor.lock")
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrPackage
	}
	p := &Process{dir: dir, config: c, lock: lock, directory: info, owned: map[string]os.FileInfo{}}
	lockInfo, _ := lock.Stat()
	p.owned["supervisor.lock"] = lockInfo
	fail := func() (*Process, error) {
		capture := p.captureArtifacts()
		cleanup := p.Close()
		if capture != nil || cleanup != nil {
			return nil, fmt.Errorf("%w: startup cleanup obligation retained", ErrPackage)
		}
		return nil, ErrPackage
	}
	text := "hostname tunnex-bgp-preflight\nrouter bgp 65534\n bgp router-id 192.0.2.1\n no bgp default ipv4-unicast\n address-family ipv4 unicast\n exit-address-family\n"
	if !observer {
		text, e = RenderConfig(c)
	}
	if e != nil {
		return fail()
	}
	if writePrivateConfig(filepath.Join(dir, "bgpd.conf"), []byte(text)) != nil || writePrivateConfig(filepath.Join(dir, "zebra.conf"), []byte("hostname tunnex-observer\n")) != nil {
		return fail()
	}
	for _, name := range []string{"bgpd.conf", "zebra.conf"} {
		fi, _ := os.Lstat(filepath.Join(dir, name))
		p.owned[name] = fi
	}
	saveIdentity := func(stage string) error {
		if checkpoint == nil {
			return nil
		}
		id, err := p.identity(stage)
		if err != nil {
			return err
		}
		return checkpoint(id)
	}
	if saveIdentity("reserved") != nil {
		return fail()
	}
	for _, name := range []string{"zebra", "bgpd"} {
		args := []string{"-f", filepath.Join(dir, name+".conf"), "-i", filepath.Join(dir, name+".pid"), "--vty_socket", dir, "-z", filepath.Join(dir, "zserv.api"), "-P", "0", "-u", "root", "-g", "root"}
		if name == "bgpd" {
			args = append(args, "-n", "-S")
			if observer {
				args = append(args, "-p", "0")
			}
			if !observer {
				listen := map[string]bool{}
				for _, peer := range c.Peers[:c.activePeerCount()] {
					if listen[peer.Local.String()] {
						continue
					}
					listen[peer.Local.String()] = true
					args = append(args, "-l", peer.Local.String())
				}
			}
		}
		cmd := exec.Command("/opt/tunnex-bgp/"+name, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		// A supervisor crash must stop exports immediately; crash cleanup still
		// validates persisted identities before deleting any residue.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		var diagnostic safeDiagnostic
		cmd.Stdout = &diagnostic
		cmd.Stderr = &diagnostic
		child := &managedChild{cmd: cmd, done: make(chan struct{}), log: &diagnostic}
		started := make(chan error, 1)
		// Linux Pdeathsig follows the creating thread, so retain that exact OS
		// thread until its child has exited; normal Go thread retirement cannot
		// unexpectedly kill a healthy managed daemon.
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			err := cmd.Start()
			started <- err
			if err == nil {
				<-child.done
			}
		}()
		if <-started != nil {
			return fail()
		}
		p.children = append(p.children, child)
		go func() { cmd.Wait(); close(child.done) }()
		if saveIdentity("partial") != nil {
			return fail()
		}
		socket := filepath.Join(dir, name+".vty")
		ready := false
		for n := 0; n < 50; n++ {
			select {
			case <-child.done:
				p.captureArtifacts()
				p.Close()
				return nil, fmt.Errorf("%w: %s startup: %s", ErrPackage, name, diagnostic.String())
			default:
			}
			if fi, e := os.Lstat(socket); e == nil && fi.Mode()&os.ModeSocket != 0 {
				if os.Chmod(socket, 0600) == nil {
					ready = true
					break
				}
			}
			select {
			case <-ctx.Done():
				return fail()
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !ready {
			return fail()
		}
		if p.captureArtifacts() != nil || saveIdentity("partial") != nil {
			return fail()
		}
	}
	if p.captureArtifacts() != nil {
		return fail()
	}
	entries, e = os.ReadDir(dir)
	if e != nil {
		return fail()
	}
	for _, entry := range entries {
		current, err := os.Lstat(filepath.Join(dir, entry.Name()))
		owned, known := p.owned[entry.Name()]
		if err != nil || !known || !os.SameFile(current, owned) {
			return fail()
		}
	}
	if saveIdentity("ready") != nil {
		return fail()
	}
	return p, nil
}
func (p *Process) Alive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.children) != 2 {
		return false
	}
	for _, c := range p.children {
		select {
		case <-c.done:
			return false
		default:
		}
	}
	return true
}
func (p *Process) Close() (result error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	defer func() { p.closeErr = result }()
	for i := len(p.children) - 1; i >= 0; i-- {
		c := p.children[i]
		select {
		case <-c.done:
		default:
			c.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				c.cmd.Process.Kill()
				<-c.done
			}
		}
	}
	if p.lock != nil {
		defer p.lock.Close()
	}
	current, dirErr := os.Lstat(p.dir)
	if dirErr != nil || !os.SameFile(current, p.directory) || !rootPrivateDirectory(current) || !privateAncestors(filepath.Dir(p.dir)) {
		return ErrPackage
	}
	// Only internal names created by our processes/configuration; foreign files refuse cleanup.
	entries, e := os.ReadDir(p.dir)
	if e != nil {
		return ErrPackage
	}
	allowed := map[string]bool{"supervisor.lock": true, "bgpd.conf": true, "zebra.conf": true, "bgpd.pid": true, "zebra.pid": true, "bgpd.vty": true, "zebra.vty": true, "zserv.api": true}
	for _, f := range entries {
		current, e := os.Lstat(filepath.Join(p.dir, f.Name()))
		expected, known := p.owned[f.Name()]
		if e != nil || !known || expected == nil || !os.SameFile(current, expected) || !allowed[f.Name()] {
			return ErrPackage
		}
	}
	for _, f := range entries {
		if f.Name() == "supervisor.lock" {
			continue
		}
		path := filepath.Join(p.dir, f.Name())
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(current, p.owned[f.Name()]) {
			return ErrPackage
		}
		if os.Remove(path) != nil {
			return ErrPackage
		}
	}
	current, err := os.Lstat(filepath.Join(p.dir, "supervisor.lock"))
	if err != nil || !os.SameFile(current, p.owned["supervisor.lock"]) {
		return ErrPackage
	}
	if os.Remove(filepath.Join(p.dir, "supervisor.lock")) != nil {
		return ErrPackage
	}
	identity, err := fileIdentity(p.directory)
	if err != nil {
		return ErrPackage
	}
	return syncEmptyDirectory(p.dir, identity)
}
func (p *Process) Observe(ctx context.Context) (Status, error) {
	if !p.Alive() || !p.vtyOwned() {
		return Status{}, ErrPackage
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/opt/tunnex-bgp/vtysh", "--vty_socket", p.dir, "-d", "bgpd", "-c", "show bgp ipv4 unicast summary json")
	var output boundedResponse
	cmd.Stdout = &output
	cmd.Stderr = &output
	if cmd.Run() != nil {
		return Status{}, ErrPackage
	}
	return ParseSummary(output.Bytes(), p.config)
}
func ProbeLocalReachability(ctx context.Context, prefixes []netip.Prefix) error {
	return probeLocalReachability(prefixes, func(args ...string) ([]byte, error) {
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(child, "/sbin/ip", args...)
		var out boundedResponse
		cmd.Stdout = &out
		if cmd.Run() != nil {
			return nil, ErrPackage
		}
		return out.Bytes(), nil
	})
}

func (p *Process) vtyOwned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	dir, e := os.Lstat(p.dir)
	if e != nil || !os.SameFile(dir, p.directory) || !rootPrivateDirectory(dir) || !privateAncestors(filepath.Dir(p.dir)) {
		return false
	}
	dst, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || dst.Uid != 0 {
		return false
	}
	socket, e := os.Lstat(filepath.Join(p.dir, "bgpd.vty"))
	expected := p.owned["bgpd.vty"]
	if e != nil || expected == nil || !os.SameFile(socket, expected) || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0600 {
		return false
	}
	st, ok := socket.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// Diagnostics is bounded nonsecret daemon output, useful for owned qualification.
func (p *Process) Diagnostics() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, c := range p.children {
		out = append(out, c.log.String())
	}
	return out
}

type safeDiagnostic struct {
	mu   sync.Mutex
	data []byte
}

func (d *safeDiagnostic) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 4096 - len(d.data)
	if n > len(p) {
		n = len(p)
	}
	if n > 0 {
		d.data = append(d.data, p[:n]...)
	}
	return len(p), nil
}
func (d *safeDiagnostic) String() string { d.mu.Lock(); defer d.mu.Unlock(); return string(d.data) }

func (p *Process) captureArtifacts() error {
	dir, err := os.Lstat(p.dir)
	if err != nil || !os.SameFile(dir, p.directory) || !rootPrivateDirectory(dir) {
		return ErrPackage
	}
	expected := map[string]bool{"supervisor.lock": true, "bgpd.conf": true, "zebra.conf": true, "bgpd.pid": true, "zebra.pid": true, "bgpd.vty": true, "zebra.vty": true, "zserv.api": true}
	entries, e := os.ReadDir(p.dir)
	if e != nil {
		return ErrPackage
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return ErrPackage
		}
		if owned, known := p.owned[entry.Name()]; known {
			current, err := os.Lstat(filepath.Join(p.dir, entry.Name()))
			if err != nil || !os.SameFile(current, owned) || current.Mode() != owned.Mode() {
				return ErrPackage
			}
			continue
		}
		fi, e := os.Lstat(filepath.Join(p.dir, entry.Name()))
		if e != nil || fi.Mode()&os.ModeSymlink != 0 {
			return ErrPackage
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return ErrPackage
		}
		isSocket := entry.Name() == "bgpd.vty" || entry.Name() == "zebra.vty" || entry.Name() == "zserv.api"
		if (isSocket && fi.Mode()&os.ModeSocket == 0) || (!isSocket && !fi.Mode().IsRegular()) {
			return ErrPackage
		}
		if os.Chmod(filepath.Join(p.dir, entry.Name()), 0600) != nil {
			return ErrPackage
		}
		fresh, err := os.Lstat(filepath.Join(p.dir, entry.Name()))
		if err != nil || !os.SameFile(fi, fresh) {
			return ErrPackage
		}
		p.owned[entry.Name()] = fresh
	}
	return nil
}

func rootPrivateDirectory(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && info.IsDir() && info.Mode().Perm() == 0700
}
func privateAncestors(path string) bool {
	for {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if path == "/" {
			return true
		}
		path = filepath.Dir(path)
	}
}
func writePrivateConfig(path string, data []byte) error {
	fd, e := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}

// ObserveRoutes reads a fixed filtered-RIB command; command text never includes input.
func (p *Process) ObserveRoutes(ctx context.Context, status Status) ([]LearnedRoute, error) {
	if !p.Alive() || !p.vtyOwned() {
		return nil, ErrPackage
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/opt/tunnex-bgp/vtysh", "--vty_socket", p.dir, "-d", "bgpd", "-c", "show bgp ipv4 unicast json")
	var output boundedRIBResponse
	cmd.Stdout = &output
	cmd.Stderr = &output
	if cmd.Run() != nil {
		return nil, ErrPackage
	}
	return ParseRoutes(output.Bytes(), p.config, status)
}

// Stopped proves every owned child Wait completed, independent of artifact
// cleanup errors. It permits forgetting only the in-memory supervisor handle.
func (p *Process) Stopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, child := range p.children {
		select {
		case <-child.done:
		default:
			return false
		}
	}
	return true
}

func (p *Process) Identity() (ProcessIdentity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ProcessIdentity{}, ErrPackage
	}
	return p.identity("ready")
}

// PreflightRIB permits one fixed read command only; configuration never enters CLI input.
func (p *Process) PreflightRIB(ctx context.Context) ([]byte, error) {
	if !p.Alive() || !p.vtyOwned() {
		return nil, ErrPackage
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/opt/tunnex-bgp/vtysh", "--vty_socket", p.dir, "-d", "bgpd", "-c", "show bgp ipv4 unicast json")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	var output boundedResponse
	var diagnostic boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		text := diagnostic.String()
		if len(text) > 256 {
			text = text[:256]
		}
		return output.Bytes(), fmt.Errorf("%w: fixed-vty read=%v diagnostic=%q", ErrPackage, err, text)
	}
	return output.Bytes(), nil
}
