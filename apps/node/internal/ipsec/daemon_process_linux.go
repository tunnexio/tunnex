//go:build linux

package ipsec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ErrDaemonProcess = errors.New("dedicated IPsec daemon unavailable")

const daemonRunDirectory = "/run/tunnex-ipsec"
const daemonExecutable = "/opt/tunnex-ipsec/libexec/ipsec/charon"

type DaemonProcess struct {
	Client    *DaemonClient
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	lock      *os.File
	dir       string
	directory os.FileInfo
	owned     map[string]os.FileInfo
	closed    bool
}

// StartDaemonProcess never adopts a foreign daemon or its configuration. The
// pinned binary's PID directory is fixed at build time. Existing unexplained
// artifacts refuse startup; neither PID reuse nor stale files authorize a kill.
func StartDaemonProcess(ctx context.Context) (*DaemonProcess, error) {
	if err := os.Mkdir(daemonRunDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrDaemonProcess
	}
	return startDaemonProcess(ctx, daemonRunDirectory, daemonExecutable)
}
func startDaemonProcess(ctx context.Context, dir, executable string) (*DaemonProcess, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !filepath.IsAbs(executable) {
		return nil, ErrDaemonProcess
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if e != nil || resolved != dir {
		return nil, ErrDaemonProcess
	}
	di, e := os.Lstat(dir)
	if e != nil || !journalPrivate(di, true) {
		return nil, ErrDaemonProcess
	}
	binary, e := os.Lstat(executable)
	if e != nil || !binary.Mode().IsRegular() || binary.Mode()&os.ModeSymlink != 0 || binary.Mode().Perm()&0022 != 0 || binary.Mode().Perm()&0111 == 0 || !ownedByCurrentUser(binary) {
		return nil, ErrDaemonProcess
	}
	resolved, e = filepath.EvalSymlinks(executable)
	if e != nil || resolved != executable {
		return nil, ErrDaemonProcess
	}
	fd, e := unix.Open(filepath.Join(dir, "supervisor.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrDaemonProcess
	}
	lock := os.NewFile(uintptr(fd), "supervisor.lock")
	li, e := lock.Stat()
	if e != nil || !journalPrivate(li, false) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrDaemonProcess
	}
	p := &DaemonProcess{dir: dir, directory: di, lock: lock, done: make(chan struct{}), owned: map[string]os.FileInfo{}}
	fail := func() (*DaemonProcess, error) { p.Close(); return nil, ErrDaemonProcess }
	entries, e := os.ReadDir(dir)
	if e != nil {
		return fail()
	}
	for _, entry := range entries {
		if entry.Name() != "supervisor.lock" {
			return fail()
		}
	}
	// All paths are internal constants. No provider text, PSK or includes are written.
	socket := filepath.Join(dir, "charon.vici")
	// IKEv2 DPD shares the IKE retransmission schedule. The upstream default
	// waits about 165s before declaring a silent peer dead. Keep three retries
	// (2 + 3 + 4.5 + 6.75 = 16.25s) so transient packet loss is tolerated while
	// the controller can select a verified standby promptly. These settings
	// affect only our dedicated daemon, including its negotiation and rekey.
	config := "charon {\n load = random nonce openssl kdf kernel-netlink socket-default vici\n retransmit_timeout = 2.0\n retransmit_base = 1.5\n retransmit_tries = 3\n install_routes = no\n routing_table = 0\n install_virtual_ip = no\n plugins {\n kernel-netlink { install_routes_xfrmi = no }\n vici { socket = unix://" + socket + " }\n }\n filelog { stderr { default = -1 } }\n}\n"
	f, e := os.OpenFile(filepath.Join(dir, "strongswan.conf"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return fail()
	}
	p.owned["strongswan.conf"], e = f.Stat()
	if e == nil {
		_, e = io.WriteString(f, config)
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fail()
	}
	cmd := exec.Command(executable)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STRONGSWAN_CONF=" + filepath.Join(dir, "strongswan.conf")}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	// Parent loss stops this child; the journal and refusal guard remain. Kernel
	// objects still require independent cleanup proof, never a process receipt.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if cmd.Start() != nil {
		return fail()
	}
	p.cmd = cmd
	go func() { _ = cmd.Wait(); close(p.done) }()
	client, e := NewDaemonClient(socket)
	if e != nil {
		return fail()
	}
	p.Client = client
	startCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-startCtx.Done():
			return fail()
		case <-p.done:
			return fail()
		case <-tick.C:
		}
		// Confirm the child and namespace before accepting its socket. Never signal a
		// PID read from disk, and never accept another process at the expected path.
		current, e := os.Lstat(dir)
		if e != nil || !os.SameFile(di, current) || !journalPrivate(current, true) {
			return fail()
		}
		si, e := os.Lstat(socket)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || si.Mode()&os.ModeSocket == 0 || si.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(si) {
			return fail()
		}
		if e = os.Chmod(socket, 0600); e != nil {
			return fail()
		}
		after, e := os.Lstat(socket)
		if e != nil || !os.SameFile(si, after) {
			return fail()
		}
		p.owned["charon.vici"] = after
		if pi, e := os.Lstat(filepath.Join(dir, "charon.pid")); e == nil && pi.Mode().IsRegular() && ownedByCurrentUser(pi) {
			p.owned["charon.pid"] = pi
		}
		inventory, e := client.Inspect(startCtx)
		if e != nil {
			continue
		}
		if len(inventory.Connections) != 0 || len(inventory.SharedKeys) != 0 || len(inventory.SAs) != 0 {
			return fail()
		}
		if !p.Alive() {
			return fail()
		}
		return p, nil
	}
}
func (p *DaemonProcess) Alive() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *DaemonProcess) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.cmd != nil {
		select {
		case <-p.done:
		default:
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-p.done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
				_ = p.cmd.Process.Kill()
				killed := time.NewTimer(2 * time.Second)
				select {
				case <-p.done:
					killed.Stop()
				case <-killed.C:
					// Preserve exclusive lock and artifacts if process death
					// cannot be established. Never report cleanup or start another.
					return ErrDaemonProcess
				}
			}
		}
	}
	var failed bool
	di, e := os.Lstat(p.dir)
	if e != nil || !os.SameFile(di, p.directory) {
		failed = true
	} else {
		for name, expected := range p.owned {
			current, e := os.Lstat(filepath.Join(p.dir, name))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil || expected == nil || !os.SameFile(current, expected) {
				failed = true
				continue
			}
			if os.Remove(filepath.Join(p.dir, name)) != nil {
				failed = true
			}
		}
	}
	if p.lock != nil {
		_ = unix.Flock(int(p.lock.Fd()), unix.LOCK_UN)
		if p.lock.Close() != nil {
			failed = true
		}
		p.lock = nil
	}
	if failed {
		return ErrDaemonProcess
	}
	return nil
}
