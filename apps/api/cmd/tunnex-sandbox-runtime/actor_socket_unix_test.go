//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

func TestActorSocketRecoveryRefusesUnknownOrLiveEndpoint(t *testing.T) {
	if os.Geteuid() == 0 {
		// The API CI container runs as root; the actor intentionally cannot.
		// Execute every fixture with real unprivileged OS credentials instead
		// of skipping them or weakening the production UID-zero refusal.
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		// go test may place its binary below a root-only temporary directory.
		dir, err := os.MkdirTemp("/tmp", "tnxas-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		path := filepath.Join(dir, "actor-socket.test")
		if err := os.WriteFile(path, binary, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, path, "-test.run=^TestActorSocketRecoveryRefusesUnknownOrLiveEndpoint$", "-test.v", "-test.count=1", "-test.timeout=25s")
		child.Dir = dir
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		output, err := child.CombinedOutput()
		t.Logf("unprivileged actor fixtures:\n%s", output)
		if err != nil {
			t.Fatal("unprivileged actor fixtures failed", err)
		}
		return
	}
	for _, fixture := range []string{"absent", "file", "symlink", "live", "stopped", "wrong-mode", "wrong-identity"} {
		t.Run(fixture, func(t *testing.T) {
			// macOS Unix sockets have a short sockaddr path limit.
			dir, err := os.MkdirTemp("/tmp", "tnxas-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			socket := filepath.Join(dir, "control.sock")
			parent, err := root.Lstat(".")
			if err != nil {
				t.Fatal(err)
			}
			// BSD may inherit the temporary directory's group from /tmp.
			uid, gid := uint32(os.Geteuid()), parent.Sys().(*syscall.Stat_t).Gid
			switch fixture {
			case "file":
				if err = os.WriteFile(socket, []byte("preserve"), 0660); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = os.Symlink("missing", socket); err != nil {
					t.Fatal(err)
				}
			case "live", "stopped", "wrong-mode", "wrong-identity":
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				listener.SetUnlinkOnClose(false)
				defer listener.Close()
				if err = os.Chmod(socket, 0660); err != nil {
					t.Fatal(err)
				}
				if fixture != "live" {
					listener.Close()
				}
				if fixture == "wrong-mode" {
					if err = os.Chmod(socket, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if fixture == "wrong-identity" {
					uid++
				}
			}
			err = removeStoppedActorSocket(root, uid, gid)
			if fixture == "absent" || fixture == "stopped" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = root.Lstat("control.sock"); !os.IsNotExist(err) {
					t.Fatal("socket still present", err)
				}
			} else {
				if err == nil {
					t.Fatal("unknown/live endpoint accepted")
				}
				if _, err = root.Lstat("control.sock"); err != nil {
					t.Fatal("endpoint was changed", err)
				}
			}
		})
	}
}

func TestActorSocketRecoveryRefusesRootIdentity(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "tnxas-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "control.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("control.sock", 0660); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat("control.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err := removeStoppedActorSocket(root, 0, uint32(os.Getegid())); !errors.Is(err, sandboxes.ErrInvalid) {
		t.Fatal("root actor identity accepted", err)
	}
	if after, err := root.Lstat("control.sock"); err != nil || !os.SameFile(before, after) {
		t.Fatal("root actor endpoint was changed", err)
	}
}
