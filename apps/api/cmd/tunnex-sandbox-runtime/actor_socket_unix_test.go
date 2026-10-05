//go:build linux || darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestActorSocketRecoveryRefusesUnknownOrLiveEndpoint(t *testing.T) {
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
