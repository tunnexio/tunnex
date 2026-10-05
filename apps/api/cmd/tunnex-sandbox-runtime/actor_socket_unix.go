//go:build linux || darwin

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

// removeStoppedActorSocket runs only after the fixed native actor placement is
// validated. SIGKILL leaves a socket inode behind. Refuse live, foreign or
// changed endpoints; remove only this actor's protected, refused socket.
// The manager supplies one actor and its UID is jointly trusted. SameFile is
// not an atomic conditional unlink against a hostile process with that UID.
func removeStoppedActorSocket(root *os.Root, uid, gid uint32) error {
	if root == nil || uid == 0 {
		return sandboxes.ErrInvalid
	}
	parent, err := root.Lstat(".")
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return sandboxes.ErrInvalid
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid || owner.Gid != gid {
		return sandboxes.ErrInvalid
	}
	info, err := root.Lstat("control.sock")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	valid := func(info os.FileInfo) bool {
		if info == nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
			return false
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		return ok && owner.Uid == uid && owner.Gid == gid
	}
	if err != nil || !valid(info) {
		return sandboxes.ErrInvalid
	}
	conn, err := net.DialTimeout("unix", filepath.Join(root.Name(), "control.sock"), 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return sandboxes.ErrInvalid
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return sandboxes.ErrInvalid
	}
	current, err := root.Lstat("control.sock")
	if err != nil || !valid(current) || !os.SameFile(info, current) {
		return sandboxes.ErrInvalid
	}
	return root.Remove("control.sock")
}
