//go:build linux || darwin

package ipsec

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
func journalPrivate(info os.FileInfo, dir bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && ownedByCurrentUser(info) && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0077 == 0 && ((dir && info.IsDir()) || (!dir && info.Mode().IsRegular() && st.Nlink == 1))
}
func journalOpenNoFollow(path string, create bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags = unix.O_CREAT | unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, e := unix.Open(path, flags, 0600)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
func journalLock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func journalUnlock(f *os.File)     { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
