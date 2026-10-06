//go:build linux || darwin

package serveraccess

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const recordingDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// Walk from an already-open directory capability. Every component is opened
// atomically without following symlinks, including aliases within the same root.
// No security decision relies on an earlier pathname Lstat result.
func recordingWalkDirectory(fd int, parts []string, create bool) (int, error) {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\x00") {
			unix.Close(fd)
			return -1, invalidStorage()
		}
		next, err := unix.Openat(fd, part, recordingDirectoryFlags, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return -1, err
			}
			// Commit the newly-created directory entry before writing children.
			if err = unix.Fsync(fd); err != nil {
				unix.Close(fd)
				return -1, err
			}
			next, err = unix.Openat(fd, part, recordingDirectoryFlags, 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}
func (f *filesystemRecordingStore) parentDirectory(key string, create bool) (int, error) {
	fd, err := unix.Open("/", recordingDirectoryFlags, 0)
	if err != nil {
		return -1, storageUnavailable()
	}
	fd, err = recordingWalkDirectory(fd, strings.Split(strings.TrimPrefix(f.c.Path, "/"), "/"), false)
	// A missing configured mount is a storage failure, not an already-deleted key.
	if err != nil {
		return -1, storageUnavailable()
	}
	return recordingWalkDirectory(fd, strings.Split(path.Dir(key), "/"), create)
}
func recordingRegularEntry(fd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return storageUnavailable()
	}
	return nil
}
func (f *filesystemRecordingStore) Put(ctx context.Context, org, id uuid.UUID, seq int, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > recordingObjectLimit {
		return invalidStorage()
	}
	key, err := recordingObjectKey(f.c, org, id, seq)
	if err != nil {
		return err
	}
	fd, err := f.parentDirectory(key, true)
	if err != nil {
		return storageUnavailable()
	}
	defer unix.Close(fd)
	target := path.Base(key)
	if err = recordingRegularEntry(fd, target); err != nil && !errors.Is(err, unix.ENOENT) {
		return storageUnavailable()
	}
	tmp := ".pending-" + uuid.NewString()
	fileFD, err := unix.Openat(fd, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return storageUnavailable()
	}
	file := os.NewFile(uintptr(fileFD), tmp)
	defer func() { file.Close(); _ = unix.Unlinkat(fd, tmp, 0) }()
	n, err := file.Write(data)
	if err != nil || n != len(data) {
		return storageUnavailable()
	}
	if err = file.Sync(); err != nil {
		return storageUnavailable()
	}
	if err = file.Close(); err != nil {
		return storageUnavailable()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Both names refer to the same selected directory handle. A concurrent path
	// replacement cannot redirect this rename to a symlink target or other tenant.
	if err = unix.Renameat(fd, tmp, fd, target); err != nil {
		return storageUnavailable()
	}
	if err = unix.Fsync(fd); err != nil {
		return storageUnavailable()
	}
	return ctx.Err()
}
func (f *filesystemRecordingStore) Get(ctx context.Context, org, id uuid.UUID, seq int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := recordingObjectKey(f.c, org, id, seq)
	if err != nil {
		return nil, err
	}
	fd, err := f.parentDirectory(key, false)
	if err != nil {
		return nil, storageUnavailable()
	}
	defer unix.Close(fd)
	fileFD, err := unix.Openat(fd, path.Base(key), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, storageUnavailable()
	}
	file := os.NewFile(uintptr(fileFD), path.Base(key))
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fileFD, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > recordingObjectLimit {
		return nil, storageUnavailable()
	}
	data, err := io.ReadAll(io.LimitReader(file, recordingObjectLimit+1))
	if err != nil || len(data) > recordingObjectLimit {
		return nil, storageUnavailable()
	}
	return data, ctx.Err()
}
func (f *filesystemRecordingStore) Delete(ctx context.Context, org, id uuid.UUID, seq int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := recordingObjectKey(f.c, org, id, seq)
	if err != nil {
		return err
	}
	fd, err := f.parentDirectory(key, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return storageUnavailable()
	}
	defer unix.Close(fd)
	name := path.Base(key)
	if err = recordingRegularEntry(fd, name); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return storageUnavailable()
	}
	// unlinkat never follows the final entry, even if it changes after Fstatat.
	if err = unix.Unlinkat(fd, name, 0); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return storageUnavailable()
	}
	if err = unix.Fsync(fd); err != nil {
		return storageUnavailable()
	}
	return ctx.Err()
}
