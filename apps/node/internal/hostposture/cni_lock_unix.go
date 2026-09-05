//go:build linux || darwin

package hostposture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

func acquireCNIOperationLock(ctx context.Context, path string) (func(), error) {
	// A read-only fd is intentional: flock works on the same local inode through
	// the gateway's read-only hostPath mount, without journal write permission.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open existing CNI operation lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !validCNILockFile(info) {
		return nil, fmt.Errorf("CNI operation lock is not a fixed public regular file")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("wait for CNI operation lock: %w", err)
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return nil, fmt.Errorf("acquire CNI operation lock: %w", err)
		}
		if err := sleepContext(ctx, 25*time.Millisecond); err != nil {
			return nil, fmt.Errorf("wait for CNI operation lock: %w", err)
		}
	}
	live, err := os.Lstat(path)
	if err != nil || !validCNILockFile(live) || !os.SameFile(info, live) {
		return nil, fmt.Errorf("CNI operation lock identity changed")
	}
	var once sync.Once
	ok = true
	return func() { once.Do(func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }) }, nil
}
