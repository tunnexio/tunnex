//go:build linux

package hostposture

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type ProcessLock struct{ file *os.File }

func AcquireProcessLock(path string) (*ProcessLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open host-posture process lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another host-posture manager owns this node journal: %w", err)
	}
	return &ProcessLock{file: f}, nil
}

func (l *ProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
