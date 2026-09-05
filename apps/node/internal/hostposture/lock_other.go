//go:build !linux

package hostposture

import "fmt"

type ProcessLock struct{}

func AcquireProcessLock(string) (*ProcessLock, error) {
	return nil, fmt.Errorf("host-posture manager requires Linux")
}

func (*ProcessLock) Close() error { return nil }
