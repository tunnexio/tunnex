//go:build !linux

package hostposture

import (
	"context"
	"fmt"
)

type CommandRunner interface{}
type LinuxKernel struct{}

func NewLinuxKernel(string, CommandRunner) (*LinuxKernel, error) {
	return nil, fmt.Errorf("host-posture manager requires Linux")
}
func (*LinuxKernel) CaptureBaseline(context.Context, string) ([]SysctlReceipt, error) {
	return nil, fmt.Errorf("host-posture manager requires Linux")
}
func (*LinuxKernel) Prepare(context.Context, *Journal, func(*Journal) error) error {
	return fmt.Errorf("host-posture manager requires Linux")
}
func (*LinuxKernel) Enforce(context.Context, Journal) error {
	return fmt.Errorf("host-posture manager requires Linux")
}
func (*LinuxKernel) RestoreAndCleanup(context.Context, *Journal) error {
	return fmt.Errorf("host-posture manager requires Linux")
}
