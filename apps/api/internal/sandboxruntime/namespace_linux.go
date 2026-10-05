//go:build linux

package sandboxruntime

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// OpenNetworkNamespace pins only the exact running owned provider resource.
// Re-inspection and inode comparison fence PID reuse before SCM_RIGHTS handoff.
func (p *Podman) OpenNetworkNamespace(ctx context.Context, id uuid.UUID, runtimeID, specHash string) (*os.File, error) {
	check := func() error {
		status, err := p.Inspect(ctx, id)
		if err != nil {
			return err
		}
		if !status.Running || status.RuntimeID != runtimeID || status.SpecHash != specHash {
			return ErrOwnership
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	pidValue, err := p.runner.Run(ctx, "inspect", "--type=container", "--format={{.State.Pid}}", runtimeID)
	if err != nil {
		return nil, ErrUnavailable
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidValue)))
	if err != nil || pid <= 1 {
		return nil, ErrOwnership
	}
	path := "/proc/" + strconv.Itoa(pid) + "/ns/net"
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	fail := func(err error) (*os.File, error) { file.Close(); return nil, err }
	if err = check(); err != nil {
		return fail(err)
	}
	current, err := p.runner.Run(ctx, "inspect", "--type=container", "--format={{.State.Pid}}", runtimeID)
	if err != nil || strings.TrimSpace(string(current)) != strconv.Itoa(pid) {
		return fail(ErrOwnership)
	}
	pinned, err := file.Stat()
	if err != nil {
		return fail(ErrUnavailable)
	}
	live, err := os.Stat(path)
	if err != nil || !os.SameFile(pinned, live) {
		return fail(ErrOwnership)
	}
	return file, nil
}
