package sandboxruntime

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
)

// RootlessRunner uses only supervised worker-owned state/run directories and
// existing runc/cgroupfs/native overlay. No login session, DBus or host socket.
type RootlessRunner struct{ Root, RunRoot, Home string }

func (r RootlessRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	return r.RunInput(ctx, nil, args...)
}
func (r RootlessRunner) RunInput(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 || !filepath.IsAbs(r.Root) || filepath.Clean(r.Root) != r.Root || r.Root == "/" || !filepath.IsAbs(r.RunRoot) || filepath.Clean(r.RunRoot) != r.RunRoot || r.RunRoot == "/" || r.Root == r.RunRoot {
		return nil, ErrInvalid
	}
	worker, err := user.Current()
	if err != nil || worker.Uid != strconv.Itoa(os.Geteuid()) || worker.HomeDir != r.Home || !filepath.IsAbs(r.Home) || filepath.Clean(r.Home) != r.Home || r.Home == "/" {
		return nil, ErrInvalid
	}
	argv := append([]string{"--root", r.Root, "--runroot", r.RunRoot, "--storage-driver=overlay", "--cgroup-manager=cgroupfs", "--runtime=/usr/bin/runc"}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/podman", argv...)
	// OS identity is supplied by the host unit. Dedicated XDG roots avoid ambient
	// user storage/config and are distinct from workload workspace mounts.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "HOME=" + r.Home, "XDG_RUNTIME_DIR=" + filepath.Dir(r.RunRoot), "XDG_CONFIG_HOME=" + filepath.Join(filepath.Dir(r.Root), "config"), "XDG_DATA_HOME=" + filepath.Join(filepath.Dir(r.Root), "data"), "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = io.Discard
	output := &runtimeOutput{limit: 262144}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type runtimeOutput struct {
	bytes.Buffer
	limit int
}

func (b *runtimeOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
