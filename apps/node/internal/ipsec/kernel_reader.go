package ipsec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const kernelOutputLimit = 1 << 20
const kernelReadTimeout = 5 * time.Second

// ErrKernelRead deliberately excludes command output and underlying OS errors.
var ErrKernelRead = errors.New("IPsec kernel inventory could not be read")

// KernelReader collects partial kernel facts in the current network namespace.
// It never proves snapshot consistency, ownership, enforcement or runtime readiness.
type KernelReader struct {
	run       func(context.Context, ...string) ([]byte, error)
	namespace func() (string, error)
}

// NewKernelReader accepts a trusted absolute executable path from the node's
// composition root, not provider input. It never uses a shell or searches PATH.
func NewKernelReader(ipPath string) (*KernelReader, error) {
	if !filepath.IsAbs(ipPath) {
		return nil, ErrKernelRead
	}
	return &KernelReader{
		run: func(ctx context.Context, args ...string) ([]byte, error) {
			return runKernelCommand(ctx, ipPath, args...)
		},
		namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") },
	}, nil
}

func (r *KernelReader) Read(ctx context.Context) (KernelInventory, error) {
	if r == nil || r.run == nil || r.namespace == nil || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	before, err := r.namespace()
	if err != nil || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	links, err := r.run(ctx, "-j", "-d", "link", "show")
	if err != nil || len(links) > kernelOutputLimit || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	routes, err := r.run(ctx, "-j", "-d", "-N", "-4", "route", "show", "table", "all")
	if err != nil || len(routes) > kernelOutputLimit || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	after, err := r.namespace()
	if err != nil || before != after || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	inventory, err := ParseKernelInventory(before, links, routes)
	if err != nil || ctx.Err() != nil {
		return KernelInventory{}, ErrKernelRead
	}
	return inventory, nil
}

type kernelOutput struct{ buffer bytes.Buffer }

func (b *kernelOutput) Write(p []byte) (int, error) {
	if len(p) > kernelOutputLimit-b.buffer.Len() {
		return 0, ErrKernelRead
	}
	return b.buffer.Write(p)
}

func runKernelCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var output kernelOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return nil, ErrKernelRead
	}
	return output.buffer.Bytes(), nil
}
