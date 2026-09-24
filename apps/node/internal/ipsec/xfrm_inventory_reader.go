package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

var ErrXFRMRead = errors.New("IPsec no-key XFRM inventory could not be read")

// XFRMReader reads partial global policy and no-key SA inventory. Socket
// policies are explicitly excluded; this cannot prove absence of bypass,
// snapshot consistency, freshness or ownership. No key-bearing command exists.
type XFRMReader struct {
	run       func(context.Context, ...string) ([]byte, error)
	namespace func() (string, error)
}

func NewXFRMReader(ipPath string) (*XFRMReader, error) {
	if !filepath.IsAbs(ipPath) {
		return nil, ErrXFRMRead
	}
	return &XFRMReader{run: func(ctx context.Context, args ...string) ([]byte, error) {
		return runKernelCommand(ctx, ipPath, args...)
	}, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }}, nil
}
func (r *XFRMReader) Read(ctx context.Context) (XFRMInventory, error) {
	fail := func() (XFRMInventory, error) { return XFRMInventory{}, ErrXFRMRead }
	if r == nil || r.run == nil || r.namespace == nil || ctx.Err() != nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	before, err := r.namespace()
	if err != nil || !validKernelNamespace(before) || ctx.Err() != nil {
		return fail()
	}
	states, err := r.run(ctx, "xfrm", "state", "list", "nokeys")
	if err != nil || len(states) > kernelOutputLimit || ctx.Err() != nil {
		return fail()
	}
	policies, err := r.run(ctx, "xfrm", "policy", "list", "nosock")
	if err != nil || len(policies) > kernelOutputLimit || ctx.Err() != nil {
		return fail()
	}
	after, err := r.namespace()
	if err != nil || after != before || ctx.Err() != nil {
		return fail()
	}
	got, err := ParseXFRMInventory(before, states, policies)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	return got, nil
}
