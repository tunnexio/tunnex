package ipsec

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

var ErrGuardRead = errors.New("IPsec guard could not be verified")

// GuardReader only observes the current namespace. Successful Check does not
// install or renew authority, prove SA ownership, or acknowledge cleanup.
type GuardReader struct {
	run        func(context.Context, ...string) ([]byte, error)
	namespace  func() (string, error)
	interfaces func() ([]GuardInterface, error)
}

// nftPath is a trusted absolute executable from the composition root.
func NewGuardReader(nftPath string) (*GuardReader, error) {
	if !filepath.IsAbs(nftPath) {
		return nil, ErrGuardRead
	}
	return &GuardReader{
		run: func(ctx context.Context, args ...string) ([]byte, error) {
			return runKernelCommand(ctx, nftPath, args...)
		},
		namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") },
		interfaces: func() ([]GuardInterface, error) {
			links, err := net.Interfaces()
			if err != nil {
				return nil, ErrGuardRead
			}
			out := make([]GuardInterface, 0, len(links))
			for _, link := range links {
				out = append(out, GuardInterface{Name: link.Name, Index: link.Index})
			}
			return out, nil
		},
	}, nil
}

// Check compares a trusted RenderGuard manifest with a bounded complete table
// listing bracketed by namespace/interface observations. The owning controller
// must separately serialize mutations and check its monotonic lease deadline.
func (r *GuardReader) Check(ctx context.Context, manifest GuardManifest) error {
	if r == nil || r.run == nil || r.namespace == nil || r.interfaces == nil || ctx.Err() != nil || !validKernelNamespace(manifest.Namespace) {
		return ErrGuardRead
	}
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	before, err := r.namespace()
	if err != nil || before != manifest.Namespace || ctx.Err() != nil {
		return ErrGuardRead
	}
	links, err := r.interfaces()
	if err != nil || len(links) > kernelEntryLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	observed, err := r.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
	if err != nil || len(observed) > kernelOutputLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	afterLinks, err := r.interfaces()
	if err != nil || len(afterLinks) > kernelEntryLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	after, err := r.namespace()
	if err != nil || after != before || ctx.Err() != nil {
		return ErrGuardRead
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	sort.Slice(afterLinks, func(i, j int) bool { return afterLinks[i].Index < afterLinks[j].Index })
	if !reflect.DeepEqual(links, afterLinks) || VerifyGuardReadbackWithInterfaces([]byte(manifest.ExpectedJSON), observed, links) != nil || ctx.Err() != nil {
		return ErrGuardRead
	}
	return nil
}
