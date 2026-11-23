//go:build !linux

package k8snetprep

import "context"

// HostFactsReader reads nothing off Linux.
type HostFactsReader struct{}

func NewHostFactsReader(NFTRunner, IPTablesRunner, IPSetRunner) *HostFactsReader {
	return &HostFactsReader{}
}

func (*HostFactsReader) Read(context.Context) HostNetFacts {
	return UnreadableHostNetFacts("Linux is required")
}

func (*Reconciler) UseHostFacts(HostFactsSource) {}

// LinkLister, CiliumStatusRunner, CiliumPinLister and BPFToolRunner exist so
// callers compile off Linux; the reader reads nothing there.
type (
	LinkLister         func() ([]string, error)
	CiliumStatusRunner func(context.Context) ([]byte, error)
	CiliumPinLister    func(context.Context) ([]string, error)
	BPFToolRunner      func(context.Context, ...string) (string, error)
)

// CiliumFactsReader reads nothing off Linux.
type CiliumFactsReader struct{}

func NewCiliumFactsReader(LinkLister, CiliumStatusRunner, CiliumPinLister, BPFToolRunner) *CiliumFactsReader {
	return &CiliumFactsReader{}
}

func (*CiliumFactsReader) Read(context.Context) *CiliumFacts { return nil }

func (*Reconciler) UseCiliumFacts(CiliumFactsSource) {}
