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
