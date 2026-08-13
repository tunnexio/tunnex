//go:build !linux

package flowlog

import (
	"context"
	"errors"
)

// DefaultNflogSockBuf keeps the const available to non-linux builds (cross-compile).
const DefaultNflogSockBuf = 4 * 1024 * 1024

// NflogSource is a non-linux stub — the agent runs on Linux gateways; this only lets other
// platforms compile. Flow logging is unavailable off Linux.
type NflogSource struct{}

// NewNflogSource is unavailable off Linux (nflog is a Linux-kernel facility).
func NewNflogSource(_ context.Context, _, _ int) (*NflogSource, error) {
	return nil, errors.New("flowlog: the nflog source is Linux-only")
}

func (s *NflogSource) Records() <-chan Record { return nil }
func (s *NflogSource) Overruns() int64        { return 0 }
func (s *NflogSource) Close() error           { return nil }
