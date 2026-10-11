//go:build !linux

package bgp

import "context"

func ProveCleanedProcessAbsent(context.Context, ProcessIdentity, bool) error  { return ErrPackage }
func ProveCleanedHistoryAbsent(context.Context, string, string, uint64) error { return ErrPackage }
