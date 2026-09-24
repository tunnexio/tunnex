//go:build linux

package ipsec

import (
	"context"
	conntrack "github.com/florianl/go-conntrack"
	"io"
	"log"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The dependency allocates its dump before returning. The count precheck and
// postcheck bound supported workloads, not concurrent kernel growth allocations.
// No host-global conntrack limits are changed by this adapter.
func runtimeDrainConntrack(ctx context.Context, entries []RuntimeJournalEntry) error {
	// Bind socket creation to this verified thread namespace without setns,
	// which would require CAP_SYS_ADMIN merely to re-enter the same namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, e := os.Readlink("/proc/thread-self/ns/net")
	if e != nil {
		return ErrRuntimeEnvironment
	}
	if len(entries) > 64 {
		return ErrRuntimeEnvironment
	}
	for _, entry := range entries {
		if entry.Allocation.Namespace != ns || !validKernelAllocation(entry.Allocation) {
			return ErrRuntimeEnvironment
		}
		for _, engine := range entry.Engines {
			if !validEngineTunnel(engine) {
				return ErrRuntimeEnvironment
			}
		}
	}
	count, e := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if e != nil {
		return ErrRuntimeEnvironment
	}
	n, e := strconv.Atoi(strings.TrimSpace(string(count)))
	if e != nil || n < 0 || n > 4096 {
		return ErrRuntimeEnvironment
	}
	c, e := conntrack.Open(&conntrack.Config{WriteTimeout: time.Second, Logger: log.New(io.Discard, "", 0)})
	if e != nil {
		return ErrRuntimeEnvironment
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if e = c.Con.SetDeadline(deadline); e != nil {
		return ErrRuntimeEnvironment
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	for pass := 0; pass < 2; pass++ {
		flows, e := c.Dump(conntrack.Conntrack, conntrack.IPv4)
		if e != nil || len(flows) > 4096 {
			return ErrRuntimeEnvironment
		}
		for _, flow := range flows {
			if ctx.Err() != nil {
				return ErrRuntimeEnvironment
			}
			match, valid := runtimeConntrackMatch(flow, entries)
			if !valid {
				return ErrRuntimeEnvironment
			}
			if !match {
				continue
			}
			if pass == 1 {
				return ErrRuntimeEnvironment
			}
			if e = c.Delete(conntrack.Conntrack, conntrack.IPv4, flow); e != nil {
				return ErrRuntimeEnvironment
			}
		}
	}
	after, e := os.Readlink("/proc/thread-self/ns/net")
	if e != nil || after != ns || ctx.Err() != nil {
		return ErrRuntimeEnvironment
	}
	return nil
}
func runtimeConntrackMatch(flow conntrack.Con, entries []RuntimeJournalEntry) (bool, bool) {
	if flow.Origin == nil || flow.Origin.Src == nil || flow.Origin.Dst == nil {
		return false, false
	}
	src, ok := netip.AddrFromSlice(*flow.Origin.Src)
	if !ok {
		return false, false
	}
	dst, ok := netip.AddrFromSlice(*flow.Origin.Dst)
	if !ok {
		return false, false
	}
	src = src.Unmap()
	dst = dst.Unmap()
	for _, entry := range entries {
		for _, engine := range entry.Engines {
			for _, local := range engine.LocalPrefixes {
				for _, remote := range engine.RemotePrefixes {
					if local.Contains(src) && remote.Contains(dst) || local.Contains(dst) && remote.Contains(src) {
						return true, true
					}
				}
			}
		}
	}
	return false, true
}
