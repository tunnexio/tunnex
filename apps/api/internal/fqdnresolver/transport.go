package fqdnresolver

import (
	"context"
	"errors"
)

// SelectedLookup is the server-side gateway transport port.  Its implementation
// belongs at the agent-control boundary: it receives the selected Site+Gateway
// IDs and must never replace them with the control-plane/public resolver.
type SelectedLookup interface {
	LookupSelected(context.Context, Context, string) ([]Response, error)
}

// WorkResolver is the scheduler-aware resolver seam. A control-plane transport
// needs the server-owned organization and resource identities in addition to
// the selected Site/Gateway pair, so it must implement this interface rather
// than deriving them from a hostname or an HTTP caller.
//
// Resolver remains supported for existing non-RPC transports and tests. The
// scheduler prefers WorkResolver when it is available.
type WorkResolver interface {
	LookupWork(context.Context, Work) ([]Response, error)
}

// ScopedSelectedLookup is the corresponding selected-transport port for
// implementations that need the complete server-derived work scope.
type ScopedSelectedLookup interface {
	LookupSelectedWork(context.Context, Work) ([]Response, error)
}

// SelectedTransport makes that restriction explicit at the Resolver boundary.
// It deliberately has no default resolver field and does not use net.Resolver.
type SelectedTransport struct{ lookup SelectedLookup }

func NewSelectedTransport(lookup SelectedLookup) *SelectedTransport {
	return &SelectedTransport{lookup: lookup}
}

func (t *SelectedTransport) Lookup(ctx context.Context, selected Context, hostname string) ([]Response, error) {
	if !selected.valid() || t == nil || t.lookup == nil {
		return nil, ErrUnboundContext
	}
	return t.lookup.LookupSelected(ctx, selected, hostname)
}

// LookupWork preserves the complete server-derived scope for a control-plane
// transport. It deliberately falls back only to the already-selected lookup,
// never to net.Resolver or a control-plane/public DNS resolver.
func (t *SelectedTransport) LookupWork(ctx context.Context, w Work) ([]Response, error) {
	if !w.Context.valid() || t == nil || t.lookup == nil {
		return nil, ErrUnboundContext
	}
	if lookup, ok := t.lookup.(ScopedSelectedLookup); ok {
		return lookup.LookupSelectedWork(ctx, w)
	}
	return t.lookup.LookupSelected(ctx, w.Context, w.Hostname)
}

// UnavailableSelectedLookup is the safe production placeholder until the
// agent-control Lane 3 request/response adapter is wired.  Starting the
// scheduler with it is intentional: selected resources fail closed, rather than
// leaking resolution to a public resolver.
type UnavailableSelectedLookup struct{}

func (UnavailableSelectedLookup) LookupSelected(context.Context, Context, string) ([]Response, error) {
	return nil, errors.New("selected gateway DNS transport is not connected")
}
