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

// UnavailableSelectedLookup is the safe production placeholder until the
// agent-control Lane 3 request/response adapter is wired.  Starting the
// scheduler with it is intentional: selected resources fail closed, rather than
// leaking resolution to a public resolver.
type UnavailableSelectedLookup struct{}

func (UnavailableSelectedLookup) LookupSelected(context.Context, Context, string) ([]Response, error) {
	return nil, errors.New("selected gateway DNS transport is not connected")
}
