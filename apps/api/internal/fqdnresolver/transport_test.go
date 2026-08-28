package fqdnresolver

import (
	"context"
	"errors"
	"testing"
)

type selectedLookupFunc func(context.Context, Context, string) ([]Response, error)

func (f selectedLookupFunc) LookupSelected(ctx context.Context, c Context, host string) ([]Response, error) {
	return f(ctx, c, host)
}

func TestSelectedTransportPassesOnlyServerSelectedPair(t *testing.T) {
	want := selected
	transport := NewSelectedTransport(selectedLookupFunc(func(_ context.Context, got Context, _ string) ([]Response, error) {
		if got != want {
			t.Fatalf("selected context = %#v, want %#v", got, want)
		}
		return []Response{{Status: StatusNXDOMAIN}}, nil
	}))
	if _, err := transport.Lookup(context.Background(), want, "db.internal"); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Lookup(context.Background(), Context{}, "db.internal"); !errors.Is(err, ErrUnboundContext) {
		t.Fatalf("unbound lookup err=%v, want ErrUnboundContext", err)
	}
}

func TestUnavailableSelectedTransportHasNoFallback(t *testing.T) {
	_, err := NewSelectedTransport(UnavailableSelectedLookup{}).Lookup(context.Background(), selected, "db.internal")
	if err == nil || errors.Is(err, ErrUnboundContext) {
		t.Fatalf("unavailable selected transport must fail the selected lookup, got %v", err)
	}
}
