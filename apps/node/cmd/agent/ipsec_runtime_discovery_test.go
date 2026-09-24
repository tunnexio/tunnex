package main

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

type runtimeDiscoveryFake struct {
	pages []ipsec.RuntimePendingPage
	calls int
}

func (f *runtimeDiscoveryFake) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}
func TestIPsecRuntimeDiscoveryOptoutAndCleanup(t *testing.T) {
	org, node, id := uuid.New(), uuid.New(), uuid.New()
	f := &runtimeDiscoveryFake{pages: []ipsec.RuntimePendingPage{{OrgID: org, NodeID: node}}}
	p, cleanup, e := discoverIPsecRuntime(context.Background(), f)
	if e != nil || p.IPsecEnabled || cleanup {
		t.Fatal("defaultoff lost")
	}
	first := ipsec.RuntimePendingPage{OrgID: org, NodeID: node, Items: []ipsec.RuntimePending{{ConnectionID: id, DesiredRevision: 1, Kind: "apply"}}, NextCursor: &id}
	second := ipsec.RuntimePendingPage{OrgID: org, NodeID: node, Items: []ipsec.RuntimePending{{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "cleanup"}}}
	f = &runtimeDiscoveryFake{pages: []ipsec.RuntimePendingPage{first, second}}
	_, cleanup, e = discoverIPsecRuntime(context.Background(), f)
	if e != nil || !cleanup || f.calls != 2 {
		t.Fatal("optout cleanup hidden", e)
	}
	second.NodeID = uuid.New()
	f = &runtimeDiscoveryFake{pages: []ipsec.RuntimePendingPage{first, second}}
	if _, _, e = discoverIPsecRuntime(context.Background(), f); e == nil {
		t.Fatal("mixed identity accepted")
	}
}
