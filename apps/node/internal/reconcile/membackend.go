package reconcile

import (
	"context"
	"sync"
)

// MemBackend is an in-memory WGBackend used by the S3.1 agent (the real wgctrl
// adapter arrives with the WireGuard device lifecycle in S3.2). It lets the full
// enroll->reconcile loop run end-to-end without NET_ADMIN or a WG device.
type MemBackend struct {
	mu     sync.Mutex
	peers  []Peer
	routes []string
}

// NewMemBackend returns an empty in-memory backend.
func NewMemBackend() *MemBackend { return &MemBackend{} }

// Configure records the interface config (no real device in the in-memory backend).
func (m *MemBackend) Configure(context.Context, InterfaceConfig) error { return nil }

func (m *MemBackend) Peers(context.Context) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// R2 fixture-fidelity: the real kernel read path cannot express SiteLink → strip it on read.
	out := make([]Peer, len(m.peers))
	for i, p := range m.peers {
		p.SiteLink = false
		out[i] = p
	}
	return out, nil
}

func (m *MemBackend) ApplyPeers(_ context.Context, peers []Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = append([]Peer(nil), peers...)
	return nil
}

// ApplyRoutes records the desired route set (the in-memory backend has no kernel FIB).
func (m *MemBackend) ApplyRoutes(_ context.Context, cidrs []string, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append([]string(nil), cidrs...)
	return nil
}

// Stats returns no telemetry (the in-memory backend has no real device).
func (m *MemBackend) Stats(context.Context) ([]PeerStat, error) { return nil, nil }

// Close is a no-op for the in-memory backend — no real interface to tear down (WF-C Layer 1).
func (m *MemBackend) Close(context.Context) error { return nil }
