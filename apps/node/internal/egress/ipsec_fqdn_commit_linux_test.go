//go:build linux

package egress

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestIPsecFQDNBridgeOnlyFollowsActualDurablePolicyCommit(t *testing.T) {
	m := New("wg0")
	path := filepath.Join(t.TempDir(), "baseline.json")
	m.SetFQDNBaselinePath(path)
	p := &nodepolicy.Compiled{Version: 9, NodeID: "owned-node", Mode: nodepolicy.ModeEnforcing, FQDNGenerations: []nodepolicy.FQDNGeneration{{ResourceID: "resource", Name: "private.example.test", Generation: "committed", Answers: []string{"10.20.0.9"}}}}
	events := []string{}
	m.SetFQDNPolicyCallbacks(func(_ context.Context, got *nodepolicy.Compiled) error {
		if got != p {
			t.Fatal("desired candidate detached from actual apply")
		}
		if !m.mu.TryLock() {
			t.Fatal("runtime withdrawal entered under egress lock")
		}
		m.mu.Unlock()
		events = append(events, "withdraw")
		return nil
	}, func(got *nodepolicy.Compiled) {
		if got != p {
			t.Fatal("committed candidate changed")
		}
		if m.mu.TryLock() {
			m.mu.Unlock()
			t.Fatal("unexpected commit seam lock")
		}
		base, err := readFQDNBaseline(path)
		if err != nil || base.State != "committed" {
			t.Fatal("bridge published pending or missing baseline", err)
		}
		seen, known := readFQDNHistory(path + ".history")
		if !seen || !known {
			t.Fatal("bridge preceded durable FQDN history")
		}
		events = append(events, "commit")
	})
	m.apply = func(context.Context, string) error { events = append(events, "nft"); return nil }
	m.SetPolicy(p)
	if err := m.applyAndTrack(context.Background(), "exact-owned-rules", p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"withdraw", "nft", "commit"}) {
		t.Fatal("positive publication order", events)
	}
	// A failed nft apply may retain the old kernel rules, but the callback may
	// only retract; it cannot manufacture a new successfully applied view.
	events = nil
	m.apply = func(context.Context, string) error {
		events = append(events, "nft")
		return errors.New("native refusal")
	}
	if err := m.applyAndTrack(context.Background(), "next-rules", p); err == nil {
		t.Fatal("native failure hidden")
	}
	if !reflect.DeepEqual(events, []string{"withdraw", "nft"}) {
		t.Fatal("failed apply published positive view", events)
	}
	if _, err := readFQDNBaseline(path); err == nil {
		t.Fatal("strict reader trusted failed pending swap")
	}
	raw, err := os.ReadFile(path)
	var pending fqdnBaselineFile
	if err != nil || json.Unmarshal(raw, &pending) != nil || pending.State != "pending" {
		t.Fatal("failed swap lost pending marker", err)
	}
}

func TestIPsecFQDNWithdrawalFailureStopsOrdinarySwapAndTeardown(t *testing.T) {
	m := New("wg0")
	calls := 0
	m.apply = func(context.Context, string) error { calls++; return nil }
	m.SetFQDNPolicyCallbacks(func(context.Context, *nodepolicy.Compiled) error { return errors.New("native withdrawal refused") }, func(*nodepolicy.Compiled) { t.Fatal("failed withdrawal published") })
	p := &nodepolicy.Compiled{Version: 9, Mode: nodepolicy.ModeEnforcing}
	m.SetPolicy(p)
	if err := m.applyAndTrack(context.Background(), "replacement", p); err == nil {
		t.Fatal("native withdrawal failure ignored")
	}
	m.Teardown(context.Background())
	if calls != 0 {
		t.Fatal("ordinary table changed before required IPsec denial", calls)
	}
}

func TestIPsecFQDNUnsupportedColdOrMeshPolicyCannotPublishPositive(t *testing.T) {
	for _, mode := range []string{"cold", "unsupported", "mesh"} {
		t.Run(mode, func(t *testing.T) {
			m := New("wg0")
			m.apply = func(context.Context, string) error { return nil }
			p := &nodepolicy.Compiled{Version: 9, Mode: nodepolicy.ModeEnforcing}
			if mode == "unsupported" {
				p.Version = nodepolicy.MaxSupportedVersion + 1
				m.SetPolicy(p)
			}
			if mode == "mesh" {
				p.Mesh = true
				m.SetPolicy(p)
			}
			seen := 0
			m.SetFQDNPolicyCallbacks(func(_ context.Context, got *nodepolicy.Compiled) error {
				if got != nil {
					t.Fatal("unqualified desired policy admitted")
				}
				return nil
			}, func(got *nodepolicy.Compiled) {
				seen++
				if got != nil {
					t.Fatal("deny-only apply published positive")
				}
			})
			if err := m.applyAndTrack(context.Background(), "deny-or-mesh", p); err != nil {
				t.Fatal(err)
			}
			if seen != 1 {
				t.Fatal("missing explicit withdrawal commit")
			}
		})
	}
}
