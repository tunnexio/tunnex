package ipsec

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestDNSGuardPublicationWaitRefusesUnsafeCompletion(t *testing.T) {
	for _, kind := range []string{"absent", "failed", "unchanged", "canceled", "expired", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			f.observed.Store(`{"nftables":[]}`)
			pending := &runtimeDNSGuardCommit{previous: f.c.dnsView.Load(), done: make(chan struct{})}
			if kind != "absent" {
				f.c.dnsGuardCommit.Store(pending)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			if kind == "expired" {
				f.c.active[f.material.Manifest.ConnectionID].Authority.Invalidate()
			}
			if kind == "epoch" {
				f.c.dnsView.Load().entries[f.material.Manifest.ConnectionID].epoch.revoked.Store(true)
			}
			if kind == "unchanged" {
				pending.published = f.c.dnsView.Load()
			}
			close(pending.done)
			if _, err := f.prove(ctx); err == nil {
				t.Fatal("unsafe completion admitted proof")
			}
			if f.guardReads.Load() > 1 {
				t.Fatalf("unsafe completion retried guard %d", f.guardReads.Load())
			}
		})
	}
}

func TestDNSGuardPublicationWaitChargesOriginalContext(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	f.observed.Store(`{"nftables":[]}`)
	f.c.dnsGuardCommit.Store(&runtimeDNSGuardCommit{previous: f.c.dnsView.Load(), done: make(chan struct{})})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.prove(ctx); err == nil {
		t.Fatal("pending guard admitted proof")
	}
	if ctx.Err() == nil || time.Since(start) > time.Second || f.guardReads.Load() != 1 {
		t.Fatal("wait lost original bounded context")
	}
}

// Render a second exact manifest for the same owner. Only native inventory is
// modeled; both initial and superseding complete guard reads use production parsing.
func dnsGuardCommitReplacement(t *testing.T, f *dnsOwnerViewFixture) GuardManifest {
	t.Helper()
	a := f.c.active[f.material.Manifest.ConnectionID]
	i := guardFixture()
	i.OwnerID = f.material.Manifest.NodeID
	i.Revision++
	i.Connections[0].ID = a.Entry.Allocation.ConnectionID
	i.Connections[0].Tunnels = a.Entry.Observed
	if a.Entry.Allocation.activeTunnelCount() == 1 {
		i.Connections[0].TunnelCount = 1
	}
	i.Connections[0].Grants = a.Grants
	i.Connections[0].ReplyIngressIndices = []int{10}
	i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: a.Entry.Engines[0].ReqID, Peer: a.Entry.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	if m.Digest == f.manifest.Digest {
		t.Fatal("replacement is not distinct")
	}
	return m
}

func TestDNSGuardPublicationDuringReadAndWait(t *testing.T) {
	for _, kind := range []string{"before-read", "during-read", "canceled", "original-authority", "epoch", "grants"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			replacement := dnsGuardCommitReplacement(t, f)
			pending := &runtimeDNSGuardCommit{previous: f.c.dnsView.Load(), done: make(chan struct{})}
			if kind != "during-read" {
				f.c.dnsGuardCommit.Store(pending)
			}
			entered := make(chan struct{})
			oldRun := f.c.guard.reader.run
			f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if f.guardReads.Load() == 0 {
					if kind == "during-read" {
						f.c.dnsGuardCommit.Store(pending)
					}
					f.observed.Store(replacement.ExpectedJSON)
					close(entered)
				}
				return oldRun(ctx, args...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := f.prove(ctx); result <- err }()
			<-entered
			select {
			case err := <-result:
				t.Fatalf("proof did not wait for publication: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			id := f.material.Manifest.ConnectionID
			switch kind {
			case "canceled":
				cancel()
			case "original-authority":
				original := f.c.active[id].Authority
				a := f.c.active[id]
				a.Authority = dnsTestAuthority(t, a.Identity)
				f.c.active[id] = a
				original.Invalidate()
			case "epoch":
				f.c.dnsView.Load().entries[id].epoch.revoked.Store(true)
			case "grants":
				a := f.c.active[id]
				a.Grants = nil
				f.c.active[id] = a
			}
			f.manifest = replacement
			f.publish(t)
			pending.published = f.c.dnsView.Load()
			close(pending.done)
			err := <-result
			positive := kind == "before-read" || kind == "during-read"
			if positive && err != nil {
				t.Fatal("exact published guard refused", err)
			}
			if !positive && err == nil {
				t.Fatal("revoked original proof admitted")
			}
			expected := int32(1)
			if positive {
				expected = 3
			}
			if f.guardReads.Load() != expected {
				t.Fatalf("guard reads %d want%d", f.guardReads.Load(), expected)
			}
			if f.nativeProofs.Load() != 1 {
				t.Fatal("native proof repeated")
			}
		})
	}
}

func TestDNSGuardCommitBindsExactTransition(t *testing.T) {
	for _, kind := range []string{"unbounded", "previous-nil", "previous-namespace", "previous-owner", "previous-epoch", "previous-inputs", "result-nil", "result-pointer", "result-namespace", "result-owner", "second-publication"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			id := f.material.Manifest.ConnectionID
			previous := f.c.dnsView.Load()
			owner := previous.entries[id]
			copyPrevious := *previous
			copyPrevious.entries = map[uuid.UUID]runtimeDNSOwnerEntry{id: owner}
			commit := &runtimeDNSGuardCommit{previous: &copyPrevious, done: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "unbounded" {
				ctx = context.Background()
			}
			switch kind {
			case "previous-nil":
				commit.previous = nil
			case "previous-namespace":
				copyPrevious.guard.Namespace = "net:[1]"
			case "previous-owner":
				copyPrevious.guard.OwnerID = uuid.New()
			case "previous-epoch":
				x := owner
				x.epoch = &runtimeDNSEpoch{}
				copyPrevious.entries[id] = x
			case "previous-inputs":
				x := owner
				x.active.Grants = nil
				copyPrevious.entries[id] = x
			}
			result := make(chan string, 1)
			go func() {
				a := owner.active
				result <- f.c.revalidateDNSGuardSnapshotDigest(ctx, id, owner, previous, a.Entry, 10, a.Entry.Engines[0].ReqID, commit)
			}()
			select {
			case got := <-result:
				if kind == "unbounded" || strings.HasPrefix(kind, "previous-") {
					if got != "" {
						t.Fatal("invalid prior admitted")
					}
					return
				}
				t.Fatal("valid prior did not await commit")
			case <-time.After(20 * time.Millisecond):
			}
			if kind == "unbounded" || strings.HasPrefix(kind, "previous-") {
				t.Fatal("invalid prior waited")
			}
			replacement := dnsGuardCommitReplacement(t, f)
			f.manifest = replacement
			f.observed.Store(replacement.ExpectedJSON)
			f.publish(t)
			published := f.c.dnsView.Load()
			commit.published = published
			switch kind {
			case "result-nil":
				commit.published = nil
			case "result-pointer":
				copyResult := *published
				commit.published = &copyResult
			case "result-namespace":
				copyResult := *published
				copyResult.guard.Namespace = "net:[1]"
				f.c.dnsView.Store(&copyResult)
				commit.published = &copyResult
			case "result-owner":
				copyResult := *published
				copyResult.guard.OwnerID = uuid.New()
				f.c.dnsView.Store(&copyResult)
				commit.published = &copyResult
			case "second-publication":
				oldRun := f.c.guard.reader.run
				f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
					raw, e := oldRun(ctx, args...)
					copyResult := *published
					f.c.dnsView.Store(&copyResult)
					return raw, e
				}
			}
			close(commit.done)
			if got := <-result; got != "" {
				t.Fatal("invalid result admitted")
			}
			expected := int32(0)
			if kind == "second-publication" {
				expected = 1
			}
			if f.guardReads.Load() != expected {
				t.Fatal("invalid transition read beyond budget", f.guardReads.Load())
			}
		})
	}
}

func TestDNSGuardCommitSingleInFlight(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	first := f.c.beginDNSGuardCommit()
	if first == nil || first.previous != f.c.dnsView.Load() {
		t.Fatal("missing exact prior view")
	}
	if f.c.beginDNSGuardCommit() != nil {
		t.Fatal("overlapping replacement admitted")
	}
	f.c.finishDNSGuardCommit(first)
	select {
	case <-first.done:
	default:
		t.Fatal("completion not closed")
	}
	if f.c.dnsGuardCommit.Load() != nil {
		t.Fatal("completed commit retained")
	}
}
