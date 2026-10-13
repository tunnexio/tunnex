package ipsec

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestDNSPendingPublicationRetainsSingleFreshRetry(t *testing.T) {
	for _, kind := range []string{"commit", "failure", "cancel", "revoked", "original_expired", "current_expired", "changed_grants", "churn", "no_pending", "wrong_predecessor", "completed", "cleared"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			id := f.material.Manifest.ConnectionID
			previous := f.c.dnsView.Load()
			owner := previous.entries[id]
			entry := owner.active.Entry
			// Native successor exists before its immutable owner view is published.
			renewDNSDiagnosticGuard(t, f)
			successor := f.c.dnsView.Load()
			f.c.dnsView.Store(previous)
			p := &runtimeDNSPublication{previous: previous, done: make(chan struct{})}
			if kind == "wrong_predecessor" {
				copy := *previous
				p.previous = &copy
			}
			if kind != "no_pending" {
				f.c.dnsPublication.Store(p)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "completed" || kind == "cleared" {
				if kind != "failure" {
					f.c.dnsView.Store(successor)
				}
				p.committed = true
				close(p.done)
				if kind == "cleared" {
					f.c.dnsPublication.Store(nil)
				}
			}
			if kind == "cancel" {
				cancel()
			}
			if kind == "churn" {
				run := f.c.guard.reader.run
				f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
					raw, e := run(ctx, args...)
					copy := *successor
					copy.guard.Digest = previous.guard.Digest
					f.c.dnsView.Store(&copy)
					return raw, e
				}
			}
			done := make(chan string, 1)
			go func() {
				done <- f.c.revalidateDNSGuardSnapshotDigest(ctx, id, owner, previous, entry, entry.Observed[0].InterfaceIndex, entry.Engines[0].ReqID)
			}()
			if kind != "no_pending" && kind != "wrong_predecessor" && kind != "completed" && kind != "cleared" {
				// Before publication there is no accepted successor and no additional read.
				select {
				case result := <-done:
					if kind != "cancel" {
						t.Fatal("returned before transaction completion", result)
					}
					done <- result
				default:
				}
				switch kind {
				case "revoked":
					owner.epoch.revoked.Store(true)
				case "original_expired":
					owner.active.Authority.Invalidate()
				case "current_expired":
					a := successor.entries[id]
					a.active.Authority = dnsTestAuthority(t, a.active.Identity)
					a.active.Authority.Invalidate()
					successor.entries[id] = a
				case "changed_grants":
					a := successor.entries[id]
					a.active.Grants = nil
					successor.entries[id] = a
				}
				if kind != "failure" {
					f.c.dnsView.Store(successor)
				}
				p.committed = kind != "failure"
				close(p.done)
			}
			result := <-done
			accepted := kind == "commit" || kind == "completed" || kind == "cleared"
			if (result != "") != accepted {
				t.Fatal("unexpected acceptance", kind, result)
			}
			if f.guardReads.Load() > 1 {
				t.Fatal("extra retry", f.guardReads.Load())
			}
		})
	}
}

func TestDNSPublicationDescriptorClearedOnInstallResult(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "replace_failure"}[failure], func(t *testing.T) {
			r, _ := azureMaintenanceRig(t, AzureActiveActiveBGPProfile)
			replace := r.c.replace
			var p *runtimeDNSPublication
			r.c.replace = func(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
				p = r.c.dnsPublication.Load()
				if p == nil {
					t.Fatal("missing descriptor")
				}
				if failure {
					return GuardManifest{}, ErrRuntimeController
				}
				return replace(ctx, intent)
			}
			err := r.c.installActive(context.Background(), r.entries)
			if (err != nil) != failure || p == nil || r.c.dnsPublication.Load() != nil {
				t.Fatal("lifecycle", err)
			}
			select {
			case <-p.done:
			default:
				t.Fatal("completion not closed")
			}
			if p.committed == failure {
				t.Fatal("wrong completion result")
			}
		})
	}
}

func TestDNSUnpublishedSuccessorProofWaitsWithinOriginalDeadline(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "original_deadline", true: "committed"}[complete], func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			previous := f.c.dnsView.Load()
			renewDNSDiagnosticGuard(t, f)
			successor := f.c.dnsView.Load()
			f.c.dnsView.Store(previous)
			p := &runtimeDNSPublication{previous: previous, done: make(chan struct{})}
			f.c.dnsPublication.Store(p)
			firstRead := make(chan struct{}, 1)
			run := f.c.guard.reader.run
			f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				raw, e := run(ctx, args...)
				if f.guardReads.Load() == 1 {
					firstRead <- struct{}{}
				}
				return raw, e
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			done := make(chan error, 1)
			go func() { _, e := f.prove(ctx); done <- e }()
			<-firstRead
			select {
			case e := <-done:
				t.Fatal("unpublished successor returned before completion", e)
			case <-time.After(10 * time.Millisecond):
			}
			if complete {
				f.c.dnsView.Store(successor)
				p.committed = true
				close(p.done)
			}
			err := <-done
			if (err == nil) != complete {
				t.Fatal("result", err)
			}
			if after, _ := ctx.Deadline(); after != deadline {
				t.Fatal("deadline extended")
			}
			if complete && f.guardReads.Load() != 3 {
				t.Fatal("strict current/final read omitted", f.guardReads.Load())
			}
			if !complete && f.guardReads.Load() != 1 {
				t.Fatal("read before publication", f.guardReads.Load())
			}
		})
	}
}

func TestDNSPublicationFailedPostReplaceQualificationCannotComplete(t *testing.T) {
	r, _ := azureMaintenanceRig(t, AzureActiveActiveBGPProfile)
	replace := r.c.replace
	var p *runtimeDNSPublication
	r.c.replace = func(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
		p = r.c.dnsPublication.Load()
		return replace(ctx, intent)
	}
	calls := 0
	err := r.c.installActiveCandidates(context.Background(), r.entries, r.c.active, nil, nil, func() bool { calls++; return calls == 1 })
	if err == nil || calls != 2 || p == nil || r.c.dnsPublication.Load() != nil {
		t.Fatal("postreplace lifecycle", err, calls)
	}
	select {
	case <-p.done:
	default:
		t.Fatal("completion missing")
	}
	if p.committed {
		t.Fatal("failed qualification completed publication")
	}
}

func TestDNSCanceledPublicationCannotSignalCommitted(t *testing.T) {
	r, _ := azureMaintenanceRig(t, AzureActiveActiveBGPProfile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replace := r.c.replace
	var p *runtimeDNSPublication
	r.c.replace = func(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
		p = r.c.dnsPublication.Load()
		m, e := replace(ctx, intent)
		cancel()
		return m, e
	}
	_ = r.c.installActive(ctx, r.entries)
	if p == nil || r.c.dnsPublication.Load() != nil {
		t.Fatal("canceled lifecycle")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("completion missing")
	}
	if p.committed {
		t.Fatal("canceled transaction signaled committed")
	}
}

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
