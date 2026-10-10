package ipsec

import (
	"context"
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
