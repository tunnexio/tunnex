package sandboxes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

type startProvider struct {
	status      sandboxruntime.Status
	creates     int
	uncertain   bool
	afterCreate func()
}

func (p *startProvider) Create(_ context.Context, spec sandboxruntime.Spec) error {
	p.creates++
	hash, _ := sandboxruntime.Fingerprint(spec)
	p.status = sandboxruntime.Status{RuntimeID: strings.Repeat("b", 64), ImageDigest: spec.ImageDigest, SpecHash: hash, Exists: true}
	if p.afterCreate != nil {
		p.afterCreate()
	}
	if p.uncertain {
		return sandboxruntime.ErrUnavailable
	}
	return nil
}
func (p *startProvider) Inspect(context.Context, uuid.UUID) (sandboxruntime.Status, error) {
	if !p.status.Exists {
		return p.status, sandboxruntime.ErrMissing
	}
	return p.status, nil
}
func (p *startProvider) Start(context.Context, uuid.UUID) error {
	panic("quarantine reconciler must not start")
}
func (p *startProvider) Stop(context.Context, uuid.UUID) error   { return nil }
func (p *startProvider) Delete(context.Context, uuid.UUID) error { return nil }

func TestQuarantinedStartPostgresRecoversUncertainCreateWithoutReplacement(t *testing.T) {
	f := newFixture(t)
	out, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("recovery"))
	if err != nil {
		t.Fatal(err)
	}
	p := &startProvider{uncertain: true}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); !errors.Is(err, sandboxruntime.ErrUnavailable) {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, out.Identity.ID)
	if err != nil || current.State != StateStarting || current.PeerID != nil || p.creates != 1 {
		t.Fatal("uncertain creation replaced or reported ready", current, err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); err != nil || p.creates != 1 {
		t.Fatal("retry not idempotent", err)
	}
	p.status.RuntimeID = strings.Repeat("c", 64)
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); !errors.Is(err, ErrConflict) {
		t.Fatal("replacement identity admitted", err)
	}
	p.status.Exists = false
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); !errors.Is(err, ErrConflict) || p.creates != 1 {
		t.Fatal("missing bound runtime recreated", err)
	}
}

func TestQuarantinedStartPostgresAdmissionAndStopRace(t *testing.T) {
	f := newFixture(t)
	out, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("race"))
	if err != nil {
		t.Fatal(err)
	}
	p := &startProvider{afterCreate: func() {
		if _, e := f.store.SetDesired(f.ctx, f.org, f.user, out.Identity.ID, out.Revision, "stopped"); e != nil {
			t.Fatal(e)
		}
	}}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, p); !errors.Is(err, ErrConflict) {
		t.Fatal("stale completion won stop race", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, out.Identity.ID)
	if err != nil || current.DesiredState != "stopped" || current.State == StateReady {
		t.Fatal(current, err)
	}
	// Removed creator cannot reach provider create even using a trusted worker.
	other, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("revoked"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	p = &startProvider{}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, other.Identity.ID, p); !errors.Is(err, ErrForbidden) || p.creates != 0 {
		t.Fatal("revoked creator reached provider", err)
	}
}
