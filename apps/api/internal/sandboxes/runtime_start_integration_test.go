package sandboxes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

type runningProvider struct {
	startProvider
	starts, stops  int
	uncertainStart bool
	afterStart     func()
}

func (p *runningProvider) Start(context.Context, uuid.UUID) error {
	p.starts++
	p.status.Running = true
	if p.afterStart != nil {
		p.afterStart()
	}
	if p.uncertainStart {
		return sandboxruntime.ErrUnavailable
	}
	return nil
}
func (p *runningProvider) Stop(context.Context, uuid.UUID) error {
	p.stops++
	p.status.Running = false
	return nil
}

func TestBoundRuntimePostgresStartRecoveryAndIdentity(t *testing.T) {
	f := newFixture(t)
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("runtime-start"))
	if err != nil {
		t.Fatal(err)
	}
	p := &runningProvider{}
	if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, p); !errors.Is(err, ErrConflict) || p.starts != 0 {
		t.Fatal("unbound start accepted", err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, p); err != nil {
		t.Fatal(err)
	}
	p.uncertainStart = true
	if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, p); !errors.Is(err, sandboxruntime.ErrUnavailable) {
		t.Fatal(err)
	}
	if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, p); err != nil || p.starts != 1 || p.creates != 1 {
		t.Fatal("uncertain start replaced or restarted", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.State != StateStarting || current.PeerID != nil {
		t.Fatal("provider running became ready", current, err)
	}
	p.status.RuntimeID = strings.Repeat("c", 64)
	if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, p); !errors.Is(err, ErrConflict) || p.starts != 1 {
		t.Fatal("replacement runtime accepted", err)
	}
}

func TestBoundRuntimePostgresStopRaceStopsStartedResource(t *testing.T) {
	f := newFixture(t)
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("runtime-race"))
	if err != nil {
		t.Fatal(err)
	}
	p := &runningProvider{}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, p); err != nil {
		t.Fatal(err)
	}
	p.afterStart = func() {
		if _, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "stopped"); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, p); !errors.Is(err, ErrConflict) || p.stops != 1 || p.status.Running {
		t.Fatal("stop lost external-start race", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.DesiredState != "stopped" || current.State == StateReady {
		t.Fatal(current, err)
	}
}
