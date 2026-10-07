package beam

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/beamreadiness"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestBeamInstallationDefaultsIgnoreEnvironmentAssertion(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	s := New(pool, Config{BaseDomain: "beam.other.net", ProxyURL: "https://connector.beam.other.net", PortalURL: "https://console.fixture.org", DomainReady: true}, nil, nil)
	v, e := s.GetDomainSettings(ctx)
	if e != nil || v.OperatorEnabled || v.AuthorityReady || v.Source != "environment" || v.Version != 1 || v.BaseDomain != "beam.other.net" {
		t.Fatal("environment hints bypassed default-off installation authority", v, e)
	}
	if _, _, e = s.DomainsContext(ctx); e == nil {
		t.Fatal("environment assertion advertised serving authority")
	}
}

func TestBeamInstallationAtomicDrainStaleProofAndReplicaWithdrawal(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	lease, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	previous, e := f.s.installation(f.ctx, f.pool)
	if e != nil {
		t.Fatal(e)
	}
	proof := f.s.readinessView(previous)
	replica := New(f.pool, f.s.config, f.s.signer, f.store)
	if _, e = replica.Renew(f.ctx, r.Binding(), lease.StreamID); e != nil {
		t.Fatal("qualified second replica failed", e)
	}
	in := DomainSettingsInput{ExpectedVersion: previous.version, OperatorEnabled: true, BaseDomain: "beam.changed.net", ProxyURL: f.s.config.ProxyURL}
	if _, e = f.s.UpdateDomainSettings(f.ctx, f.owner, in); e == nil {
		t.Fatal("active shares were drained without impact confirmation")
	}
	in.ConfirmEndActiveShares = true
	updated, e := f.s.UpdateDomainSettings(f.ctx, f.owner, in)
	if e != nil || updated.Version != previous.version+1 || updated.AuthorityReady || updated.AffectedActiveShares != 0 {
		t.Fatal("namespace change did not atomically withdraw authority", updated, e)
	}
	if _, e = replica.Renew(f.ctx, r.Binding(), lease.StreamID); e == nil {
		t.Fatal("other replica cached old serving authority")
	}
	if _, e = replica.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("old connector survived a namespace change")
	}
	if _, e = f.s.persistReadiness(f.ctx, previous, proof); e == nil {
		t.Fatal("stale completed probe reactivated changed configuration")
	}
	if _, e = f.s.UpdateDomainSettings(f.ctx, f.owner, in); e == nil {
		t.Fatal("stale settings version saved")
	}
	var state, host string
	if e = f.pool.QueryRow(f.ctx, `SELECT state,hostname FROM beam_shares WHERE id=$1`, r.ID).Scan(&state, &host); e != nil || state != "revoked" || host != r.Hostname {
		t.Fatal("ended share URL was rewritten or reopened", state, host, e)
	}
}

func TestBeamInstallationProofExpiryAndFailedRefreshDenyImmediately(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	rsettings, e := f.s.installation(f.ctx, f.pool)
	if e != nil {
		t.Fatal(e)
	}
	view := f.s.readinessView(rsettings)
	short := time.Now().Add(2 * time.Second)
	view.ExpiresAt = &short
	if _, e = f.s.persistReadiness(f.ctx, rsettings, view); e != nil {
		t.Fatal(e)
	}
	until, e := f.s.Channel(f.ctx, r.Binding(), *r.Serial)
	if e != nil || until.After(short) {
		t.Fatal("serving lease exceeded measured evidence expiry", until, e)
	}
	view.Passed = false
	if _, e = f.s.persistReadiness(f.ctx, rsettings, view); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("failed fresh network evidence preserved old readiness")
	}
	view.Passed = true
	if _, e = f.s.persistReadiness(f.ctx, rsettings, view); e != nil {
		t.Fatal(e)
	}
	f.exec(`UPDATE beam_installation_settings SET readiness_expires_at=now()-interval '1 second',readiness_checked_at=now()-interval '2 seconds' WHERE singleton`)
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("expired persisted evidence retained authority without a worker")
	}
	if ready, e := f.s.GetDomainSettings(f.ctx); e != nil || ready.AuthorityReady {
		t.Fatal("expired proof projected ready", ready, e)
	}
}

func TestBeamInstallationCurrentTrustAndPortalBindEveryDecision(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	otherPortal := f.s.config
	otherPortal.PortalURL = "https://changed.fixture.org"
	replica := New(f.pool, otherPortal, f.s.signer, f.store)
	if _, e := replica.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("a replica with different portal reused old proof")
	}
	replica = New(f.pool, f.s.config, f.s.signer, f.store)
	replica.SetReadinessInspector(beamreadiness.New())
	if _, e := replica.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("changed inspector trust profile reused old proof")
	}
}

func TestBeamInstallationSaveSerializesResourceCreation(t *testing.T) {
	f := newFixture(t)
	settings, e := f.s.GetDomainSettings(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	var workers sync.WaitGroup
	createResult := make(chan error, 1)
	saveResult := make(chan error, 1)
	workers.Add(2)
	go func() {
		defer workers.Done()
		_, e := f.s.Create(f.ctx, f.org, f.a, CreateInput{Name: "Racing create", Target: Target{Protocol: "http", Address: "127.0.0.1", Port: 3000}, Duration: 120, IdempotencyKey: uuid.New()})
		createResult <- e
	}()
	go func() {
		defer workers.Done()
		_, e := f.s.UpdateDomainSettings(f.ctx, f.owner, DomainSettingsInput{ExpectedVersion: settings.Version, OperatorEnabled: false, BaseDomain: settings.BaseDomain, ProxyURL: settings.ProxyURL, ConfirmEndActiveShares: true})
		saveResult <- e
	}()
	workers.Wait()
	if e = <-saveResult; e != nil {
		t.Fatal("installation withdrawal failed", e)
	}
	createError := <-createResult
	// Depending on lock order, creation either commits then is drained or is
	// refused under the new authority. It must never remain serving afterward.
	var active int
	if e = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM beam_shares WHERE state IN ('starting','active','paused')`).Scan(&active); e != nil || active != 0 {
		t.Fatal("installation save missed a concurrent resource create", active, e)
	}
	if createError != nil {
		var known *apierr.Error
		if !errors.As(createError, &known) || known.Code != "beam_unavailable" {
			t.Fatal("creation failed outside the expected authority withdrawal", createError)
		}
	}
	current, e := f.s.GetDomainSettings(f.ctx)
	if e != nil || current.OperatorEnabled {
		t.Fatal("installation withdrawal was not persisted", current, e)
	}
}
