package beam

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

// LS-UX-1 #2: a lapse in serving checks must never stop an administrator from
// tightening or turning off an enabled policy, while turning it on still needs
// current checks and serving still denies.
func TestBeamPolicyEditsWhileServingChecksLapse(t *testing.T) {
	f := newFixture(t)
	browser := f.a
	browser.CredentialID = uuid.Nil
	browser.SessionID = "fixture-policy"
	f.create()
	f.exec(`UPDATE beam_installation_settings SET readiness_expires_at=now()-interval '1 second',readiness_checked_at=now()-interval '2 seconds' WHERE singleton`)
	p, e := f.s.policy(f.ctx, f.pool, f.org)
	if e != nil || !p.Enabled || p.DomainReady {
		t.Fatal("fixture did not lapse serving checks", p.Enabled, p.DomainReady, e)
	}
	tight := PolicyInput{Enabled: true, ExpectedVersion: p.Version, PublisherGroups: []uuid.UUID{f.group}, ReviewerUsers: []uuid.UUID{}, MaxDuration: 600, MaxShares: 1, ConfirmEndActiveShares: true}
	saved, e := f.s.UpdatePolicy(f.ctx, f.org, browser, tight)
	if e != nil || saved.MaxDuration != 600 || !saved.Enabled {
		t.Fatal("tightening an enabled policy was refused while checks lapsed", e)
	}
	if p, e = f.s.policy(f.ctx, f.pool, f.org); e != nil || f.s.publisher(f.ctx, f.pool, f.org, f.owner, p) == nil {
		t.Fatal("publishing allowed while checks lapsed", e)
	}
	off := tight
	off.Enabled, off.ExpectedVersion = false, saved.Version
	saved, e = f.s.UpdatePolicy(f.ctx, f.org, browser, off)
	if e != nil || saved.Enabled {
		t.Fatal("turning the policy off was refused while checks lapsed", e)
	}
	on := off
	on.Enabled, on.ExpectedVersion = true, saved.Version
	if _, e = f.s.UpdatePolicy(f.ctx, f.org, browser, on); e == nil {
		t.Fatal("policy turned on without current serving checks")
	}
}

// LS-UX-1 #9: the sharing domain must not share a hostname space with App Access.
func TestBeamInstallationDomainRefusesAppAccessOverlap(t *testing.T) {
	f := newFixture(t)
	current, e := f.s.GetDomainSettings(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.s.config.AppAccessBaseDomain = "console.fixture.org"
	overlap := func(e error) bool { return e != nil && strings.Contains(e.Error(), "overlaps the App Access domain") }
	if _, e = f.s.UpdateDomainSettings(f.ctx, f.owner, DomainSettingsInput{ExpectedVersion: current.Version, OperatorEnabled: true, BaseDomain: "console.fixture.org", ProxyURL: f.s.config.ProxyURL, ConfirmEndActiveShares: true}); !overlap(e) {
		t.Fatal("sharing domain equal to the App Access base was not refused for overlap", e)
	}
	f.exec(`INSERT INTO app_access_domain_settings(singleton,portal_url,app_base_domain,version)VALUES(true,'https://console.fixture.org','apps.beam.other.net',1) ON CONFLICT (singleton) DO UPDATE SET app_base_domain=EXCLUDED.app_base_domain`)
	f.s.config.AppAccessBaseDomain = ""
	if _, e = f.s.UpdateDomainSettings(f.ctx, f.owner, DomainSettingsInput{ExpectedVersion: current.Version, OperatorEnabled: true, BaseDomain: "beam.other.net", ProxyURL: "https://connector2.beam.other.net", ConfirmEndActiveShares: true}); !overlap(e) {
		t.Fatal("sharing domain containing the saved App Access base was not refused for overlap", e)
	}
	if _, e = f.s.UpdateDomainSettings(f.ctx, f.owner, DomainSettingsInput{ExpectedVersion: current.Version, OperatorEnabled: true, BaseDomain: "share.independent.net", ProxyURL: "https://connector2.beam.other.net", ConfirmEndActiveShares: true}); e != nil {
		t.Fatal("independent sharing domain refused", e)
	}
}

func TestBeamDomainOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"a.example.net", "a.example.net", true}, {"x.a.example.net", "a.example.net", true}, {"a.example.net", "x.a.example.net", true}, {"ba.example.net", "a.example.net", false}, {"a.example.net", "", false}, {"share.other.net", "cp.example.net", false}} {
		if got := domainsOverlap(c.a, c.b); got != c.want {
			t.Fatal(c.a, c.b, got)
		}
	}
}

// LS-UX-1: the reverse direction, an App Access base saved over the Local Sharing domain.
func TestAppAccessDomainRefusesLocalSharingOverlap(t *testing.T) {
	f := newFixture(t)
	domains := appdomains.New(f.pool, appdomains.Config{})
	save := func(base string) error {
		v, e := domains.Get(context.Background())
		if e != nil {
			return e
		}
		_, e = domains.Save(f.ctx, f.owner, appdomains.Update{ExpectedVersion: v.Version, PortalURL: "https://console.fixture.org", AppBaseDomain: base})
		return e
	}
	if e := save("apps.beam.other.net"); e == nil || !strings.Contains(e.Error(), "overlaps the Local Sharing domain") {
		t.Fatal("App Access base nested in the sharing domain was not refused", e)
	}
	if e := save("apps.independent.net"); e != nil {
		t.Fatal("independent App Access base refused", e)
	}
}
