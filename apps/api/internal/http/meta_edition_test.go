package http

import (
	"context"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/release"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE EDITION IS A LICENCE READ, ASSERTED IN BOTH DIRECTIONS.
//
// From S12.1 (`34004a72`) until this fix, `/meta` reported "open" unconditionally — the build-tag split was
// removed and `const Name = "open"` was left as the only definition. Eleven web files gate on this value,
// so a fully licensed customer saw upsell cards on every enterprise surface.
//
// ⚠ ONE DIRECTION IS HALF A TEST, AND IT IS THE WORTHLESS HALF. A handler hardcoded to "enterprise" would
// pass "a paid licence reports enterprise" perfectly — and would be exactly the bug that just shipped,
// mirrored. The unlicensed case is what makes the paid case mean anything.
func TestMetaEditionFollowsTheLicence(t *testing.T) {
	for _, tc := range []struct {
		name string
		mgr  *licence.Manager
		want string
	}{
		// ⭐ The commonest deployment there is. Community is a product, not a degraded state.
		{"no licence at all", &licence.Manager{}, "open"},
		{"trial", licence.NewTestManager("trial", time.Now().Add(time.Hour)), "enterprise"},
		{"starter", licence.NewTestManager("starter", time.Now().Add(time.Hour)), "enterprise"},
		{"scale", licence.NewTestManager("scale", time.Now().Add(time.Hour)), "enterprise"},
		// ⭐ GRACE, AND IT NEEDS NO CASE IN THE HANDLER. Evaluate keeps the licensed tier for the whole
		// 90 days, so the UI keeps working for a customer who is one day late renewing — the ladder's
		// whole point, inherited rather than re-implemented.
		{"expired, inside grace", licence.NewTestManager("growth", time.Now().Add(-24*time.Hour)), "enterprise"},
		// ⛔ AND AFTER GRACE THE SURFACES CLOSE ON THEIR OWN, because the tier falls to Community.
		{"lapsed past grace", licence.NewTestManager("growth", time.Now().Add(-100*24*time.Hour)), "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := (apiServer{licence: tc.mgr}).editionName()
			if got != tc.want {
				t.Errorf("edition = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetMetaCarriesVerifiedUpgradeStatusOnlyWhenConfigured(t *testing.T) {
	st := &release.Status{Available: true, Verified: true, CurrentVersion: "0.3.0", CurrentSourceSHA: "old", Version: "0.4.0", SourceSHA: "new", Sequence: 8, Compatibility: "N/N-1", Downtime: "rolling", ReleaseNotesURL: "https://tunnex.io/r/0.4.0"}
	s := apiServer{licence: &licence.Manager{}, releaseStatus: st}
	got, err := s.GetMeta(context.Background(), api.GetMetaRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	body := got.(api.GetMeta200JSONResponse).Body
	if body.Upgrade == nil || !body.Upgrade.Available || !body.Upgrade.Verified || body.Upgrade.SourceSha == nil || *body.Upgrade.SourceSha != "new" {
		t.Fatalf("upgrade status not surfaced: %+v", body.Upgrade)
	}
}

func TestGetMetaCarriesBlockedUpgradeStatus(t *testing.T) {
	st := &release.Status{State: "failed", Reason: "installation verification failed; updates are blocked", Verified: false}
	s := apiServer{licence: &licence.Manager{}, releaseStatus: st}
	got, err := s.GetMeta(context.Background(), api.GetMetaRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	body := got.(api.GetMeta200JSONResponse).Body
	if body.Upgrade == nil || body.Upgrade.Verified || body.Upgrade.Available || body.Upgrade.Reason == "" || body.Upgrade.State == nil || string(*body.Upgrade.State) != "failed" {
		t.Fatalf("blocked upgrade status not surfaced fail-closed: %+v", body.Upgrade)
	}
}

func TestGetMetaReadsTheLatestVerifiedReleaseStatus(t *testing.T) {
	// The online checker refreshes in the background. /meta must read its current
	// immutable snapshot, rather than the boot-time descriptor forever.
	boot := &release.Status{Verified: true, CurrentVersion: "0.3.0", Version: "0.3.0", Sequence: 3}
	latest := &release.Status{Available: true, Verified: true, CurrentVersion: "0.3.0", Version: "0.4.0", SourceSHA: "new", Sequence: 4}
	s := apiServer{licence: &licence.Manager{}, releaseStatus: boot, releaseStatusProvider: func() *release.Status { return latest }}
	got, err := s.GetMeta(context.Background(), api.GetMetaRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	body := got.(api.GetMeta200JSONResponse).Body
	if body.Upgrade == nil || !body.Upgrade.Available || body.Upgrade.Version == nil || *body.Upgrade.Version != "0.4.0" {
		t.Fatalf("/meta did not read latest verified release status: %+v", body.Upgrade)
	}
}

// ⛔ THE REGRESSION GUARD, NAMED FOR WHAT IT CATCHES. The defect was not a wrong branch — it was a
// CONSTANT. Anything that makes this function ignore its input reintroduces it exactly.
func TestMetaEditionIsNotAConstant(t *testing.T) {
	unlicensed := (apiServer{licence: &licence.Manager{}}).editionName()
	licensed := (apiServer{licence: licence.NewTestManager("growth", time.Now().Add(time.Hour))}).editionName()
	if unlicensed == licensed {
		t.Fatalf("⛔ /meta REPORTS %q REGARDLESS OF THE LICENCE. This is the S12.1 defect: eleven web "+
			"files gate on this value, so either every deployment sees upsell cards it has paid past, or "+
			"every deployment is shown surfaces it has not paid for", unlicensed)
	}
}
