package http

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type fakeHubReconciler struct {
	calls []uuid.UUID
	err   error
}

func (f *fakeHubReconciler) ReconcileHubSet(_ context.Context, orgID uuid.UUID) (nodes.HubSet, error) {
	f.calls = append(f.calls, orgID)
	return nodes.HubSet{}, f.err
}

type fakeOrgPusher struct{ calls []uuid.UUID }

func (f *fakeOrgPusher) PushOrgNodes(_ context.Context, orgID uuid.UUID) {
	f.calls = append(f.calls, orgID)
}

// TestConvergeSiteTopologyReconcilesThenPushes (SSI-6) — a site mutation persists the hub set and tells the
// organization's gateways to re-fetch, and a reconcile failure never swallows the push: the hub set heals on
// the failover tick, but a removed range must leave the gateways now.
func TestConvergeSiteTopologyReconcilesThenPushes(t *testing.T) {
	org := uuid.New()
	hub, push := &fakeHubReconciler{}, &fakeOrgPusher{}
	convergeSiteTopology(context.Background(), hub, push, org, "test")
	if len(hub.calls) != 1 || hub.calls[0] != org || len(push.calls) != 1 || push.calls[0] != org {
		t.Fatalf("want one reconcile and one push for the org, got reconcile=%v push=%v", hub.calls, push.calls)
	}

	failing, push2 := &fakeHubReconciler{err: errors.New("db down")}, &fakeOrgPusher{}
	convergeSiteTopology(context.Background(), failing, push2, org, "test")
	if len(push2.calls) != 1 {
		t.Fatalf("a failed reconcile must not swallow the push, got %d pushes", len(push2.calls))
	}
}

// TestEverySiteTopologyMutationConverges (SSI-6, findings F6 and F7) is a census over the handler source:
// every site handler that changes what gateways carry must call siteTopologyChanged. It exists because the
// defect was an omission — bind and unbind reconciled, the one-screen route and delete did not, and nothing
// pushed — and an omission is invisible to a test of the handlers that already had the call.
func TestEverySiteTopologyMutationConverges(t *testing.T) {
	src, err := os.ReadFile("site_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	must := []string{"RouteLAN", "BindSiteNode", "UnbindSiteNode", "ApproveSiteSubnet", "RemoveSiteSubnet", "DeleteSite", "SetSiteLanEgress"}
	funcRE := regexp.MustCompile(`(?m)^func \(s apiServer\) (\w+)\(`)
	locs := funcRE.FindAllSubmatchIndex(src, -1)
	bodies := map[string]string{}
	for i, loc := range locs {
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		bodies[string(src[loc[2]:loc[3]])] = string(src[loc[0]:end])
	}
	for _, name := range must {
		body, ok := bodies[name]
		if !ok {
			t.Fatalf("handler %s not found in site_handlers.go: update this census", name)
		}
		if !strings.Contains(body, "s.siteTopologyChanged(ctx, req.OrgId,") {
			t.Errorf("%s changes site topology but never calls siteTopologyChanged", name)
		}
	}
}
