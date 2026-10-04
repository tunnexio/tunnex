package appaccess

import (
	"context"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"strings"
	"testing"
)

func TestBrowserGenerationsStageWithoutCancellingActive(t *testing.T) {
	policy, err := originpolicy.Normalize(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	active := BrowserAssignment{Binding: apptransport.Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.example.net", Purpose: "browser_proxy"}, OriginURL: "https://origin.example.com", Policy: policy}
	staged := active
	staged.Binding.Generation = "55555555-5555-5555-5555-555555555555"
	staged.Binding.Revision = 2
	staged.Binding.Digest = strings.Repeat("b", 64)
	activeCtx, activeCancel := context.WithCancel(context.Background())
	defer activeCancel()
	stagedCtx, stagedCancel := context.WithCancel(context.Background())
	defer stagedCancel()
	pool := &BrowserPool{workers: map[string]browserWorker{browserKey(active.Binding): {active, activeCancel}, browserKey(staged.Binding): {staged, stagedCancel}}}
	pool.Sync(context.Background(), []BrowserAssignment{active, staged})
	if len(pool.workers) != 2 || activeCtx.Err() != nil || stagedCtx.Err() != nil {
		t.Fatal("staging retired active generation")
	}
	pool.Sync(context.Background(), []BrowserAssignment{active})
	if len(pool.workers) != 1 || activeCtx.Err() != nil || stagedCtx.Err() == nil {
		t.Fatal("pending withdrawal damaged active generation")
	}
	mutated := active
	mutated.OriginURL = "https://changed.example.com"
	pool.Sync(context.Background(), []BrowserAssignment{mutated})
	if len(pool.workers) != 0 || activeCtx.Err() == nil {
		t.Fatal("generation reused with changed origin")
	}
}

func TestBrowserSnapshotCannotSupplyThreeGenerationsPerApplication(t *testing.T) {
	policy, err := originpolicy.Normalize(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	assignment := BrowserAssignment{Binding: apptransport.Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.example.net", Purpose: "browser_proxy"}, OriginURL: "https://origin.example.com", Policy: policy}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &BrowserPool{workers: map[string]browserWorker{browserKey(assignment.Binding): {assignment, cancel}}}
	assignments := []BrowserAssignment{assignment, assignment, assignment}
	assignments[1].Binding.Generation = "55555555-5555-5555-5555-555555555555"
	assignments[2].Binding.Generation = "66666666-6666-6666-6666-666666666666"
	pool.Sync(context.Background(), assignments)
	if len(pool.workers) != 0 || ctx.Err() == nil {
		t.Fatal("three generations exceeded per-application bound")
	}
}
