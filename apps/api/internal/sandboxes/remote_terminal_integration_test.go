package sandboxes

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

func remoteTerminalFixture(t *testing.T) (fixture, BoundedRuntimeBinding) {
	t.Helper()
	f, b, _ := newDevReservationFixture(t)
	_, terminalKey, _ := wgkey.Generate()
	devExec(t, f, `UPDATE devices SET public_key=$2 WHERE id=$1`, b.TerminalDeviceID, terminalKey)
	runtimeGateway := uuid.MustParse("ffffffff-ffff-4fff-8fff-fffffffffff0")
	_, public, _ := wgkey.Generate()
	devExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial,endpoint,wg_public_key,status,policy_reported_at) VALUES($1,$2,'remote runtime',$3,'172.31.18.44:51821',$4,'active',now())`, runtimeGateway, f.org, runtimeGateway.String(), public)
	b.RemoteTerminal = &RemoteTerminalBinding{GatewayID: f.node, GatewayEndpoint: "172.31.18.43:51820", RuntimeGatewayEndpoint: "172.31.18.44:51821"}
	b.GatewayID = runtimeGateway
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	return f, b
}

func TestRemoteTerminalBindingRequiresPersistentPrivateDistinctGateways(t *testing.T) {
	b := persistentTestBinding()
	b.RemoteTerminal = &RemoteTerminalBinding{GatewayID: uuid.New(), GatewayEndpoint: "172.31.18.43:51820", RuntimeGatewayEndpoint: "172.31.18.44:51821"}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*BoundedRuntimeBinding){func(b *BoundedRuntimeBinding) { b.RemoteTerminal.GatewayID = b.GatewayID }, func(b *BoundedRuntimeBinding) { b.RemoteTerminal.GatewayEndpoint = "example.com:51820" }, func(b *BoundedRuntimeBinding) { b.RemoteTerminal.RuntimeGatewayEndpoint = "203.0.113.4:51821" }, func(b *BoundedRuntimeBinding) { b.RemoteTerminal.RuntimeGatewayEndpoint = "172.31.18.44:0" }, func(b *BoundedRuntimeBinding) { b.Mode = "trial" }} {
		copy := b
		r := *b.RemoteTerminal
		copy.RemoteTerminal = &r
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("expanded remote transport binding admitted")
		}
	}
}

func TestRemoteTerminalPostgresPlacementRoutingReadinessAndWithdrawal(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		global bool
	}{{"global disabled", false}, {"global enabled", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			runRemoteTerminalPostgresPlacementRoutingReadinessAndWithdrawal(t, scenario.global)
		})
	}
}

func runRemoteTerminalPostgresPlacementRoutingReadinessAndWithdrawal(t *testing.T, global bool) {
	f, b := remoteTerminalFixture(t)
	devExec(t, f, `UPDATE organizations SET cross_gateway_clients_enabled=$2 WHERE id=$1`, f.org, global)
	var otherGateway uuid.UUID
	var oldOtherPeers []gatewaymesh.Peer
	if global {
		otherGateway = uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee0")
		_, key, _ := wgkey.Generate()
		devExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial,endpoint,wg_public_key,status,policy_reported_at) VALUES($1,$2,'unrelated gateway',$3,'192.168.1.20:51820',$4,'active',now()-interval '1 hour')`, otherGateway, f.org, otherGateway.String(), key)
		_, deviceKey, _ := wgkey.Generate()
		devExec(t, f, `INSERT INTO devices(org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,'unrelated client',$4,'10.99.0.21','human')`, f.org, f.other, otherGateway, deviceKey)
		before, err := gatewaymesh.Load(f.ctx, sqlc.New(f.pool), f.org, true, true)
		if err != nil {
			t.Fatal(err)
		}
		oldOtherPeers = before.Peers(otherGateway)
	}
	in := devInput(f, b, 0)
	created, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	again, replay, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil || !replay || again.Identity.ID != created.Identity.ID {
		t.Fatal("remote idempotency", err)
	}
	var local pgtype.UUID
	var terminal, runtime uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT s.local_terminal_gateway_id,r.terminal_gateway_id,r.runtime_gateway_id FROM sandboxes s JOIN sandbox_remote_terminal_routes r ON r.sandbox_id=s.id WHERE s.id=$1`, created.Identity.ID).Scan(&local, &terminal, &runtime); err != nil || local.Valid || terminal != f.node || runtime != b.GatewayID {
		t.Fatal("execution placement replaced terminal enrollment", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_remote_terminal_routes SET runtime_gateway_endpoint='172.31.18.45:51821' WHERE sandbox_id=$1`, created.Identity.ID); err == nil {
		t.Fatal("accepted transport pins mutable")
	}
	down, err := db.MigrationsFS.ReadFile("migrations/0195_sandbox_remote_terminal_routes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, string(down)); err == nil {
		_ = tx.Rollback(f.ctx)
		t.Fatal("downgrade discarded retained remote transport")
	}
	if err = tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.IssueBootstrap(f.ctx, f.org, f.user, created.Identity.ID, f.node); !errors.Is(err, ErrConflict) {
		t.Fatal("remote runtime enrolled on terminal gateway", err)
	}
	server, client, _ := persistentRPCFixture(t, b)
	invoker := &enrollmentInvokerFixture{f: f}
	files, err := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	reader := &policyReaderFixture{}
	orchestrator, err := NewAPIOrchestrator(f.store, b, client, reader, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = orchestrator.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
		t.Fatal(err)
	}
	ready, err := f.store.Get(f.ctx, f.org, f.user, created.Identity.ID)
	if err != nil || ready.State != StateReady || len(reader.ids) != 2 {
		t.Fatal("two-gateway readiness not proven", ready.State, reader.ids, err)
	}
	assertHistoricalPending(t, f, b)
	check := func(want bool) {
		t.Helper()
		snap, e := policy.BuildSnapshotWithQueries(f.ctx, sqlc.New(f.pool), f.org)
		if e != nil {
			t.Fatal(e)
		}
		rows, e := sqlc.New(f.pool).ListScopedSandboxTerminalRoutes(f.ctx, f.org)
		if e != nil || (len(rows) == 1) != want || len(rows) > 1 {
			t.Fatal("routing authority projection", len(rows), e)
		}
		if want {
			if !snap.CrossGatewayGraph.AllowsSandboxTerminal(f.node, b.GatewayID, "10.99.0.2", ready.Connection.Address) {
				t.Fatal("exact private route missing")
			}
			artifacts := policy.Compile(snap)
			for _, id := range []uuid.UUID{f.node, b.GatewayID} {
				if len(artifacts[id].Allow) != 1 || artifacts[id].Allow[0].Protocol != "tcp" || artifacts[id].Allow[0].PortLow != 22 || artifacts[id].Allow[0].PortHigh != 22 {
					t.Fatal("remote scope widened", artifacts[id].Allow)
				}
			}
			if peers := snap.CrossGatewayGraph.Peers(b.GatewayID); len(peers) != 1 || peers[0].NodeID != f.node || !reflect.DeepEqual(peers[0].Prefixes, []string{"10.99.0.2/32"}) {
				t.Fatal("runtime carried unrelated clients", peers)
			}
		} else if len(snap.Sandboxes) != 0 || (snap.CrossGatewayGraph != nil && snap.CrossGatewayGraph.SandboxScoped()) {
			t.Fatal("withdrawn sandbox retained projected authorization")
		}
		if global {
			if !reflect.DeepEqual(snap.CrossGatewayGraph.Peers(otherGateway), oldOtherPeers) {
				t.Fatal("ordinary unrelated gateway carriage changed")
			}
			if len(policy.Compile(snap)[otherGateway].Allow) != 0 || snap.CrossGatewayGraph.AllowsSandboxTerminal(otherGateway, b.GatewayID, "10.99.0.21", ready.Connection.Address) {
				t.Fatal("unrelated client received sandbox authorization")
			}
			if !want && len(snap.CrossGatewayGraph.Peers(b.GatewayID)) != 0 {
				t.Fatal("stopped/deleted runtime fell back to ordinary client carriage")
			}
		}
	}
	check(true)
	// Real desired state carries the exact corridor with either global setting;
	// CP also preserves ordinary routes, while the runtime gets only the Mac.
	nodeService := nodes.NewService(f.pool, nil, nil)
	nodeService.SetPolicyProvider(policy.NewService(f.pool))
	for _, id := range []uuid.UUID{f.node, b.GatewayID} {
		node, e := sqlc.New(f.pool).GetNodeForOrg(f.ctx, sqlc.GetNodeForOrgParams{ID: id, OrgID: f.org})
		if e != nil {
			t.Fatal(e)
		}
		desired, e := nodeService.DesiredState(f.ctx, node)
		if e != nil || desired.Policy == nil {
			t.Fatal("site-less desired state omitted corridor", e)
		}
		wantRoutes := []string{ready.Connection.Address + "/32"}
		if id == b.GatewayID {
			wantRoutes = []string{"10.99.0.2/32"}
		} else if global {
			wantRoutes = append(wantRoutes, "10.99.0.21/32")
		}
		actual := []string{}
		for _, route := range desired.Policy.Routes {
			actual = append(actual, route.DstCIDR)
		}
		sort.Strings(wantRoutes)
		sort.Strings(actual)
		if !reflect.DeepEqual(actual, wantRoutes) {
			t.Fatal("scoped/ordinary routes changed", id, actual, wantRoutes)
		}
	}
	devExec(t, f, `UPDATE nodes SET policy_reported_at=now()-interval '1 hour' WHERE id=$1`, f.node)
	target := PrivateNetworkTarget{OrgID: f.org, SandboxID: created.Identity.ID}
	if err = f.pool.QueryRow(f.ctx, `SELECT id,gateway_node_id,generation,runtime_id,spec_hash FROM sandbox_launch_operations WHERE sandbox_id=$1 AND org_id=$2`, created.Identity.ID, f.org).Scan(&target.OperationID, &target.GatewayID, &target.Generation, &target.RuntimeID, &target.SpecHash); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CurrentSandboxPolicyAcknowledgements(f.ctx, target, reader); !errors.Is(err, ErrDisabled) {
		t.Fatal("stale terminal gateway bypassed convergence", err)
	}
	devExec(t, f, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node)
	stopped, err := f.store.SetDesired(f.ctx, f.org, f.user, ready.Identity.ID, ready.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, stopped.Identity.ID, stopped.Revision, "deleted"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = orchestrator.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := f.store.Get(f.ctx, f.org, f.user, created.Identity.ID)
	if err != nil || deleted.State != StateDeleted {
		t.Fatal("remote cleanup", deleted.State, err)
	}
	assertHistoricalPending(t, f, b)
	var unchanged bool
	if err = f.pool.QueryRow(f.ctx, `SELECT cross_gateway_clients_enabled=$2 FROM organizations WHERE id=$1`, f.org, global).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("existing organization cross-gateway setting changed", err)
	}
}

func TestRemoteTerminalPostgresRejectsSharedRuntimeBeforeCreate(t *testing.T) {
	for _, global := range []bool{false, true} {
		for _, kind := range []string{"human", "agent"} {
			t.Run(kind+map[bool]string{false: " global disabled", true: " global enabled"}[global], func(t *testing.T) {
				f, b := remoteTerminalFixture(t)
				devExec(t, f, `UPDATE organizations SET cross_gateway_clients_enabled=$2 WHERE id=$1`, f.org, global)
				_, key, _ := wgkey.Generate()
				devExec(t, f, `INSERT INTO devices(org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,'shared runtime client',$4,'10.99.0.31',$5)`, f.org, f.other, b.GatewayID, key, kind)
				if _, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0)); !errors.Is(err, ErrForbidden) {
					t.Fatal("shared runtime accepted", err)
				}
				var accepted int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1 AND id<>$2`, f.org, devReservedSandbox).Scan(&accepted); err != nil || accepted != 0 {
					t.Fatal("rejected shared runtime left a sandbox row", accepted, err)
				}
				assertHistoricalPending(t, f, b)
			})
		}
	}
}
