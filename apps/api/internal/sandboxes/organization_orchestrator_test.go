package sandboxes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

func TestOrganizationAPIConfigKeepsDeploymentPins(t *testing.T) {
	b := organizationTestBinding()
	cfg := APIWorkerConfig{Binding: b, Socket: "/run/tunnex-sandbox-worker/control.sock", WorkerUID: 1001, ProbePublicKey: publicTerminalKey(t)}
	path := filepath.Join(t.TempDir(), "worker.json")
	raw, err := json.Marshal(cfg)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write synthetic configuration", err)
	}
	restored, err := LoadAPIWorkerConfig(path)
	if err != nil || !bindingEqual(restored.Binding, b) || !restored.Binding.OrganizationScoped() {
		t.Fatal("organization deployment rejected or pins changed", err)
	}
	cfg.Binding.CreatorID = uuid.New()
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAPIWorkerConfig(path); err == nil {
		t.Fatal("mixed organization/creator authority parsed")
	}
}

func TestOrganizationOrchestratorPostgresSequentialMembersAndRevokedOwnerCleanup(t *testing.T) {
	f := newFixture(t)
	b := organizationTestBinding()
	b.OrgID, b.GatewayID = f.org, f.node
	b.Profiles = b.Profiles[:1]
	profile := b.Profiles[0]
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'organization runtime',$3,'[]',128,900,true)`, profile.TemplateID, f.org, profile.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	devices := []uuid.UUID{uuid.New(), uuid.New()}
	for i, owner := range []uuid.UUID{f.user, f.other} {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) VALUES($1,$2,$3,$4,'terminal',$5,'active','human')`, devices[i], f.org, owner, f.node, "terminal-"+devices[i].String()); err != nil {
			t.Fatal(err)
		}
	}
	_, public, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	server, client, _ := persistentRPCFixture(t, b)
	invoker := &enrollmentInvokerFixture{f: f}
	files, err := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	orchestration, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	batch := func() {
		t.Helper()
		var failures []error
		if err := orchestration.batch(f.ctx, func(_ uuid.UUID, err error) { failures = append(failures, err) }); err != nil || len(failures) != 0 {
			t.Fatal("organization reconciliation failed", err, failures)
		}
	}
	for i, owner := range []uuid.UUID{f.user, f.other} {
		in := CreateInput{TemplateID: profile.TemplateID, Name: "member work", Requested: []Scope{}, TTLSeconds: 900, IdempotencyKey: "independent-owner-request", SSHPublicKeys: []string{f.sshPublicKey}, TerminalDeviceID: &devices[i]}
		created, replay, err := f.store.Create(f.ctx, f.org, owner, in)
		if err != nil || replay {
			t.Fatal("member could not create", i, err)
		}
		batch()
		current, err := f.store.Get(f.ctx, f.org, owner, created.Identity.ID)
		if err != nil || current.State != StateReady || server.active == nil || server.active.CreatorID != owner || server.active.TerminalDeviceID != devices[i] {
			t.Fatal("stored owner/device not used for launch", i, current.State, err)
		}
		server.active, server.sandboxID = nil, uuid.Nil
		if _, err := server.CheckRetirement(); err != nil || server.active == nil || server.active.CreatorID != owner || server.active.TerminalDeviceID != devices[i] {
			t.Fatal("worker restart changed request identity", err)
		}
		if i == 0 {
			if _, err := f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, owner); err != nil {
				t.Fatal(err)
			}
		} else if _, err := f.store.SetDesired(f.ctx, f.org, owner, current.Identity.ID, current.Revision, "deleted"); err != nil {
			t.Fatal(err)
		}
		batch()
		batch()
		var desired, observed string
		var retired bool
		if err := f.pool.QueryRow(f.ctx, `SELECT s.desired_state,s.observed_state,r.worker_retired_at IS NOT NULL FROM sandboxes s JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id WHERE s.id=$1`, created.Identity.ID).Scan(&desired, &observed, &retired); err != nil || desired != "deleted" || observed != "deleted" || !retired {
			t.Fatal("owner cleanup did not retire exact workload", i, desired, observed, retired, err)
		}
	}
	if invoker.calls != 2 {
		t.Fatal("member launch enrolled repeatedly", invoker.calls)
	}
}

func TestOrganizationSetupPostgresReportsRequestDeviceAndSharedCapacity(t *testing.T) {
	f := newFixture(t)
	b := organizationTestBinding()
	b.OrgID, b.GatewayID = f.org, f.node
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET max_sandboxes_per_user=3,max_sandboxes=8 WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	makeSetupAdmin(t, f)
	before := SetupSettings{Enabled: true, MaxPerUser: 3, MaxTotal: 8}
	after := SetupSettings{Enabled: true, MaxPerUser: 3, MaxTotal: 9}
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, before, after, true); err != nil {
		t.Fatal("normal org quota settings rejected", err)
	}
	for _, actor := range []uuid.UUID{f.user, f.other} {
		status, err := f.store.Setup(f.ctx, f.org, actor)
		if err != nil || !status.RequiresTerminalDevice || status.TerminalGatewayID == nil || *status.TerminalGatewayID != f.node || status.RuntimeLimits == nil || status.RuntimeLimits.MaxRetained != 1 || status.RuntimeLimits.MaxWorkloads != 1 || status.Settings.MaxPerUser != 3 || status.Settings.MaxTotal != 9 || containsReason(status.BlockedReasons, "runtime_binding_unavailable") {
			t.Fatal("setup hid normal-member admission or runtime capacity", status, err)
		}
	}
}
