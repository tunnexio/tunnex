package sandboxes

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

func stoppedResumeFixture(t *testing.T) (fixture, Sandbox, *InitialLaunchCoordinator, *uncertainStopProvider, *composedNetworkFixture) {
	t.Helper()
	f := newFixture(t)
	f.store.WithQualificationOrg(f.org)
	_, key, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, key); err != nil {
		t.Fatal(err)
	}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("resume-denial"))
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(private)
	assetsRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { assetsRoot.Close() })
	assets, _ := sandboxruntime.NewFilesystemAssets(assetsRoot)
	controlRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { controlRoot.Close() })
	files, err := NewFileBootstrapTransport(controlRoot, "https://fixture.example", &enrollmentInvokerFixture{f: f})
	if err != nil {
		t.Fatal(err)
	}
	provider := &uncertainStopProvider{}
	network := &composedNetworkFixture{f: f}
	policies := &readinessPolicyFixture{hash: "finalized"}
	initial := &InitialLaunchCoordinator{Store: f.store, Provider: provider, AssetsRoot: assetsRoot, Assets: assets, Files: files, Network: network, Probe: network, ProbeIdentity: identity, Policies: policies, Sealer: launchTestSealer(t), GatewayID: f.node}
	if err = initial.Reconcile(f.ctx, sandbox.Identity.ID); err != nil {
		t.Fatal(err)
	}
	sandbox, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, 1, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := &PrivateNetworkCleanup{Store: f.store, Network: network, Gateway: network, Files: files, Policies: policies}
	if err = f.store.ReconcileCleanup(f.ctx, sandbox.Identity.ID, provider, cleanup); err != nil {
		t.Fatal(err)
	}
	sandbox, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "started")
	if err != nil {
		t.Fatal(err)
	}
	return f, sandbox, initial, provider, network
}

func TestResumePostgresPreservesReadinessPolicyStage(t *testing.T) {
	f, sandbox, initial, provider, network := stoppedResumeFixture(t)
	initial.Policies = &readinessPolicyFixture{hash: ""}
	probesBefore := network.probes
	err := (&ResumeCoordinator{Initial: initial}).Reconcile(f.ctx, sandbox.Identity.ID)
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("policy refusal lost ErrDisabled: %v", err)
	}
	var staged *LaunchStageError
	if !errors.As(err, &staged) || staged.Stage != "readiness-policy-before" {
		t.Fatalf("policy refusal lost its readiness stage: %v", err)
	}
	if provider.starts != 2 {
		t.Fatalf("resume did not reach the policy gate after starting: starts=%d", provider.starts)
	}
	if network.probes != probesBefore {
		t.Fatal("policy refusal reached the terminal probe")
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != StateStarting || current.Revision != sandbox.Revision || current.Connection != nil {
		t.Fatalf("policy refusal changed pending resume admission: state=%s revision=%d connection=%v", current.State, current.Revision, current.Connection)
	}
}

func TestResumePostgresCurrentAdmissionAndStopRace(t *testing.T) {
	for _, scenario := range []string{"creator", "template", "credential", "runtime", "withdrawal", "stop-race"} {
		t.Run(scenario, func(t *testing.T) {
			f, sandbox, initial, provider, network := stoppedResumeFixture(t)
			var err error
			switch scenario {
			case "creator":
				_, err = f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
			case "template":
				_, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET enabled=false WHERE id=$1`, f.template)
			case "credential":
				_, err = f.pool.Exec(f.ctx, `UPDATE sandbox_runtime_credentials SET revoked_at=now() WHERE sandbox_id=$1`, sandbox.Identity.ID)
			case "withdrawal":
				_, err = f.pool.Exec(f.ctx, `DELETE FROM sandbox_network_withdrawals WHERE sandbox_id=$1`, sandbox.Identity.ID)
			case "runtime":
				provider.status.RuntimeID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			case "stop-race":
				if err = f.store.PrepareResume(f.ctx, sandbox.Identity.ID, provider); err != nil {
					t.Fatal(err)
				}
				_, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node)
				network.afterProbe = func() {
					if _, e := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "stopped"); e != nil {
						t.Fatal(e)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = (&ResumeCoordinator{Initial: initial}).Reconcile(f.ctx, sandbox.Identity.ID); err == nil {
				t.Fatal("denied resume became ready", scenario)
			}
			if scenario != "stop-race" && provider.starts != 1 {
				t.Fatal("denied resume started workload", scenario, provider.starts)
			}
			current, e := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
			if e == nil && current.Connection != nil {
				t.Fatal("denied/racing resume exposed connection", scenario)
			}
		})
	}
}

func TestResumePostgresDowngradeNeedsDeletedEpoch(t *testing.T) {
	f, sandbox, initial, provider, network := stoppedResumeFixture(t)
	if err := f.store.PrepareResume(f.ctx, sandbox.Identity.ID, provider); err != nil {
		t.Fatal(err)
	}
	down, err := db.MigrationsFS.ReadFile("migrations/0192_sandbox_start_epochs.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, string(down)); err == nil {
		t.Fatal("unfinished epoch discarded")
	}
	_ = tx.Rollback(f.ctx)
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	if err = (&ResumeCoordinator{Initial: initial}).Reconcile(f.ctx, sandbox.Identity.ID); err != nil {
		t.Fatal(err)
	}
	deleted, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "deleted")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := &PrivateNetworkCleanup{Store: f.store, Network: network, Gateway: network, Files: initial.Files, Policies: initial.Policies}
	if err = f.store.ReconcileCleanup(f.ctx, deleted.Identity.ID, provider, cleanup); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, string(down)); err != nil {
		t.Fatal("completed epoch could not restore fixture schema", err)
	}
	_ = tx.Rollback(f.ctx)
}
