package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/google/uuid"
	"os"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

func stoppedDeleteFixture(t *testing.T) (fixture, Sandbox, *InitialLaunchCoordinator, *uncertainStopProvider, *composedNetworkFixture) {
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
	return f, sandbox, initial, provider, network
}

// expireStoppedFixture simulates clock advancement only in this disposable
// test database. Restore the identity trigger before calling production cleanup;
// never alter or mint withdrawal evidence.
func expireStoppedFixture(t *testing.T, f fixture, id uuid.UUID) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	for _, q := range []string{`ALTER TABLE sandboxes DISABLE TRIGGER sandbox_immutable_identity`, `UPDATE sandboxes SET created_at=created_at-interval '1 day',expires_at=expires_at-interval '1 day' WHERE id=$1`, `SET CONSTRAINTS ALL IMMEDIATE`, `ALTER TABLE sandboxes ENABLE TRIGGER sandbox_immutable_identity`} {
		if strings.Contains(q, "$1") {
			_, err = tx.Exec(f.ctx, q, id)
		} else {
			_, err = tx.Exec(f.ctx, q)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

// A stopped provider has no network namespace, matching SocketNetwork's
// OpenNetworkNamespace ownership check. Re-entry must use the real stop receipt.
type stoppedNamespaceNetwork struct {
	*composedNetworkFixture
	provider *uncertainStopProvider
}

func (n *stoppedNamespaceNetwork) RemovePrivateNetwork(ctx context.Context, t PrivateNetworkTarget, c []byte) error {
	if !n.provider.status.Running {
		n.removals++
		return sandboxruntime.ErrOwnership
	}
	return n.composedNetworkFixture.RemovePrivateNetwork(ctx, t, c)
}
func TestStoppedTTLDeletePostgresReusesExactWithdrawal(t *testing.T) {
	f, s, initial, provider, network := stoppedDeleteFixture(t)
	if provider.status.Running || s.Revision != 2 {
		t.Fatal("fixture not stopped", s.Revision)
	}
	var observed string
	if err := f.pool.QueryRow(f.ctx, `SELECT observed_at::text FROM sandbox_network_withdrawals WHERE sandbox_id=$1`, s.Identity.ID).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	expireStoppedFixture(t, f, s.Identity.ID)
	cleanup := &PrivateNetworkCleanup{Store: f.store, Network: &stoppedNamespaceNetwork{network, provider}, Gateway: network, Files: initial.Files, Policies: initial.Policies}
	if err := f.store.ReconcileCleanup(f.ctx, s.Identity.ID, provider, cleanup); err != nil {
		t.Fatal("TTL delete after stopped namespace", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, s.Identity.ID)
	if err != nil || current.State != StateDeleted || current.Revision != 3 || network.removals != 1 || network.absences != 1 {
		t.Fatal("cleanup incomplete/repeated network", current, err, network.removals, network.absences)
	}
	var generation int64
	var unchanged, released bool
	if err = f.pool.QueryRow(f.ctx, `SELECT w.generation,w.observed_at::text=$2,d.assigned_ip IS NULL FROM sandbox_network_withdrawals w JOIN devices d ON d.id=w.peer_id WHERE w.sandbox_id=$1`, s.Identity.ID, observed).Scan(&generation, &unchanged, &released); err != nil || generation != 3 || !unchanged || !released {
		t.Fatal("receipt/address", generation, unchanged, released, err)
	}
}
func TestStoppedDeletePostgresRejectsForeignOrResumedWithdrawal(t *testing.T) {
	for _, scenario := range []string{"peer", "runtime", "spec", "org", "epoch", "intervening-start", "missing", "stale-policy"} {
		t.Run(scenario, func(t *testing.T) {
			f, s, initial, provider, network := stoppedDeleteFixture(t)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "peer":
				peer := uuid.New()
				_, key, _ := wgkey.Generate()
				exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,kind) VALUES($1,$2,$3,$4,'foreign',$5,'human')`, peer, f.org, f.user, f.node, key)
				exec(`UPDATE sandbox_network_withdrawals SET peer_id=$2 WHERE sandbox_id=$1`, s.Identity.ID, peer)
			case "runtime":
				exec(`UPDATE sandbox_network_withdrawals SET runtime_id=$2 WHERE sandbox_id=$1`, s.Identity.ID, strings.Repeat("c", 64))
			case "spec":
				exec(`UPDATE sandbox_network_withdrawals SET spec_hash=$2 WHERE sandbox_id=$1`, s.Identity.ID, strings.Repeat("d", 64))
			case "org":
				org := uuid.New()
				exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'foreign',$2)`, org, org.String())
				exec(`UPDATE sandbox_network_withdrawals SET org_id=$2 WHERE sandbox_id=$1`, s.Identity.ID, org)
			case "intervening-start":
				resumed, err := f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, s.Revision, "started")
				if err != nil {
					t.Fatal(err)
				}
				resume := &ResumeCoordinator{Initial: initial}
				if err = resume.Reconcile(f.ctx, s.Identity.ID); !errors.Is(err, ErrConflict) {
					t.Fatal("expected fresh epoch ACK gate", err)
				}
				exec(`UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node)
				if err = resume.Reconcile(f.ctx, s.Identity.ID); err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, resumed.Revision, "stopped"); err != nil {
					t.Fatal(err)
				}
				if err = provider.Stop(f.ctx, s.Identity.ID); err != nil {
					t.Fatal(err)
				}
			case "epoch":
				var op uuid.UUID
				if err := f.pool.QueryRow(f.ctx, `SELECT operation_id FROM sandbox_network_withdrawals WHERE sandbox_id=$1`, s.Identity.ID).Scan(&op); err != nil {
					t.Fatal(err)
				}
				epoch := uuid.New()
				exec(`INSERT INTO sandbox_start_epochs(id,sandbox_id,org_id,generation,operation_id) VALUES($1,$2,$3,3,$4)`, epoch, s.Identity.ID, f.org, op)
				if scenario == "epoch" {
					exec(`UPDATE sandbox_network_withdrawals SET network_epoch_id=$2 WHERE sandbox_id=$1`, s.Identity.ID, epoch)
				}
			case "missing":
				exec(`DELETE FROM sandbox_network_withdrawals WHERE sandbox_id=$1`, s.Identity.ID)
			case "stale-policy":
				exec(`UPDATE nodes SET policy_reported_at=now()-interval '1 hour' WHERE id=$1`, f.node)
			}
			expireStoppedFixture(t, f, s.Identity.ID)
			cleanup := &PrivateNetworkCleanup{Store: f.store, Network: &stoppedNamespaceNetwork{network, provider}, Gateway: network, Files: initial.Files, Policies: initial.Policies}
			err := f.store.ReconcileCleanup(f.ctx, s.Identity.ID, provider, cleanup)
			if err == nil {
				t.Fatal("foreign/stale receipt reused")
			}
			if scenario != "stale-policy" && !errors.Is(err, sandboxruntime.ErrOwnership) {
				t.Fatal("missing stopped namespace not exercised", err)
			}
			current, e := f.store.Get(f.ctx, f.org, f.user, s.Identity.ID)
			if e != nil || current.State != StateDeleting {
				t.Fatal("denial changed cleanup", current, e)
			}
			if provider.status.RuntimeID == "" {
				t.Fatal("denial deleted provider")
			}
		})
	}
}
