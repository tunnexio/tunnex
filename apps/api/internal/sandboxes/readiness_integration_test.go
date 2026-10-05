package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

type readinessNetworkFixture struct {
	mutate func(*PrivateNetworkObservation)
	calls  int
}

func (n *readinessNetworkFixture) InspectPrivateNetwork(_ context.Context, target PrivateNetworkTarget) (PrivateNetworkObservation, error) {
	n.calls++
	observation := PrivateNetworkObservation{target, time.Now().UTC()}
	if n.mutate != nil {
		n.mutate(&observation)
	}
	return observation, nil
}

type readinessPolicyFixture struct{ hash string }

func (p *readinessPolicyFixture) PolicyHealthForNodes(_ context.Context, _ uuid.UUID, selected []sqlc.Node, _ ...nodes.SiteTopoBatch) map[uuid.UUID]nodes.PolicyHealth {
	out := map[uuid.UUID]nodes.PolicyHealth{}
	for _, node := range selected {
		out[node.ID] = nodes.PolicyHealth{Kind: nodes.KindHealthy, PushKnown: true, PushedHash: p.hash, AppliedHash: p.hash}
	}
	return out
}

func TestPrivateReadinessPostgresComposition(t *testing.T) {
	for _, scenario := range []string{"ready", "wrong-runtime", "stale-network", "missing-handshake", "stale-handshake", "ssh-failed", "stop-during-probe", "creator-removed", "policy-changed", "credential-revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			_, gatewayKey, err := wgkey.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, gatewayKey); err != nil {
				t.Fatal(err)
			}
			sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("ready-"+scenario))
			if err != nil {
				t.Fatal(err)
			}
			_, probeKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := ssh.NewSignerFromKey(probeKey)
			if err != nil {
				t.Fatal(err)
			}
			base, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			if err = base.Mkdir(sandbox.Identity.ID.String(), 0700); err != nil {
				t.Fatal(err)
			}
			owned, err := base.OpenRoot(sandbox.Identity.ID.String())
			if err != nil {
				t.Fatal(err)
			}
			defer owned.Close()
			if _, _, err = f.store.PrepareCreationAssets(f.ctx, sandbox.Identity.ID, owned, string(ssh.MarshalAuthorizedKey(identity.PublicKey()))); err != nil {
				t.Fatal(err)
			}
			assets, err := sandboxruntime.NewFilesystemAssets(base)
			if err != nil {
				t.Fatal(err)
			}
			provider := &runningProvider{}
			if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, provider); err != nil {
				t.Fatal(err)
			}
			h, err := f.store.PrepareLaunch(f.ctx, sandbox.Identity.ID, f.node, launchTestSealer(t))
			if err != nil {
				t.Fatal(err)
			}
			control, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			transport, err := NewFileBootstrapTransport(control, "https://fixture.example", &enrollmentInvokerFixture{f: f})
			if err != nil {
				t.Fatal(err)
			}
			if err = f.store.EnrollPreparedLaunch(f.ctx, h, transport); err != nil {
				t.Fatal(err)
			}
			if err = f.store.StartBoundRuntime(f.ctx, sandbox.Identity.ID, provider); err != nil {
				t.Fatal(err)
			}
			if scenario != "missing-handshake" {
				age := time.Duration(0)
				if scenario == "stale-handshake" {
					age = -5 * time.Minute
				}
				var deviceKey string
				if err = f.pool.QueryRow(f.ctx, `SELECT public_key FROM devices WHERE id=(SELECT peer_id FROM sandboxes WHERE id=$1)`, sandbox.Identity.ID).Scan(&deviceKey); err != nil {
					t.Fatal(err)
				}
				node, e := sqlc.New(f.pool).GetNodeForOrg(f.ctx, sqlc.GetNodeForOrgParams{ID: f.node, OrgID: f.org})
				if e != nil {
					t.Fatal(e)
				}
				if err = nodes.NewService(f.pool, nil, nil).ReportStatus(f.ctx, node, []nodes.PeerStatus{{PublicKey: deviceKey, LastHandshake: time.Now().UTC().Add(age).Unix()}}); err != nil {
					t.Fatal(err)
				}
			}
			network := &readinessNetworkFixture{}
			if scenario == "wrong-runtime" {
				network.mutate = func(o *PrivateNetworkObservation) { o.Target.RuntimeID = "wrong" }
			}
			if scenario == "stale-network" {
				network.mutate = func(o *PrivateNetworkObservation) { o.ObservedAt = time.Now().Add(-time.Minute) }
			}
			policies := &readinessPolicyFixture{hash: "finalized"}
			probe := func(_ context.Context, _ netip.Addr, host ssh.PublicKey, _ ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
				switch scenario {
				case "ssh-failed":
					return sandboxruntime.SSHProbeResult{}, sandboxruntime.ErrUnavailable
				case "stop-during-probe":
					_, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "stopped")
				case "creator-removed":
					_, err = f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
				case "policy-changed":
					policies.hash = "new-finalized"
				case "credential-revoked":
					_, err = f.pool.Exec(f.ctx, `UPDATE sandbox_runtime_credentials SET revoked_at=now() WHERE sandbox_id=$1`, sandbox.Identity.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
				return sandboxruntime.SSHProbeResult{HostKeyFingerprint: ssh.FingerprintSHA256(host), ObservedAt: time.Now().UTC(), UID: 1001}, nil
			}
			err = f.store.verifyPrivateReadiness(f.ctx, sandbox.Identity.ID, provider, policies, network, assets, identity, probe)
			if scenario == "ready" && err != nil {
				t.Fatal("complete trusted fixture refused", err)
			}
			if scenario != "ready" && err == nil {
				t.Fatal("incomplete or obsolete evidence admitted")
			}
			var state string
			if err = f.pool.QueryRow(f.ctx, `SELECT observed_state FROM sandboxes WHERE id=$1`, sandbox.Identity.ID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if (state == "ready") != (scenario == "ready") {
				t.Fatal("unexpected observed state", state)
			}
			if provider.creates != 1 || provider.starts != 1 {
				t.Fatal("readiness provisioned replacement resource")
			}
		})
	}
}

func TestPrivateReadinessDisabledWithoutAdapters(t *testing.T) {
	if err := (&Store{}).VerifyPrivateReadiness(context.Background(), uuid.New(), nil, nil, nil, nil, nil); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
}

func TestNetworkObservationBindingAndFreshness(t *testing.T) {
	now := time.Now().UTC()
	target := PrivateNetworkTarget{SandboxID: uuid.New(), Generation: 2}
	for _, age := range []time.Duration{-time.Second, 10 * time.Second, time.Minute} {
		if validNetworkObservation(now, now.Add(-time.Minute), target, PrivateNetworkObservation{target, now.Add(-age)}) {
			t.Fatal("future/stale evidence accepted", age)
		}
	}
	other := target
	other.Generation++
	if validNetworkObservation(now, now.Add(-time.Minute), target, PrivateNetworkObservation{other, now}) {
		t.Fatal("wrong generation accepted")
	}
}
