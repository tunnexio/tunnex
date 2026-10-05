package sandboxes

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"strings"
	"sync"
	"testing"
)

func TestSandboxBootstrapPostgresAtomicDistinctAndSingleUse(t *testing.T) {
	f := newFixture(t)
	_, gatewayPublic, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, gatewayPublic); err != nil {
		t.Fatal(err)
	}
	created, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.IssueBootstrap(f.ctx, f.org, f.user, created.Identity.ID, f.node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.IssueBootstrap(f.ctx, f.org, f.user, created.Identity.ID, f.node); err != ErrConflict {
		t.Fatalf("uncertain handoff replaced: %v", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	if _, err = sqlc.New(f.pool).ConsumeSandboxBootstrapToken(f.ctx, sqlc.ConsumeSandboxBootstrapTokenParams{TokenHash: tokenHash[:], OrgID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("another organization consumed the bound token: %v", err)
	}
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	service := devices.NewService(f.pool, nil, nil)
	input := devices.CreateInput{SandboxBootstrapToken: token, PublicKey: public, OrgID: uuid.New(), OwnerID: uuid.New(), NodeID: uuid.New(), FullTunnel: true}
	type result struct {
		value devices.CreateResult
		err   error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(2)
	for range 2 {
		go func() { start.Done(); start.Wait(); v, e := service.Create(f.ctx, input); results <- result{v, e} }()
	}
	a, b := <-results, <-results
	if (a.err == nil) == (b.err == nil) {
		t.Fatalf("single use failed: %v %v", a.err, b.err)
	}
	got := a.value
	if a.err != nil {
		got = b.value
	}
	if got.Device.Kind != "sandbox" || got.Device.UserID != f.user || got.Device.OrgID != f.org || got.Device.NodeID != f.node || got.Device.FullTunnel {
		t.Fatal("bootstrap identity or mode spoofed")
	}
	if got.Device.PublicKey != public || got.PrivateKeyOneTime != "" || strings.Count(got.Config, "__TUNNEX_PRIVATE_KEY__") != 1 || got.RuntimeCredential == "" {
		t.Fatal("client-key bootstrap contract broken")
	}
	if !strings.Contains(got.Config, "MTU = 1280\n") {
		t.Fatal("authenticated sandbox bootstrap lost bounded MTU")
	}
	if strings.Contains(got.Config, "::/") || strings.Contains(got.Config, "DNS =") {
		t.Fatal("unexpected IPv6 or split-tunnel DNS")
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, created.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.PeerID == nil || *current.PeerID != got.Device.ID || current.State == StateReady {
		t.Fatal("peer not atomically bound or enrollment labeled ready")
	}
	var peers, agentProfiles, credentials int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM devices WHERE org_id=$1`, f.org).Scan(&peers); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM agent_profiles WHERE device_id=$1`, got.Device.ID).Scan(&agentProfiles); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandbox_runtime_credentials WHERE sandbox_id=$1`, created.Identity.ID).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if peers != 1 || agentProfiles != 0 || credentials != 1 {
		t.Fatalf("duplicate or agent identity: %d %d %d", peers, agentProfiles, credentials)
	}
	var stored []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT token_hash FROM sandbox_runtime_credentials WHERE sandbox_id=$1`, created.Identity.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(got.RuntimeCredential))
	if string(stored) != string(hash[:]) {
		t.Fatal("runtime credential not hashed")
	}
	body, _ := json.Marshal(current)
	if strings.Contains(string(body), token) || strings.Contains(string(body), got.RuntimeCredential) {
		t.Fatal("ordinary sandbox read exposes credentials")
	}
	identity, err := f.store.AuthenticateRuntime(f.ctx, got.RuntimeCredential)
	if err != nil || identity.SandboxID != created.Identity.ID || identity.PeerID != got.Device.ID || identity.Generation != current.Revision {
		t.Fatalf("current runtime binding unavailable: %v", err)
	}
	for _, invalid := range []string{token, "tnx_runtime_" + strings.TrimPrefix(got.RuntimeCredential, "tnx_sandbox_runtime_"), got.RuntimeCredential + "x"} {
		if _, err = f.store.AuthenticateRuntime(f.ctx, invalid); err != ErrRuntimeUnauthorized {
			t.Fatal("accepted unrelated credential")
		}
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE devices SET health_blocked=true WHERE id=$1`, got.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, got.RuntimeCredential); err != ErrRuntimeUnauthorized {
		t.Fatal("blocked peer authenticated")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE devices SET health_blocked=false WHERE id=$1`, got.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE users SET must_change_password=true WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, got.RuntimeCredential); err != ErrRuntimeUnauthorized {
		t.Fatal("ineligible creator authenticated")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE users SET must_change_password=false WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, current.Identity.ID, current.Revision, "stopped"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, got.RuntimeCredential); err != ErrRuntimeUnauthorized {
		t.Fatal("stopped sandbox authenticated")
	}
}

func TestSandboxBootstrapPostgresStoppedAndExpiredRefused(t *testing.T) {
	f := newFixture(t)
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	created, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("stop"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.IssueBootstrap(f.ctx, f.org, f.user, created.Identity.ID, f.node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, created.Identity.ID, created.Revision, "stopped"); err != nil {
		t.Fatal(err)
	}
	service := devices.NewService(f.pool, nil, nil)
	if _, err = service.Create(f.ctx, devices.CreateInput{SandboxBootstrapToken: token, PublicKey: public}); err == nil {
		t.Fatal("stopped generation enrolled")
	}
	next, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("expired"))
	if err != nil {
		t.Fatal(err)
	}
	token, err = f.store.IssueBootstrap(f.ctx, f.org, f.user, next.Identity.ID, f.node)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(token))
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_bootstrap_tokens SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE token_hash=$1`, h[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Create(f.ctx, devices.CreateInput{SandboxBootstrapToken: token, PublicKey: public}); err == nil {
		t.Fatal("expired bootstrap enrolled")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM devices WHERE org_id=$1`, f.org).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("refusal left a peer")
	}
}

// The node roster is transport authorization, not merely a policy view. A
// stopped/expired sandbox must leave wg syncconf's peer set while ordinary
// authorized devices continue through the original identity gate.
func TestSandboxPeerRosterPostgresWithdrawsWithAdmission(t *testing.T) {
	f := newFixture(t)
	_, gatewayKey, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, gatewayKey); err != nil {
		t.Fatal(err)
	}
	created, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("roster"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.IssueBootstrap(f.ctx, f.org, f.user, created.Identity.ID, f.node)
	if err != nil {
		t.Fatal(err)
	}
	_, public, _ := wgkey.Generate()
	got, err := devices.NewService(f.pool, nil, nil).Create(f.ctx, devices.CreateInput{SandboxBootstrapToken: token, PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	query := sqlc.New(f.pool)
	assertPresent := func(want bool) {
		t.Helper()
		peers, err := query.ListActiveWireGuardPeersForNode(f.ctx, f.node)
		if err != nil {
			t.Fatal(err)
		}
		present := false
		for _, peer := range peers {
			if peer.PublicKey == got.Device.PublicKey {
				present = true
			}
		}
		if present != want {
			t.Fatalf("sandbox physical peer presence=%v want=%v", present, want)
		}
	}
	assertPresent(true)
	for _, change := range []struct{ deny, restore string }{
		{`UPDATE sandboxes SET desired_state='stopped' WHERE id=$1`, `UPDATE sandboxes SET desired_state='started' WHERE id=$1`},
		{`UPDATE sandbox_templates SET enabled=false WHERE id=(SELECT template_id FROM sandboxes WHERE id=$1)`, `UPDATE sandbox_templates SET enabled=true WHERE id=(SELECT template_id FROM sandboxes WHERE id=$1)`},
	} {
		if _, err := f.pool.Exec(f.ctx, change.deny, created.Identity.ID); err != nil {
			t.Fatal(err)
		}
		assertPresent(false)
		if _, err := f.pool.Exec(f.ctx, change.restore, created.Identity.ID); err != nil {
			t.Fatal(err)
		}
		assertPresent(true)
	}
}

func TestOrdinaryDevicePostgresRetains1420MTU(t *testing.T) {
	f := newFixture(t)
	_, public, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	result, err := devices.NewService(f.pool, nil, nil).Create(f.ctx, devices.CreateInput{OrgID: f.org, ActorID: f.user, OwnerID: f.user, NodeID: f.node, Name: "ordinary-MTU"})
	if err != nil || !strings.Contains(result.Config, "MTU = 1420\n") {
		t.Fatal("ordinary device MTU changed", err)
	}
	if _, err = devices.NewService(f.pool, nil, nil).Create(f.ctx, devices.CreateInput{OrgID: f.org, ActorID: f.user, OwnerID: f.user, NodeID: f.node, Name: "spoofed-MTU", Kind: "sandbox", PublicKey: public}); err == nil {
		t.Fatal("unauthenticated sandbox identity admitted")
	}
}
