package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// These fixtures attest only to source contracts. They do not activate a runtime
// or establish native image, network, SSH or provider qualification.
func newEligibilityFixture(t *testing.T) (fixture, BoundedRuntimeBinding, uuid.UUID, uuid.UUID, CreateInput) {
	t.Helper()
	f := newFixture(t)
	b := persistentTestBinding()
	b.Admission = "organization"
	b.OrgID, b.GatewayID = f.org, f.node
	b.CreatorID, b.TerminalDeviceID = uuid.Nil, uuid.Nil
	b.Profiles = b.Profiles[:1]
	eligibilityExec(t, f, `UPDATE nodes SET status='active',wg_public_key=$2 WHERE id=$1`, f.node, strings.Repeat("a", 43)+"=")
	p := b.Profiles[0]
	eligibilityExec(t, f, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'synthetic eligibility',$3,'[]',128,900,true)`, p.TemplateID, f.org, p.ConfigDigest)
	devices := []uuid.UUID{uuid.New(), uuid.New()}
	for i, owner := range []uuid.UUID{f.user, f.other} {
		eligibilityExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind,status) VALUES($1,$2,$3,$4,'synthetic terminal',$5,$6,'human','active')`, devices[i], f.org, owner, f.node, strings.Repeat(string(rune('b'+i)), 43)+"=", []string{"10.99.0.2", "10.99.0.3"}[i])
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	in := f.input("eligibility")
	in.TemplateID, in.TerminalDeviceID, in.Requested, in.TTLSeconds = p.TemplateID, &devices[0], []Scope{}, 900
	return f, b, devices[0], devices[1], in
}

func eligibilityExec(t *testing.T, f fixture, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func bindEligibilityRuntime(t *testing.T, f fixture, v Sandbox) (uuid.UUID, string) {
	t.Helper()
	peer := uuid.New()
	raw := sha256.Sum256([]byte(v.Identity.ID.String()))
	token := "tnx_sandbox_runtime_" + base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx) //nolint:errcheck
	if _, err = tx.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,kind,status) VALUES($1,$2,$3,$4,'synthetic sandbox','linux',$5,'10.99.0.4','sandbox','active')`, peer, f.org, v.Identity.CreatorID, f.node, strings.Repeat("d", 43)+"="); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE sandboxes SET peer_id=$2 WHERE id=$1`, v.Identity.ID, peer); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `INSERT INTO sandbox_runtime_credentials(org_id,sandbox_id,peer_id,token_hash) VALUES($1,$2,$3,$4)`, f.org, v.Identity.ID, peer, hash[:]); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.AuthenticateRuntime(f.ctx, token); err != nil || got.SandboxID != v.Identity.ID || got.PeerID != peer || got.Generation != v.Revision {
		t.Fatalf("initial runtime identity: %+v %v", got, err)
	}
	return peer, token
}

func assertEligibilityWithdrawal(t *testing.T, f fixture, v Sandbox, peer uuid.UUID) {
	t.Helper()
	var desired string
	var observed State
	var generation int64
	var revoked, blocked, addressHeld, retirementPending bool
	err := f.pool.QueryRow(f.ctx, `SELECT s.desired_state,s.observed_state,s.generation,c.revoked_at IS NOT NULL,d.health_blocked,d.assigned_ip IS NOT NULL,r.worker_retired_at IS NULL
 FROM sandboxes s JOIN sandbox_runtime_credentials c ON c.sandbox_id=s.id
 JOIN devices d ON d.id=s.peer_id JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id
 WHERE s.id=$1 AND d.id=$2`, v.Identity.ID, peer).Scan(&desired, &observed, &generation, &revoked, &blocked, &addressHeld, &retirementPending)
	if err != nil || desired != "deleted" || observed != v.State || generation != v.Revision+1 || !revoked || !blocked || !addressHeld || !retirementPending {
		t.Fatalf("withdrawal must request cleanup without claiming removal: desired=%s observed=%s generation=%d revoked=%t blocked=%t addressHeld=%t retirementPending=%t err=%v", desired, observed, generation, revoked, blocked, addressHeld, retirementPending, err)
	}
	var count int
	var actor string
	var metadata []byte
	err = f.pool.QueryRow(f.ctx, `SELECT count(*),min(actor_system),min(metadata::text)::jsonb FROM audit_logs WHERE org_id=$1 AND target_id=$2 AND action='sandbox.eligibility_withdraw'`, f.org, v.Identity.ID.String()).Scan(&count, &actor, &metadata)
	var audit struct {
		OwnerID        uuid.UUID `json:"owner_id"`
		Generation     int64     `json:"generation"`
		DesiredState   string    `json:"desired_state"`
		CleanupPending bool      `json:"cleanup_pending"`
		Cause          string    `json:"cause"`
	}
	if err != nil || count != 1 || actor != "sandbox-eligibility-reconciler" || json.Unmarshal(metadata, &audit) != nil || audit.OwnerID != v.Identity.CreatorID || audit.Generation != v.Revision+1 || audit.DesiredState != "deleted" || !audit.CleanupPending || audit.Cause != "current_authority_withdrawn" {
		t.Fatalf("system withdrawal audit: count=%d actor=%s audit=%+v err=%v", count, actor, audit, err)
	}
	_, total, workloads, err := f.store.retainedCounts(f.ctx, f.pool, f.org, f.other)
	if err != nil || total != 1 || workloads != 1 {
		t.Fatalf("withdrawal released retained capacity: total=%d workloads=%d err=%v", total, workloads, err)
	}
}

func TestOrganizationEligibilityWithdrawsCurrentAuthorityPostgres(t *testing.T) {
	for _, scenario := range []string{"member-removed", "member-access-revoked", "device-reassigned", "device-revoked", "device-health-blocked", "owner-deactivated", "gateway-inactive"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, device, _, in := newEligibilityFixture(t)
			v, _, err := f.store.Create(f.ctx, f.org, f.user, in)
			if err != nil {
				t.Fatal(err)
			}
			peer, token := bindEligibilityRuntime(t, f, v)
			switch scenario {
			case "member-removed":
				eligibilityExec(t, f, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
			case "member-access-revoked":
				eligibilityExec(t, f, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
			case "device-reassigned":
				eligibilityExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, device, f.other)
			case "device-revoked":
				eligibilityExec(t, f, `UPDATE devices SET status='revoked' WHERE id=$1`, device)
			case "device-health-blocked":
				eligibilityExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
			case "owner-deactivated":
				eligibilityExec(t, f, `UPDATE users SET status='deactivated' WHERE id=$1`, f.user)
			case "gateway-inactive":
				eligibilityExec(t, f, `UPDATE nodes SET status='revoked' WHERE id=$1`, f.node)
			}
			if _, err = f.store.AuthenticateRuntime(f.ctx, token); !errors.Is(err, ErrRuntimeUnauthorized) {
				t.Fatalf("lost current authority authenticated before sweep: %v", err)
			}
			var unchanged bool
			if err = f.pool.QueryRow(f.ctx, `SELECT s.desired_state='started' AND s.generation=$2 AND c.revoked_at IS NULL AND NOT d.health_blocked FROM sandboxes s JOIN sandbox_runtime_credentials c ON c.sandbox_id=s.id JOIN devices d ON d.id=s.peer_id WHERE s.id=$1`, v.Identity.ID, v.Revision).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("runtime refusal claimed reconciliation before sweep", err)
			}
			if scenario == "device-reassigned" {
				if withdrawn, err := f.store.WithdrawIneligible(f.ctx, v.Identity.ID); err != nil || !withdrawn {
					t.Fatal("direct withdrawal refused immutable cleanup identity", withdrawn, err)
				}
			} else if err = f.store.SweepEligibility(f.ctx, f.org, 2); err != nil {
				t.Fatal(err)
			}
			if err = f.store.SweepEligibility(f.ctx, f.org, 2); err != nil {
				t.Fatal(err)
			}
			if withdrawn, err := f.store.WithdrawIneligible(f.ctx, v.Identity.ID); err != nil || !withdrawn {
				t.Fatal("idempotent withdrawal", withdrawn, err)
			}
			assertEligibilityWithdrawal(t, f, v, peer)
		})
	}
}

func TestOrganizationEligibilityRetainsQuotaUntilConfirmedRetirementPostgres(t *testing.T) {
	f, _, device, otherDevice, in := newEligibilityFixture(t)
	v, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := bindEligibilityRuntime(t, f, v)
	eligibilityExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	if err = f.store.SweepEligibility(f.ctx, f.org, 2); err != nil {
		t.Fatal(err)
	}
	assertEligibilityWithdrawal(t, f, v, peer)
	next := in
	next.IdempotencyKey, next.TerminalDeviceID = "next-owner", &otherDevice
	assertQuota := func() {
		t.Helper()
		if _, _, err := f.store.Create(f.ctx, f.org, f.other, next); !errors.Is(err, ErrQuota) {
			t.Fatalf("unretired workload released quota: %v", err)
		}
	}
	assertQuota()
	provider := &cleanupProvider{exists: true, running: true}
	offline := errors.New("synthetic network unavailable")
	if err = f.store.ReconcileCleanup(f.ctx, v.Identity.ID, provider, cleanupNetworkFunc(func(_ context.Context, _ Sandbox) (Withdrawal, error) { return Withdrawal{}, offline })); !errors.Is(err, offline) || provider.deletes != 0 {
		t.Fatal("unconfirmed network withdrawal deleted provider", err)
	}
	assertQuota()
	if err = f.store.ReconcileCleanup(f.ctx, v.Identity.ID, provider, cleanupNetworkFunc(func(_ context.Context, current Sandbox) (Withdrawal, error) { return matchingWithdrawal(current), nil })); err != nil || provider.deletes != 1 {
		t.Fatal("confirmed cleanup failed", err)
	}
	var deleted, retired bool
	if err = f.pool.QueryRow(f.ctx, `SELECT s.observed_state='deleted',r.worker_retired_at IS NOT NULL FROM sandboxes s JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id WHERE s.id=$1`, v.Identity.ID).Scan(&deleted, &retired); err != nil || !deleted || retired {
		t.Fatal("cleanup conflated provider deletion with worker retirement", err)
	}
	assertQuota()
	// A synthetic trusted retirement receipt follows the confirmed tombstone.
	eligibilityExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=clock_timestamp() WHERE sandbox_id=$1`, v.Identity.ID)
	if nextSandbox, _, err := f.store.Create(f.ctx, f.org, f.other, next); err != nil || nextSandbox.Identity.CreatorID != f.other {
		t.Fatal("confirmed retirement did not release next-owner capacity", err)
	}
}

// Synthetic historical inventory deliberately bypasses admission quotas, solely
// to verify a deployment's cleanup scope cannot select another deployment's row.
func seedEligibilityInventory(t *testing.T, f fixture, org, owner, template, terminal uuid.UUID, localGateway any) uuid.UUID {
	t.Helper()
	id := uuid.New()
	eligibilityExec(t, f, `INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,idempotency_key,request_hash,expires_at,terminal_device_id,local_terminal_gateway_id) VALUES($1,$2,$3,$4,'synthetic inventory','[]',$5,$6,now()+interval '900 seconds',$7,$8)`, id, org, owner, template, id.String(), make([]byte, 32), terminal, localGateway)
	return id
}

func TestOrganizationEligibilitySweepRequiresExactRemoteRoutePostgres(t *testing.T) {
	f, b, device, otherDevice, in := newEligibilityFixture(t)
	runtime, otherGateway := uuid.New(), uuid.New()
	for i, gateway := range []uuid.UUID{runtime, otherGateway} {
		eligibilityExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial,status,wg_public_key) VALUES($1,$2,$3,$3,'active',$4)`, gateway, f.org, gateway.String(), strings.Repeat(string(rune('f'+i)), 43)+"=")
	}
	b.GatewayID = runtime
	b.RemoteTerminal = &RemoteTerminalBinding{GatewayID: f.node, GatewayEndpoint: "172.16.0.2:51820", RuntimeGatewayEndpoint: "172.16.0.3:51821"}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	v, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	var unowned []uuid.UUID
	for _, scenario := range []string{"terminal-endpoint", "runtime-endpoint", "terminal-gateway", "runtime-gateway", "terminal-device", "missing-route"} {
		id := seedEligibilityInventory(t, f, f.org, f.user, in.TemplateID, device, nil)
		unowned = append(unowned, id)
		terminalGateway, runtimeGateway, selectedDevice := f.node, runtime, device
		terminalEndpoint, runtimeEndpoint := b.RemoteTerminal.GatewayEndpoint, b.RemoteTerminal.RuntimeGatewayEndpoint
		switch scenario {
		case "terminal-endpoint":
			terminalEndpoint = "172.16.0.4:51820"
		case "runtime-endpoint":
			runtimeEndpoint = "172.16.0.5:51821"
		case "terminal-gateway":
			terminalGateway = otherGateway
		case "runtime-gateway":
			runtimeGateway = otherGateway
		case "terminal-device":
			selectedDevice = otherDevice
		case "missing-route":
			continue
		}
		eligibilityExec(t, f, `INSERT INTO sandbox_remote_terminal_routes(sandbox_id,org_id,terminal_device_id,terminal_gateway_id,runtime_gateway_id,terminal_gateway_endpoint,runtime_gateway_endpoint) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, f.org, selectedDevice, terminalGateway, runtimeGateway, terminalEndpoint, runtimeEndpoint)
	}
	eligibilityExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	for _, id := range unowned {
		if eligible, err := sandboxEligible(f.ctx, f.pool, id); err != nil || eligible {
			t.Fatal("unowned route fixture must itself be ineligible", eligible, err)
		}
		if withdrawn, err := f.store.WithdrawIneligible(f.ctx, id); err != nil || withdrawn {
			t.Fatal("withdrawal crossed exact operator route", withdrawn, err)
		}
	}
	if err = f.store.SweepEligibility(f.ctx, f.org, 2); err != nil {
		t.Fatal(err)
	}
	var withdrawn bool
	if err = f.pool.QueryRow(f.ctx, `SELECT desired_state='deleted' AND generation=$2 AND observed_state='creating' FROM sandboxes WHERE id=$1`, v.Identity.ID, v.Revision+1).Scan(&withdrawn); err != nil || !withdrawn {
		t.Fatal("configured invalid remote route not withdrawn", err)
	}
	assertEligibilityInventoryUntouched(t, f, unowned...)
}

func assertEligibilityInventoryUntouched(t *testing.T, f fixture, ids ...uuid.UUID) {
	t.Helper()
	for _, id := range ids {
		var untouched bool
		if err := f.pool.QueryRow(f.ctx, `SELECT generation=1 AND desired_state='started' AND observed_state='creating' AND NOT EXISTS(SELECT 1 FROM audit_logs WHERE target_id=s.id::text AND action='sandbox.eligibility_withdraw') FROM sandboxes s WHERE id=$1`, id).Scan(&untouched); err != nil || !untouched {
			t.Fatalf("unowned or eligible inventory %s changed: %v", id, err)
		}
	}
}

func TestOrganizationEligibilitySweepOnlyConfiguredInventoryPostgres(t *testing.T) {
	f, b, device, otherDevice, in := newEligibilityFixture(t)
	v, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	validOther := seedEligibilityInventory(t, f, f.org, f.other, in.TemplateID, otherDevice, f.node)
	unownedTemplate := seedEligibilityInventory(t, f, f.org, f.user, f.template, device, f.node)
	foreignGateway := uuid.New()
	eligibilityExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'unowned gateway',$3)`, foreignGateway, f.org, foreignGateway.String())
	unownedGateway := seedEligibilityInventory(t, f, f.org, f.user, in.TemplateID, device, foreignGateway)
	foreignOrg, foreignTemplate, foreignDevice, foreignNode := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	eligibilityExec(t, f, `INSERT INTO organizations(id,name,slug,zero_trust_mode,sandboxes_enabled) VALUES($1,'unowned org',$2,'enforcing',true)`, foreignOrg, foreignOrg.String())
	eligibilityExec(t, f, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'unowned template',$3,'[]',128,900,true)`, foreignTemplate, foreignOrg, b.Profiles[0].ConfigDigest)
	eligibilityExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'unowned node',$3)`, foreignNode, foreignOrg, foreignNode.String())
	eligibilityExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,kind,health_blocked) VALUES($1,$2,$3,$4,'unowned terminal',$5,'human',true)`, foreignDevice, foreignOrg, f.user, foreignNode, strings.Repeat("e", 43)+"=")
	unownedOrg := seedEligibilityInventory(t, f, foreignOrg, f.user, foreignTemplate, foreignDevice, foreignNode)
	eligibilityExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	for _, id := range []uuid.UUID{unownedTemplate, unownedGateway, unownedOrg} {
		if eligible, err := sandboxEligible(f.ctx, f.pool, id); err != nil || eligible {
			t.Fatal("unowned fixture must itself be ineligible", eligible, err)
		}
		if withdrawn, err := f.store.WithdrawIneligible(f.ctx, id); err != nil || withdrawn {
			t.Fatal("direct withdrawal crossed configured inventory", withdrawn, err)
		}
	}
	if eligible, err := sandboxEligible(f.ctx, f.pool, validOther); err != nil || !eligible {
		t.Fatal("other creator's current device was invalidated", eligible, err)
	}
	if err := f.store.SweepEligibility(f.ctx, foreignOrg, 2); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign sweep org accepted", err)
	}
	for _, limit := range []int{0, 101} {
		if err := f.store.SweepEligibility(f.ctx, f.org, limit); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbounded sweep accepted", err)
		}
	}
	if err = f.store.SweepEligibility(f.ctx, uuid.Nil, 2); err != nil {
		t.Fatal(err)
	}
	var withdrawn bool
	if err = f.pool.QueryRow(f.ctx, `SELECT desired_state='deleted' AND generation=$2 AND observed_state='creating' FROM sandboxes WHERE id=$1`, v.Identity.ID, v.Revision+1).Scan(&withdrawn); err != nil || !withdrawn {
		t.Fatal("configured invalid workload not withdrawn", err)
	}
	assertEligibilityInventoryUntouched(t, f, validOther, unownedTemplate, unownedGateway, unownedOrg)
}

func TestLegacyBoundedRuntimeEligibilitySweepRemainsDormantPostgres(t *testing.T) {
	f, b, device, _, in := newEligibilityFixture(t)
	b.Admission, b.CreatorID, b.TerminalDeviceID = "", f.user, device
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	v, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	eligibilityExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	if err = f.store.SweepEligibility(f.ctx, f.org, 2); err != nil {
		t.Fatal(err)
	}
	if withdrawn, err := f.store.WithdrawIneligible(f.ctx, v.Identity.ID); err != nil || withdrawn {
		t.Fatal("legacy binding gained org-mode cleanup", withdrawn, err)
	}
	assertEligibilityInventoryUntouched(t, f, v.Identity.ID)
}
