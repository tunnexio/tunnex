package devices

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// TestAI0CommunityEnrollmentIdentityPreservesManagedRuntimeGate proves that
// base enrollment/current-credential authentication is available with the
// actual Community licence defaults, independently of managed runtime opt-in.
// It makes no claim about an AI endpoint, Bifrost, or provider execution.
func TestAI0CommunityEnrollmentIdentityPreservesManagedRuntimeGate(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'AI0 Community',$2,'10.99.0.0/24',0)`, org, "ai0-community-"+org.String())
	exec(`INSERT INTO users (id,email,name,status) VALUES ($1,$2,'AI0 Community owner','active')`, owner, owner.String()+"@ai0-community.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, owner)
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 11)
	}
	gatewayKey := base64.StdEncoding.EncodeToString(keyBytes)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'ai0-community-gateway',$3,$4,'gateway.example:51820','active')`, node, org, "ai0-community-"+node.String(), gatewayKey)
	manager := &licence.Manager{}
	if status := manager.Evaluate(time.Now()); status.Tier != licence.TierCommunity || status.State != licence.StateUnlicensed {
		t.Fatalf("fixture is not unlicensed Community: %+v", status)
	}
	svc := NewService(pool, nodepush.New(), nil).WithLicence(manager)
	queries := sqlc.New(pool)
	persisted, err := queries.GetOrganizationByID(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ManagedAgentRuntimeEnabled {
		t.Fatal("managed runtime must default off")
	}
	unavailable := agentruntime.OrganizationOptIn(queries, func() bool { return false })
	state, err := unavailable(ctx, org)
	if err != nil || state != agentruntime.OptInUnavailable {
		t.Fatalf("locked runtime state=%s err=%v", state, err)
	}
	disabled := agentruntime.OrganizationOptIn(queries, func() bool { return true })
	state, err = disabled(ctx, org)
	if err != nil || state != agentruntime.OptInDisabled {
		t.Fatalf("unlocked default runtime state=%s err=%v", state, err)
	}
	bootstrap, err := svc.IssueAgentBootstrapToken(ctx, owner, org, node, "ai0-community-agent")
	if err != nil {
		t.Fatal(err)
	}
	keyBytes[0]++
	clientPublicKey := base64.StdEncoding.EncodeToString(keyBytes)
	enrolled, err := svc.Create(ctx, CreateInput{BootstrapToken: bootstrap, PublicKey: clientPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.RuntimeCredential == "" || enrolled.PrivateKeyOneTime != "" {
		t.Fatal("enrollment must return runtime identity while preserving client private key ownership")
	}
	if enrolled.Device.PublicKey != clientPublicKey || enrolled.Device.Kind != "agent" {
		t.Fatal("enrollment did not preserve agent kind/public key")
	}
	runtime := agentruntime.New(pool, unavailable)
	identity, err := runtime.AuthenticateCurrent(ctx, enrolled.RuntimeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if identity.OrgID != org || identity.DeviceID != enrolled.Device.ID || identity.CredentialRevision != 1 || identity.CredentialState != "current" {
		t.Fatalf("wrong current identity binding: %+v", identity)
	}
	if _, _, err := runtime.Poll(ctx, identity, 0, 1, "ai0-community-fixture"); !errors.Is(err, agentruntime.ErrOptInUnavailable) {
		t.Fatalf("locked managed runtime poll error=%v", err)
	}
	// A persisted opt-in cannot override a missing unlock. Only this disposable
	// fixture is changed; Community's production gate is left intact.
	exec(`UPDATE organizations SET managed_agent_runtime_enabled=true WHERE id=$1`, org)
	state, err = unavailable(ctx, org)
	if err != nil || state != agentruntime.OptInUnavailable {
		t.Fatalf("opt-in bypassed unlock: state=%s err=%v", state, err)
	}
	if _, _, err := runtime.Poll(ctx, identity, 0, 1, "ai0-community-fixture"); !errors.Is(err, agentruntime.ErrOptInUnavailable) {
		t.Fatalf("persisted opt-in bypassed locked poll: %v", err)
	}
	for _, invalid := range []string{bootstrap, enrolled.RuntimeCredential + "invalid"} {
		if _, err := runtime.AuthenticateCurrent(ctx, invalid); !errors.Is(err, agentruntime.ErrUnauthorized) {
			t.Fatalf("invalid bearer accepted: %v", err)
		}
	}
	if err := svc.Revoke(ctx, org, owner, enrolled.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AuthenticateCurrent(ctx, enrolled.RuntimeCredential); !errors.Is(err, agentruntime.ErrUnauthorized) {
		t.Fatalf("revoked enrolled identity authenticated: %v", err)
	}
	t.Log("unlicensed Community bootstrap enrollment/current identity succeeded; org/device/revision bound; managed runtime default off and locked even after persisted opt-in; invalid/revoked identity refused")
}
