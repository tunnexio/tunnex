package serveraccess

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// SA-UX-3 bug 2: a server whose host trust is pending is registered and edited without ever seeing the placeholder,
// and the placeholder can never be saved as a pin.
func TestPendingTrustNeverRoundTripsThePlaceholder(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	sealer, _ := secret.NewSealer(make([]byte, 32))
	svc := New(pool, nil, sealer, true)
	org, user, gateway := uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'Pending trust fixture',$2,'10.95.0.0/24')`, org, "pending-trust-"+org.String())
	seed(`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, user, user.String()+"@example.invalid")
	seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['owner'])`, org, user)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'gw','pending-trust-cert','pending-trust-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	if e := svc.Configure(ctx, org, user, api.ServerAccessSettingsInput{Enabled: true}); e != nil {
		t.Fatal(e)
	}
	stored := func(id uuid.UUID) (fp string, accounts []string) {
		t.Helper()
		if e := pool.QueryRow(ctx, `SELECT host_fingerprint,accounts FROM server_access_servers WHERE id=$1`, id).Scan(&fp, &accounts); e != nil {
			t.Fatal(e)
		}
		return
	}
	in := api.ServerAccessServerInput{GatewayId: gateway, Name: "pending", PrivateIp: "10.1.2.3", SshPort: 2222, HostFingerprint: "", Accounts: []string{}, IdleTimeoutSeconds: 300, MaxSessionSeconds: 900}
	created, e := svc.SaveServer(ctx, org, user, uuid.Nil, in)
	if e != nil {
		t.Fatal(e)
	}
	pendingView := func(v api.ServerAccessServer) bool { return v.HostFingerprint != nil && *v.HostFingerprint == "" }
	if !pendingView(created) {
		t.Fatalf("placeholder returned on create: %v", created.HostFingerprint)
	}
	if fp, _ := stored(created.Id); fp != PendingHostFingerprint {
		t.Fatalf("pending server stored with %q", fp)
	}
	principal := &authctx.Principal{UserID: user, RoleSets: map[uuid.UUID][]string{org: {"owner"}}}
	workspace, e := svc.Workspace(ctx, org, principal)
	if e != nil || len(workspace.Servers) != 1 || !pendingView(workspace.Servers[0]) {
		t.Fatalf("workspace leaks the placeholder: %+v %v", workspace.Servers, e)
	}

	// Editing other fields of a pending server (empty fingerprint, as the dashboard sends) keeps trust pending.
	in.Name, in.Revision = "renamed", created.Revision
	renamed, e := svc.SaveServer(ctx, org, user, created.Id, in)
	if e != nil || !pendingView(renamed) || renamed.Name != "renamed" {
		t.Fatalf("pending edit: %+v %v", renamed, e)
	}
	// An older bundle that echoes the placeholder for a pending server still works.
	in.HostFingerprint, in.Revision = PendingHostFingerprint, renamed.Revision
	echoed, e := svc.SaveServer(ctx, org, user, created.Id, in)
	if e != nil || !pendingView(echoed) {
		t.Fatalf("placeholder echo for a pending server refused: %v", e)
	}

	// The bug: typing accounts while the placeholder sits in the fingerprint field must never pin it.
	in.Accounts, in.Revision = []string{"ubuntu"}, echoed.Revision
	var refused *apierr.Error
	if _, e = svc.SaveServer(ctx, org, user, created.Id, in); !errors.As(e, &refused) || refused.Code != "host_fingerprint_placeholder" {
		t.Fatalf("placeholder saved as a pin: %v", e)
	}
	if fp, accounts := stored(created.Id); fp != PendingHostFingerprint || len(accounts) != 0 {
		t.Fatalf("refused save changed the server: %q %v", fp, accounts)
	}

	// A real, independently verified pin is saved and returned as is.
	real := "SHA256:" + strings.Repeat("B", 43)
	in.HostFingerprint = real
	pinned, e := svc.SaveServer(ctx, org, user, created.Id, in)
	if e != nil || pinned.HostFingerprint == nil || *pinned.HostFingerprint != real {
		t.Fatalf("real pin: %+v %v", pinned, e)
	}
	// Once trusted, an empty fingerprint is refused rather than silently dropping or replacing the pin.
	in.HostFingerprint, in.Revision = "", pinned.Revision
	if _, e = svc.SaveServer(ctx, org, user, created.Id, in); e == nil {
		t.Fatal("trusted server saved without its pin")
	}
	if fp, _ := stored(created.Id); fp != real {
		t.Fatalf("pin changed to %q", fp)
	}
}
