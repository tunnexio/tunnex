package serveraccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func installationCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func installationFixture(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	admin := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, admin, admin.String()+"@example.invalid"); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, admin
}

// fresh drops the one-second cache so a test observes the database, as another replica would.
func fresh(s *Service) *Service {
	s.setInstallationCache(false)
	s.install.readAt = time.Time{}
	return s
}

func TestInstallationEnvironmentSeedsUntilFirstSave(t *testing.T) {
	ctx, pool, admin := installationFixture(t)
	off := New(pool, nil, nil, false)
	v, err := off.Installation(ctx)
	if err != nil || v.Enabled || v.Effective || v.Source != "environment" || v.Version != 0 {
		t.Fatalf("seed off view = %+v, %v", v, err)
	}
	if off.InstallationEffective(ctx) || off.available() == nil {
		t.Fatal("seed off admitted terminal capability")
	}
	// An install that wrote TUNNEX_SERVER_ACCESS_ENABLED=false enables from the dashboard.
	v, _, err = off.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: true, ExpectedVersion: 0})
	if err != nil || !v.Enabled || !v.Effective || v.Source != "database" || v.Version != 1 {
		t.Fatalf("enable = %+v, %v", v, err)
	}
	// After the first save the database wins over any seed, on every replica.
	for _, seed := range []bool{false, true} {
		replica := fresh(New(pool, nil, nil, seed))
		if !replica.InstallationEffective(ctx) {
			t.Fatalf("seed %v replica ignored saved value", seed)
		}
	}
	if _, _, err = off.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: false, ExpectedVersion: 0}); installationCode(err) != "server_access_installation_changed" {
		t.Fatalf("stale version accepted: %v", err)
	}
	v, _, err = off.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: false, ExpectedVersion: 1})
	if err != nil || v.Enabled || v.Effective || v.Version != 2 {
		t.Fatalf("disable = %+v, %v", v, err)
	}
	if fresh(New(pool, nil, nil, true)).InstallationEffective(ctx) {
		t.Fatal("seed true overrode a saved off")
	}
	var audits int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='server_access.installation_updated' AND actor_user_id=$1 AND target_id='deployment' AND org_id IS NULL`, admin).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit rows = %d, %v", audits, err)
	}
}

func TestInstallationLockForcesOffAndRefusesEnable(t *testing.T) {
	ctx, pool, admin := installationFixture(t)
	if _, _, err := New(pool, nil, nil, false).SaveInstallation(ctx, admin, InstallationUpdate{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	locked := New(pool, nil, nil, true).WithInstallationLock(true)
	v, err := locked.Installation(ctx)
	if err != nil || !v.Enabled || v.Effective || !v.Locked {
		t.Fatalf("locked view = %+v, %v", v, err)
	}
	if locked.InstallationEffective(ctx) || locked.available() == nil {
		t.Fatal("lock did not force the capability off")
	}
	if _, _, err = locked.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: true, ExpectedVersion: 1}); installationCode(err) != "server_access_locked" {
		t.Fatalf("enable while locked = %v", err)
	}
	if v, _, err = locked.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: false, ExpectedVersion: 1}); err != nil || v.Enabled || v.Effective {
		t.Fatalf("disable while locked = %+v, %v", v, err)
	}
}

func TestInstallationReadFailureIsOff(t *testing.T) {
	ctx, pool, _ := installationFixture(t)
	s := New(pool, nil, nil, true)
	if _, err := pool.Exec(ctx, `DROP TABLE server_access_installation_settings`); err != nil {
		t.Fatal(err)
	}
	if fresh(s).InstallationEffective(ctx) {
		t.Fatal("an unreadable installation setting fell back to the environment seed")
	}
}

func TestInstallationAndOrganizationAreBothRequired(t *testing.T) {
	ctx, pool, admin := installationFixture(t)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'SA-UI-1',$2,'10.96.0.0/24')`, org, "saui-"+org.String()); err != nil {
		t.Fatal(err)
	}
	s := New(pool, nil, nil, true)
	if on, err := s.Enabled(ctx, org); err != nil || on {
		t.Fatal("organization without opt-in was enabled", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO server_access_settings(org_id,enabled,ca_private_sealed,ca_public) VALUES($1,true,'unused','unused')`, org); err != nil {
		t.Fatal(err)
	}
	if on, err := s.Enabled(ctx, org); err != nil || !on {
		t.Fatal("organization opt-in with installation on was refused", err)
	}
	if _, _, err := s.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if on, err := s.Enabled(ctx, org); err != nil || on {
		t.Fatal("organization stayed enabled with the installation off", err)
	}
}

func TestInstallationDisableEndsActiveSessions(t *testing.T) {
	ctx, pool, admin := installationFixture(t)
	org, gateway, server := uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'SA-UI-1 sessions',$2,'10.95.0.0/24')`, org, "sauis-"+org.String())
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'gw','saui-cert','saui-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	seed(`INSERT INTO server_access_settings(org_id,enabled,ca_private_sealed,ca_public) VALUES($1,true,'unused','unused')`, org)
	seed(`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled) VALUES($1,$2,$3,'Linux','10.1.2.3',22,'SHA256:fixture',ARRAY['ubuntu'],true)`, server, org, gateway)
	for _, status := range []string{"pending", "connected", "connected", "ended"} {
		seed(`INSERT INTO server_access_sessions(org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,'x','x',1,'ubuntu',1,'saui-cert','terminal',$5,now()+interval '1 hour',now()+interval '1 hour',false)`, org, server, gateway, admin, status)
	}
	s := New(pool, nil, nil, true)
	v, ended, err := s.SaveInstallation(ctx, admin, InstallationUpdate{Enabled: false})
	if err != nil || v.Effective || ended != 3 {
		t.Fatalf("disable = %+v ended=%d err=%v", v, ended, err)
	}
	var active, reasoned, audited int
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('pending','connecting','connected')), count(*) FILTER (WHERE reason=$1) FROM server_access_sessions`, ReasonInstallationDisabled).Scan(&active, &reasoned); err != nil || active != 0 || reasoned != 3 {
		t.Fatalf("sessions active=%d reasoned=%d err=%v", active, reasoned, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='server_access.session_ended' AND metadata->>'reason'=$1`, ReasonInstallationDisabled).Scan(&audited); err != nil || audited != 3 {
		t.Fatalf("session end audits = %d, %v", audited, err)
	}
	if _, err = s.StartSession(ctx, org, nil, api.ServerAccessConnectInput{ServerId: server, Account: "ubuntu"}, false); installationCode(err) != "server_access_disabled" {
		t.Fatalf("new session after disable = %v", err)
	}
}
