package appaccess

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"testing"
	"time"
)

func TestConnectorLocalDatabase(t *testing.T) {
	pool := grantPool(t)
	if e := db.MigrateTo(pool.Config().ConnString(), 174); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	org, actor, gw := uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Connector','connector')", org)
	exec("INSERT INTO users(id,email,name)VALUES($1,'connector@test.fixture','Connector')", actor)
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'connector','current',now()+interval '1 day','gateway')", gw, org)
	s := NewService(pool, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	if _, e := s.UpdateSettings(ctx, org, actor, true, 1, true); e != nil {
		t.Fatal(e)
	}
	in := DraftInput{Name: "Connector", OriginURL: "http://origin", GatewayID: gw, PublicHostname: "connector.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300, AllowedDestinationCIDRs: []string{"10.0.0.5/24"}}
	a, e := s.CreateDraft(ctx, org, actor, in, true)
	if e != nil {
		t.Fatal(e)
	}
	if a.Draft.AllowedDestinationCIDRs[0] != "10.0.0.0/24" {
		t.Fatal("policy not canonical")
	}
	g := AuthenticatedGateway{org, gw, "current"}
	if _, e = s.RequestCheck(ctx, org, actor, a.ID, a.Version, true); e == nil {
		t.Fatal("unknown capability accepted")
	}
	if _, e = s.ReportCapability(ctx, g, 1); e != nil {
		t.Fatal(e)
	}
	c, e := s.RequestCheck(ctx, org, actor, a.ID, a.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.RequestCheck(ctx, org, actor, a.ID, a.Version, true)
	if e != nil || same.ID != c.ID {
		t.Fatal("pending check not reused", e)
	}
	d, e := s.DesiredForGateway(ctx, g, true)
	if e != nil || len(d.Checks) != 1 || len(d.Assignments) != 1 || d.Checks[0].Status != "running" {
		t.Fatalf("desired %+v %v", d, e)
	}
	lease, e := s.AuthorizeChannel(ctx, g, a.ID, c.Generation, c.Revision, c.Digest, c.Purpose, true)
	if e != nil || lease.After(time.Now().Add(6*time.Second)) {
		t.Fatal("lease", e)
	}
	// Database latency consumes the lease; it never restarts the validity window.
	decisionStart := time.Now().UTC()
	calls := 0
	delayedConfig := s.config
	delayedConfig.Now = func() time.Time {
		calls++
		if calls == 1 {
			return decisionStart
		}
		return decisionStart.Add(3 * time.Second)
	}
	delayedService := NewService(pool, delayedConfig)
	bounded, e := delayedService.AuthorizeChannel(ctx, g, a.ID, c.Generation, c.Revision, c.Digest, c.Purpose, true)
	if e != nil || !bounded.Equal(decisionStart.Add(5*time.Second)) {
		t.Fatal("decision latency extended channel lease", bounded, e)
	}
	calls = 0
	delayedConfig.Now = func() time.Time {
		calls++
		if calls == 1 {
			return decisionStart
		}
		return decisionStart.Add(6 * time.Second)
	}
	delayedService = NewService(pool, delayedConfig)
	if _, e = delayedService.AuthorizeChannel(ctx, g, a.ID, c.Generation, c.Revision, c.Digest, c.Purpose, true); e == nil {
		t.Fatal("expired decision admitted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.AuthorizeChannel(canceled, g, a.ID, c.Generation, c.Revision, c.Digest, c.Purpose, true); e == nil {
		t.Fatal("canceled decision admitted")
	}
	r := Result{RequestID: c.ID, AppID: a.ID, Generation: c.Generation, Revision: c.Revision, Digest: c.Digest, Purpose: c.Purpose, DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}
	done, e := s.CompleteCheck(ctx, g, r, true)
	if e != nil || done.Status != "succeeded" {
		t.Fatal("completion", done, e)
	}
	if _, e = s.CompleteCheck(ctx, g, r, true); e == nil {
		t.Fatal("replay accepted")
	}
	if _, e = s.ReportApplied(ctx, g, Applied{AppID: a.ID, Generation: c.Generation, Revision: c.Revision, Digest: c.Digest, Purpose: c.Purpose, Status: "configured"}, true); e != nil {
		t.Fatal(e)
	}
	in.AllowedDestinationCIDRs = nil
	a, e = s.UpdateDraft(ctx, org, actor, a.ID, in, a.Version, true)
	if e != nil || len(a.Draft.AllowedDestinationCIDRs) != 1 {
		t.Fatal("omission lost policy", e)
	}
	if _, e = s.AuthorizeChannel(ctx, g, a.ID, c.Generation, c.Revision, c.Digest, c.Purpose, true); e == nil {
		t.Fatal("stale revision authorized")
	}
	in.AllowedDestinationCIDRsSet = true
	a, e = s.UpdateDraft(ctx, org, actor, a.ID, in, a.Version, true)
	if e != nil || len(a.Draft.AllowedDestinationCIDRs) != 0 {
		t.Fatal("explicit empty did not clear", e)
	}
	old, e := s.GetRevision(ctx, org, a.ID, 1)
	if e != nil || len(old.AllowedDestinationCIDRs) != 1 {
		t.Fatal("history changed", e)
	}
	c, e = s.RequestCheck(ctx, org, actor, a.ID, a.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	d, e = s.DesiredForGateway(ctx, g, false)
	if e != nil || !d.Withdrawn || len(d.Assignments) != 0 {
		t.Fatal("feature loss not withdrawn", e)
	}
	check, e := s.GetCheck(ctx, org, a.ID, c.ID)
	if e != nil || check.Status != "withdrawn" {
		t.Fatal("pending check survived feature loss", e)
	}
	exec("UPDATE nodes SET cert_serial='rotated' WHERE id=$1", gw)
	if _, e = s.ReportCapability(ctx, g, 1); e == nil {
		t.Fatal("old certificate accepted")
	}
	g.CertSerial = "rotated"
	if _, e = s.ReportCapability(ctx, g, 0); e != nil {
		t.Fatal(e)
	}
	d, e = s.DesiredForGateway(ctx, g, true)
	if e != nil || d.Reason != "capability_unsupported" {
		t.Fatal("legacy capability", e)
	}
	if _, e = s.GetCheck(ctx, uuid.New(), a.ID, c.ID); e == nil {
		t.Fatal("cross tenant check leaked")
	}
	if _, e = s.ReportCapability(ctx, g, 1); e != nil {
		t.Fatal(e)
	}
	c, e = s.RequestCheck(ctx, org, actor, a.ID, a.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DesiredForGateway(ctx, g, true); e != nil {
		t.Fatal(e)
	}
	r = Result{RequestID: c.ID, AppID: a.ID, Generation: c.Generation, Revision: c.Revision, Digest: c.Digest, Purpose: c.Purpose, DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped", ErrorCode: "connector_failed"}
	exec(`CREATE FUNCTION aa3_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.origin_check_completed' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER aa3_fail_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION aa3_fail_audit()`)
	if _, e = s.CompleteCheck(ctx, g, r, true); e == nil {
		t.Fatal("completion swallowed audit failure")
	}
	check, e = s.GetCheck(ctx, org, a.ID, c.ID)
	if e != nil || check.Status != "running" {
		t.Fatal("completion audit did not rollback", e)
	}
	exec("DROP TRIGGER aa3_fail_audit ON audit_logs; DROP FUNCTION aa3_fail_audit()")
	check, e = s.CompleteCheck(ctx, g, r, true)
	if e != nil || check.Status != "failed" {
		t.Fatal("HTTP probe failure marked successful", e)
	}
	var system string
	if e = pool.QueryRow(ctx, "SELECT actor_system FROM audit_logs WHERE action='app_access.origin_check_completed' AND target_id=$1", c.ID.String()).Scan(&system); e != nil || system != "app-access-connector" {
		t.Fatal("missing system actor", e)
	}
	// The assigned tuple is immutable even for direct database writes.
	if _, e = pool.Exec(ctx, "UPDATE app_access_connector_assignments SET digest=repeat('0',64) WHERE generation=$1", c.Generation); e == nil {
		t.Fatal("assignment tuple mutable")
	}
	if _, e = pool.Exec(ctx, "UPDATE app_access_origin_checks SET app_id=$1 WHERE id=$2", uuid.New(), c.ID); e == nil {
		t.Fatal("check tuple mutable")
	}
	// Moving an application retires old work even when the old gateway never polls.
	oldPending, e := s.RequestCheck(ctx, org, actor, a.ID, a.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	newGateway := uuid.New()
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'newconnector','newcurrent',now()+interval '1 day','gateway')", newGateway, org)
	newIdentity := AuthenticatedGateway{org, newGateway, "newcurrent"}
	if _, e = s.ReportCapability(ctx, newIdentity, 1); e != nil {
		t.Fatal(e)
	}
	moved := in
	moved.GatewayID = newGateway
	a, e = s.UpdateDraft(ctx, org, actor, a.ID, moved, a.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RequestCheck(ctx, org, actor, a.ID, a.Version, true); e != nil {
		t.Fatal(e)
	}
	previous, e := s.GetCheck(ctx, org, a.ID, oldPending.ID)
	if e != nil || previous.Status != "withdrawn" {
		t.Fatal("offline old gateway prevented finalization", e)
	}
	// Eight dispatched checks plus 32 queued are allowed; the next is rejected.
	var capacityApp Application
	for i := 0; i < 41; i++ {
		input := in
		input.Name = fmt.Sprintf("Capacity%d", i)
		input.PublicHostname = fmt.Sprintf("capacity%d.apps.fixture.test", i)
		capacityApp, e = s.CreateDraft(ctx, org, actor, input, true)
		if e != nil {
			t.Fatal(e)
		}
		_, e = s.RequestCheck(ctx, org, actor, capacityApp.ID, capacityApp.Version, true)
		if i == 40 {
			if e == nil {
				t.Fatal("queue capacity exceeded")
			}
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if i == 7 {
			if _, e = s.DesiredForGateway(ctx, g, true); e != nil {
				t.Fatal(e)
			}
		}
	}
	d, e = s.DesiredForGateway(ctx, g, true)
	if e != nil || len(d.Checks) != 8 {
		t.Fatal("running bound", len(d.Checks), e)
	}

	down, e := db.MigrationsFS.ReadFile("migrations/0169_app_access_connector.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, string(down))
	_ = tx.Rollback(ctx)
	if e == nil {
		t.Fatal("connector history destructively rolled down")
	}

}

func TestOriginPolicyDraftDigest(t *testing.T) {
	s := NewService(nil, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	in := DraftInput{Name: "Policy", OriginURL: "https://origin", GatewayID: uuid.New(), PublicHostname: "policy.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	_, empty, e := s.validate(in)
	if e != nil {
		t.Fatal(e)
	}
	in.AllowedDestinationCIDRs = []string{"10.0.0.5/24", "10.0.0.0/24"}
	normalized, digest, e := s.validate(in)
	if e != nil || len(normalized.AllowedDestinationCIDRs) != 1 || digest == empty {
		t.Fatal("policy normalization/digest", e)
	}
	in.AllowedDestinationCIDRsSet = true
	_, same, e := s.validate(in)
	if e != nil || same != digest {
		t.Fatal("presence flags altered digest", e)
	}
	in.AllowedDestinationCIDRs = []string{"0.0.0.0/0"}
	if _, _, e = s.validate(in); e == nil {
		t.Fatal("blanket private allowance accepted")
	}
	in.AllowedDestinationCIDRs = nil
	in.OriginCAPEM = "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----"
	if _, _, e = s.validate(in); e == nil {
		t.Fatal("private key accepted")
	}
}
