package appaccess

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

type companyFixture struct {
	t                                                          *testing.T
	ctx                                                        context.Context
	pool                                                       *pgxpool.Pool
	service                                                    *Service
	org, other, admin, manager, next, member, foreign, gateway uuid.UUID
	app, second                                                Application
	parent                                                     *mfaPolicyParent
}

func newCompanyFixture(t *testing.T) *companyFixture {
	t.Helper()
	pool := grantPool(t)
	if err := db.MigrateTo(pool.Config().ConnString(), 178); err != nil {
		t.Fatal(err)
	}
	f := &companyFixture{t: t, ctx: context.Background(), pool: pool, org: uuid.New(), other: uuid.New(), admin: uuid.New(), manager: uuid.New(), next: uuid.New(), member: uuid.New(), foreign: uuid.New(), gateway: uuid.New()}
	f.exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Company',$2),($3,'Foreign',$4)", f.org, f.org.String(), f.other, f.other.String())
	for _, u := range []uuid.UUID{f.admin, f.manager, f.next, f.member, f.foreign} {
		f.exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,$3,now())", u, u.String()+"@fixture.test", "User "+u.String()[:8])
	}
	f.exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner'),($1,$3,'member'),($1,$4,'member'),($1,$5,'member'),($6,$7,'member')", f.org, f.admin, f.manager, f.next, f.member, f.other, f.foreign)
	f.exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'Company gateway','gateway',$3,now()+interval '1 day')", f.gateway, f.org, f.gateway.String())
	now := time.Now().UTC()
	f.parent = &mfaPolicyParent{value: session.Session{ID: uuid.NewString(), UserID: f.member, AuthMethod: authctx.AuthLocalPassword, AppAuthEpoch: 1, ExpiresAt: now.Add(time.Hour)}, until: now.Add(time.Hour)}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := appcrypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	f.service = NewService(pool, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, Now: func() time.Time { return now }}).
		WithSessionAuthority(f.parent, NewAppSessionStore(rdb), sealer, func(context.Context, uuid.UUID) (bool, error) { return false, nil }).
		WithMFAEnrollmentChecker(func(context.Context, uuid.UUID) (bool, error) { return false, nil })
	if _, err = f.service.UpdateSettings(f.ctx, f.org, f.admin, true, 1, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		app, err := f.service.CreateDraft(f.ctx, f.org, f.admin, DraftInput{Name: fmt.Sprintf("Published %d", i), Description: "Public display only", OriginURL: "https://private-secret.fixture:8081", GatewayID: f.gateway, PublicHostname: fmt.Sprintf("company%d-%s.apps.example.net", i, f.org.String()[:8]), IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 3600}, true)
		if err != nil {
			t.Fatal(err)
		}
		f.exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", f.org, app.ID, f.gateway, app.DraftRevision, app.Draft.Digest, app.Draft.PublicHostname)
		if i == 0 {
			f.app = app
		} else {
			f.second = app
		}
	}
	return f
}
func (f *companyFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
		f.t.Fatal(err)
	}
}
func (f *companyFixture) policy(owner *uuid.UUID, visible bool) AccessManagement {
	f.t.Helper()
	old, err := f.service.GetAccessManagement(f.ctx, f.org, f.admin, f.app.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := f.service.UpdateAccessManagement(f.ctx, f.org, f.admin, f.app.ID, visible, owner, old.Version)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *companyFixture) request(user uuid.UUID) AccessRequest {
	f.t.Helper()
	out, err := f.service.CreateAccessRequest(f.ctx, f.org, user, f.app.ID, "Need this for work", true)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}
func TestCompanyCatalogScopedAuthorityLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	s := f.service
	catalog, err := s.CompanyApps(f.ctx, f.org, f.member, f.parent.value.ID, "", 50, 0, true)
	if err != nil || len(catalog.Items) != 0 {
		t.Fatal("default hidden", catalog, err)
	}
	_, err = s.CreateAccessRequest(f.ctx, f.org, f.member, f.app.ID, "", true)
	code(t, err, "application_not_found")
	_, err = s.UpdateAccessManagement(f.ctx, f.org, f.admin, f.app.ID, true, nil, f.app.Version)
	code(t, err, "app_admin_required")
	_, err = s.UpdateAccessManagement(f.ctx, f.org, f.admin, f.app.ID, true, &f.foreign, f.app.Version)
	code(t, err, "application_not_found")
	policy := f.policy(&f.manager, true)
	_, err = s.UpdateAccessManagement(f.ctx, f.org, f.admin, f.app.ID, false, &f.manager, f.app.Version)
	code(t, err, "version_conflict")
	_, err = s.UpdateAccessManagement(f.ctx, f.org, f.manager, f.app.ID, false, &f.manager, policy.Version)
	code(t, err, "forbidden")
	access, err := s.EffectiveAccess(f.ctx, f.org, f.app.ID, f.manager, true)
	if err != nil || access.GrantMatch {
		t.Fatal("assignment conferred content access", access, err)
	}
	catalog, err = s.CompanyApps(f.ctx, f.org, f.member, f.parent.value.ID, "", 50, 0, true)
	if err != nil || len(catalog.Items) != 1 || catalog.Items[0].AccessGranted || catalog.Items[0].LaunchURL != "" || catalog.Items[0].AppAdmin.ID != f.manager {
		t.Fatal("safe opt-in catalog", catalog, err)
	}
	managed, err := s.ManagedApps(f.ctx, f.org, f.manager, nil, 50, 0)
	if err != nil || len(managed.Items) != 1 || managed.Items[0].ID != f.app.ID || managed.CanViewApplications || managed.CanManageGrants {
		t.Fatal("owner scope", managed, err)
	}
	hidden, err := s.ManagedApps(f.ctx, f.org, f.manager, &f.second.ID, 50, 0)
	if err != nil || len(hidden.Items) != 0 {
		t.Fatal("foreign app filter disclosed", hidden, err)
	}
	subjects, err := s.GrantSubjects(f.ctx, f.org, f.manager, f.app.ID, "user", "", 50, 0)
	if err != nil || len(subjects) != 4 {
		t.Fatal("scoped subjects", subjects, err)
	}
	for _, u := range subjects {
		if u.ID == f.foreign {
			t.Fatal("foreign subject disclosed")
		}
	}
	_, err = s.GrantSubjects(f.ctx, f.org, f.manager, f.second.ID, "user", "", 50, 0)
	code(t, err, "application_not_found")
	_, err = s.CreateManagedGrant(f.ctx, f.org, f.manager, f.second.ID, GrantInput{AppID: f.second.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true}, true)
	code(t, err, "application_not_found")
	grant, err := s.CreateManagedGrant(f.ctx, f.org, f.manager, f.app.ID, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateManagedGrant(f.ctx, f.org, f.manager, f.second.ID, grant.ID, GrantUpdate{Enabled: false}, grant.Version, true)
	code(t, err, "application_not_found")
	_, err = s.RevokeManagedGrant(f.ctx, f.other, f.foreign, f.app.ID, grant.ID, grant.Version)
	code(t, err, "application_not_found")
	grant, err = s.UpdateManagedGrant(f.ctx, f.org, f.manager, f.app.ID, grant.ID, GrantUpdate{Enabled: false}, grant.Version, false)
	if err != nil || grant.Enabled {
		t.Fatal("scoped disable after entitlement loss", err)
	}
	grant, err = s.UpdateManagedGrant(f.ctx, f.org, f.manager, f.app.ID, grant.ID, GrantUpdate{Enabled: true}, grant.Version, true)
	if err != nil || !grant.Enabled {
		t.Fatal("scoped enable", err)
	}
	f.policy(&f.next, true)
	_, err = s.RevokeManagedGrant(f.ctx, f.org, f.manager, f.app.ID, grant.ID, grant.Version)
	code(t, err, "application_not_found")
	_, err = s.RevokeManagedGrant(f.ctx, f.org, f.next, f.app.ID, grant.ID, grant.Version)
	if err != nil {
		t.Fatal("new owner cannot revoke", err)
	}
	f.policy(nil, true)
	catalog, err = s.CompanyApps(f.ctx, f.org, f.member, f.parent.value.ID, "", 50, 0, true)
	if err != nil || len(catalog.Items) != 1 || catalog.Items[0].AppAdmin != nil {
		t.Fatal("cleared owner must preserve visible fallback", catalog, err)
	}
	request := f.request(f.member)
	approved, err := s.DecideAccessRequest(f.ctx, f.org, f.admin, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: request.Version}, true)
	if err != nil || approved.Status != "approved" {
		t.Fatal("fallback approval", approved, err)
	}
	current, err := s.GetApplication(f.ctx, f.org, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateMFAPolicy(f.ctx, f.org, f.admin, f.app.ID, true, current.Version)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = s.CompanyApps(f.ctx, f.org, f.member, f.parent.value.ID, "", 50, 0, true)
	if err != nil || len(catalog.Items) != 1 || !catalog.Items[0].AccessGranted || catalog.Items[0].LaunchURL == "" || !catalog.Items[0].MFARequired || !catalog.Items[0].MFASetupRequired {
		t.Fatal("MFA should challenge Open without another access request", catalog, err)
	}
}
func TestCompanyRequestsAtomicHistoryLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	s := f.service
	f.policy(&f.manager, true)
	var wg sync.WaitGroup
	results := make(chan AccessRequest, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.CreateAccessRequest(f.ctx, f.org, f.member, f.app.ID, "duplicate", true)
			results <- r
			failures <- e
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	var request AccessRequest
	for r := range results {
		if request.ID != uuid.Nil && request.ID != r.ID {
			t.Fatal("duplicate pending requests")
		}
		request = r
	}
	queue, err := s.AccessRequests(f.ctx, f.org, f.manager, false, "pending", nil, 50, 0)
	if err != nil || queue.PendingCount != 1 || len(queue.Items) != 1 {
		t.Fatal("queue", queue, err)
	}
	own, err := s.AccessRequests(f.ctx, f.org, f.member, false, "pending", nil, 50, 0)
	if err != nil || own.PendingCount != 0 || len(own.Items) != 0 {
		t.Fatal("member saw managed queue", own, err)
	}
	f.policy(&f.next, true)
	_, err = s.DecideAccessRequest(f.ctx, f.org, f.manager, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true)
	code(t, err, "application_not_found")
	queue, err = s.AccessRequests(f.ctx, f.org, f.next, false, "pending", nil, 50, 0)
	if err != nil || queue.PendingCount != 1 {
		t.Fatal("reassign lost queue", err)
	}
	// Unpublished draft metadata never replaces the request's published snapshot.
	app, err := s.GetApplication(f.ctx, f.org, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft := app.Draft.DraftInput
	draft.Name = "Unpublished confidential rename"
	if _, err = s.UpdateDraft(f.ctx, f.org, f.admin, f.app.ID, draft, app.Version, true); err != nil {
		t.Fatal(err)
	}
	history, err := s.AccessRequests(f.ctx, f.org, f.member, true, "", nil, 50, 0)
	if err != nil || history.Items[0].AppName != f.app.Draft.Name {
		t.Fatal("draft name leaked to requester", history, err)
	}
	f.policy(&f.next, false)
	f.exec("UPDATE app_access_serving_publications SET state='disabled' WHERE org_id=$1 AND app_id=$2", f.org, f.app.ID)
	approved, err := s.DecideAccessRequest(f.ctx, f.org, f.next, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true)
	if err != nil || approved.Status != "approved" || approved.GrantID == nil {
		t.Fatal("hidden/disabled retained request approval", approved, err)
	}
	grant, err := s.GetGrant(f.ctx, f.org, *approved.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeManagedGrant(f.ctx, f.org, f.next, f.app.ID, grant.ID, grant.Version); err != nil {
		t.Fatal(err)
	}
	replay, err := s.DecideAccessRequest(f.ctx, f.org, f.next, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true)
	if err != nil || replay.Version != approved.Version {
		t.Fatal("terminal replay", replay, err)
	}
	access, err := s.EffectiveAccess(f.ctx, f.org, f.app.ID, f.member, true)
	if err != nil || access.GrantMatch {
		t.Fatal("terminal replay restored revoked access", access, err)
	}
	f.exec("UPDATE app_access_serving_publications SET state='active' WHERE org_id=$1 AND app_id=$2", f.org, f.app.ID)
	f.policy(&f.next, true)
	second := f.request(f.member)
	if second.ID == request.ID {
		t.Fatal("terminal request prevented a fresh request")
	}
	f.exec("CREATE FUNCTION company_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.request_approved' THEN RAISE EXCEPTION 'fixture audit unavailable'; END IF; RETURN NEW; END $$")
	f.exec("CREATE TRIGGER company_reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION company_reject_audit()")
	if _, err = s.DecideAccessRequest(f.ctx, f.org, f.next, second.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true); err == nil {
		t.Fatal("audit failure accepted")
	}
	access, err = s.EffectiveAccess(f.ctx, f.org, f.app.ID, f.member, true)
	if err != nil || access.GrantMatch {
		t.Fatal("audit rollback leaked grant", access, err)
	}
	pending, err := s.AccessRequests(f.ctx, f.org, f.member, true, "pending", nil, 50, 0)
	if err != nil || pending.PendingCount != 1 {
		t.Fatal("audit rollback lost pending", pending, err)
	}
	f.exec("DROP TRIGGER company_reject_audit ON audit_logs")
	outcomes := make(chan error, 2)
	for _, decision := range []string{"approved", "rejected"} {
		go func(decision string) {
			_, e := s.DecideAccessRequest(f.ctx, f.org, f.next, second.ID, AccessDecision{Decision: decision, ExpectedVersion: 1}, true)
			outcomes <- e
		}(decision)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-outcomes == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("approve/reject race had", successes, "successful decisions")
	}
	// Same-org but wrong-app grant linkage is blocked at the database boundary.
	otherGrant, err := s.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.second.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE app_access_requests SET grant_id=$1 WHERE id=$2", otherGrant.ID, second.ID); err == nil {
		t.Fatal("cross-app grant FK accepted")
	}
}
func TestCompanyUnavailableMembershipAndRetainedQueueLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	s := f.service
	f.policy(&f.manager, true)
	req := f.request(f.member)
	// Removing an owner does not hide the app or strand old/new requests.
	f.exec("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", f.org, f.manager)
	current, err := s.GetAccessManagement(f.ctx, f.org, f.admin, f.app.ID)
	if err != nil || !current.CatalogVisible || current.AppAdmin != nil {
		t.Fatal("directory removal hid catalog", current, err)
	}
	next := f.request(f.next)
	if _, err = s.DecideAccessRequest(f.ctx, f.org, f.admin, next.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true); err != nil {
		t.Fatal("fallback new request", err)
	}
	// A deleted/recreated membership cannot revive the original pending request.
	f.exec("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", f.org, f.member)
	f.exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')", f.org, f.member)
	_, err = s.DecideAccessRequest(f.ctx, f.org, f.admin, req.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true)
	code(t, err, "requester_unavailable")
	f.exec("UPDATE app_access_applications SET state='archived' WHERE org_id=$1 AND id=$2", f.org, f.app.ID)
	rejected, err := s.DecideAccessRequest(f.ctx, f.org, f.admin, req.ID, AccessDecision{Decision: "rejected", ExpectedVersion: 1, Reason: "Requesting membership removed"}, false)
	if err != nil || rejected.Status != "rejected" {
		t.Fatal("archived pending closure", rejected, err)
	}
}
func TestCompanyScopedGrantDirectoryLockOrderLocalDatabase(t *testing.T) {
	for _, action := range []string{"create", "update", "revoke"} {
		t.Run(action, func(t *testing.T) {
			f := newCompanyFixture(t)
			s := f.service
			f.policy(&f.manager, true)
			var grant Grant
			if action != "create" {
				var err error
				grant, err = s.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.manager, Enabled: true}, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			deletion, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer deletion.Rollback(f.ctx)
			if _, err = deletion.Exec(f.ctx, "SELECT user_id FROM memberships WHERE org_id=$1 AND user_id=$2 FOR UPDATE", f.org, f.manager); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
				defer cancel()
				var e error
				switch action {
				case "create":
					_, e = s.CreateManagedGrant(ctx, f.org, f.admin, f.app.ID, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.manager, Enabled: true}, true)
				case "update":
					_, e = s.UpdateManagedGrant(ctx, f.org, f.admin, f.app.ID, grant.ID, GrantUpdate{Enabled: false}, grant.Version, true)
				case "revoke":
					_, e = s.RevokeManagedGrant(ctx, f.org, f.admin, f.app.ID, grant.ID, grant.Version)
				}
				done <- e
			}()
			// Wait for the worker to block on the held directory row, then prove it
			// has not acquired the app lock that the directory FK needs next.
			deadline := time.Now().Add(3 * time.Second)
			blocked := false
			for time.Now().Before(deadline) {
				if err = f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%LockAppAccessGrantUserDirectory%')").Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("scoped mutation did not reach directory lock")
			}
			if _, err = deletion.Exec(f.ctx, "SELECT version FROM app_access_applications WHERE org_id=$1 AND id=$2 FOR UPDATE NOWAIT", f.org, f.app.ID); err != nil {
				t.Fatal("mutation held app before directory", err)
			}
			if _, err = deletion.Exec(f.ctx, "DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", f.org, f.manager); err != nil {
				t.Fatal(err)
			}
			if err = deletion.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			e := <-done
			if errors.Is(e, context.DeadlineExceeded) || e != nil && (strings.Contains(e.Error(), "deadlock") || strings.Contains(e.Error(), "timeout")) {
				t.Fatal("directory race did not resolve", e)
			}
			if action == "create" && e == nil {
				t.Fatal("removed subject gained grant")
			}
		})
	}
}
func TestCompanyMigrationRetainsHistoryLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	var initialVersion int
	if err := f.pool.QueryRow(f.ctx, "SELECT version FROM schema_migrations").Scan(&initialVersion); err != nil {
		t.Fatal("read migration state", err)
	}
	down, err := db.MigrationsFS.ReadFile("migrations/0177_app_access_company_apps.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	f.policy(&f.manager, true)
	if _, err = f.pool.Exec(f.ctx, string(down)); err == nil || !strings.Contains(err.Error(), "request history are retained") {
		t.Fatal("unsafe rollback accepted", err)
	}
	var dirty bool
	var version int
	if err = f.pool.QueryRow(f.ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty); err != nil || dirty || version != initialVersion {
		t.Fatal("migration state changed", version, dirty, err)
	}
	// Attempt a speculative future version before pre-lock owner validation.
	policy, err := f.service.GetAccessManagement(f.ctx, f.org, f.admin, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UpdateAccessManagement(f.ctx, f.org, f.admin, f.app.ID, false, &f.manager, policy.Version+1)
	code(t, err, "version_conflict")
}

func TestCompanyApprovalExistingGrantsLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	s := f.service
	f.policy(&f.manager, true)
	request := f.request(f.member)
	expired := time.Now().Add(-time.Hour)
	direct, err := s.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.member, Enabled: false, ExpiresAt: &expired}, true)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	approved, err := s.DecideAccessRequest(f.ctx, f.org, f.manager, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1, ExpiresAt: &expiry}, true)
	if err != nil || approved.GrantID == nil || *approved.GrantID != direct.ID {
		t.Fatal("disabled/expired grant was not deliberately reused", approved, err)
	}
	updated, err := s.GetGrant(f.ctx, f.org, direct.ID)
	if err != nil || !updated.Enabled || updated.Version != direct.Version+1 || updated.ExpiresAt == nil || updated.StartsAt != nil {
		t.Fatal("explicit approval did not renew exact direct grant", updated, err)
	}
	if _, err = s.RevokeGrant(f.ctx, f.org, f.admin, updated.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	request = f.request(f.member)
	group := uuid.New()
	f.exec("INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Company group')", group, f.org)
	f.exec("INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)", f.org, group, f.member)
	team, err := s.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "group", SubjectID: group, Enabled: true, ExpiresAt: &expiry}, true)
	if err != nil {
		t.Fatal(err)
	}
	wider := expiry.Add(24 * time.Hour)
	approved, err = s.DecideAccessRequest(f.ctx, f.org, f.manager, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1, ExpiresAt: &wider}, true)
	if err != nil || approved.GrantID == nil || *approved.GrantID != team.ID {
		t.Fatal("existing group access not reused", approved, err)
	}
	retained, err := s.GetGrant(f.ctx, f.org, team.ID)
	if err != nil || retained.Version != team.Version || !retained.ExpiresAt.Equal(team.ExpiresAt.UTC()) {
		t.Fatal("approval widened existing group grant", retained, err)
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM app_access_grants WHERE org_id=$1 AND app_id=$2 AND subject_kind='user' AND revoked_at IS NULL", f.org, f.app.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("group access duplicated as direct grant", count, err)
	}
}
func TestCompanyReassignmentSerializesDecisionsLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	s := f.service
	f.policy(&f.manager, true)
	request := f.request(f.member)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, "UPDATE app_access_applications SET app_admin_user_id=$3,version=version+1 WHERE org_id=$1 AND id=$2", f.org, f.app.ID, f.next); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		_, e := s.DecideAccessRequest(ctx, f.org, f.manager, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: 1}, true)
		done <- e
	}()
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if err = f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%LockAppAccessApplication%')").Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("decision did not wait for app reassignment")
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	code(t, <-done, "application_not_found")
	queue, err := s.AccessRequests(f.ctx, f.org, f.next, false, "pending", nil, 50, 0)
	if err != nil || queue.PendingCount != 1 {
		t.Fatal("racing old owner consumed pending request", queue, err)
	}
}

func TestCompanySmallPoolConcurrentReadsLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.policy(&f.manager, true)
	if _, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true}, true); err != nil {
		t.Fatal(err)
	}
	app, err := f.service.GetApplication(f.ctx, f.org, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.UpdateMFAPolicy(f.ctx, f.org, f.admin, f.app.ID, true, app.Version); err != nil {
		t.Fatal(err)
	}
	config := f.pool.Config()
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(f.ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := *f.service
	s.pool = pool
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { <-start; _, err := s.ManagedGrants(ctx, f.org, f.manager, f.app.ID, 50, 0); done <- err }()
	}
	close(start)
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal("small-pool grant reads blocked", err)
		}
	}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	s.mfaEnrolled = func(ctx context.Context, _ uuid.UUID) (bool, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		var n int
		err := pool.QueryRow(ctx, "SELECT 1").Scan(&n)
		return false, err
	}
	for i := 0; i < 2; i++ {
		go func() { _, err := s.CompanyApps(ctx, f.org, f.member, f.parent.value.ID, "", 50, 0, true); done <- err }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("catalog did not release connection before enrollment")
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal("MFA checker pool re-entry blocked", err)
		}
	}
}
func TestCompanyMigrationDefaultCompatibilityLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	if err := db.MigrateTo(f.pool.Config().ConnString(), 176); err != nil {
		t.Fatal("empty catalog rollback", err)
	}
	if _, err := f.service.GetApplication(f.ctx, f.org, f.app.ID); err != nil {
		t.Fatal("previous schema application read", err)
	}
	if err := db.MigrateTo(f.pool.Config().ConnString(), 177); err != nil {
		t.Fatal("forward", err)
	}
	for _, app := range []uuid.UUID{f.app.ID, f.second.ID} {
		policy, err := f.service.GetAccessManagement(f.ctx, f.org, f.admin, app)
		if err != nil || policy.CatalogVisible || policy.AppAdminUserID != nil {
			t.Fatal("migration exposed existing application", policy, err)
		}
	}
}

// Test navigation against current persisted membership, independent of assignment.
func TestCompanyManagedNavigationPermissionsLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.policy(&f.manager, true)
	for _, tc := range []struct {
		name        string
		actor       uuid.UUID
		view, grant bool
		count       int
	}{
		{"organization administrator", f.admin, true, true, 2},
		{"ordinary member", f.member, false, false, 0},
		{"assigned App admin", f.manager, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.service.ManagedApps(f.ctx, f.org, tc.actor, nil, 50, 0)
			if err != nil || out.CanViewApplications != tc.view || out.CanManageGrants != tc.grant || len(out.Items) != tc.count {
				t.Fatalf("current permissions and scope: %+v err=%v", out, err)
			}
		})
	}
	// A second request reads role changes from the database, not session hints.
	f.exec("UPDATE memberships SET role='admin' WHERE org_id=$1 AND user_id=$2", f.org, f.member)
	promoted, err := f.service.ManagedApps(f.ctx, f.org, f.member, nil, 50, 0)
	if err != nil || !promoted.CanViewApplications || !promoted.CanManageGrants || len(promoted.Items) != 2 {
		t.Fatal("promotion not reflected", promoted, err)
	}
	f.exec("UPDATE memberships SET role='member' WHERE org_id=$1 AND user_id=$2", f.org, f.member)
	demoted, err := f.service.ManagedApps(f.ctx, f.org, f.member, nil, 50, 0)
	if err != nil || demoted.CanViewApplications || demoted.CanManageGrants || len(demoted.Items) != 0 {
		t.Fatal("stale authority retained", demoted, err)
	}
	_, err = f.service.ManagedApps(f.ctx, f.other, f.admin, nil, 50, 0)
	code(t, err, "application_not_found")
	f.exec("UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2", f.org, f.manager)
	_, err = f.service.ManagedApps(f.ctx, f.org, f.manager, nil, 50, 0)
	code(t, err, "application_not_found")
}
