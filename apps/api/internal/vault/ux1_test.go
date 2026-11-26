package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

// allowStepUp stands in for a caller that has just re-authenticated.
func allowStepUp(context.Context) error { return nil }

func code(t *testing.T, err error, want string) {
	t.Helper()
	var v *apierr.Error
	if !errors.As(err, &v) || v.Code != want {
		t.Fatalf("error code: got %v, want %s", err, want)
	}
}

type ux1Fixture struct {
	ctx                                          context.Context
	pool                                         *pgxpool.Pool
	s                                            *Service
	org                                          uuid.UUID
	admin, alice, bob, aiViewer, unverified, sso uuid.UUID
	service                                      api.VaultService
}

func newUX1Fixture(t *testing.T) ux1Fixture {
	t.Helper()
	ctx, pool, s := newTestService(t)
	f := ux1Fixture{ctx: ctx, pool: pool, s: s, org: uuid.New(), admin: uuid.New(), alice: uuid.New(), bob: uuid.New(), aiViewer: uuid.New(), unverified: uuid.New(), sso: uuid.New()}
	f.exec(t, `INSERT INTO organizations(id,name,slug) VALUES($1,'Vault UX fixture',$2)`, f.org, f.org.String())
	for _, u := range []struct {
		id         uuid.UUID
		name, role string
		verified   bool
	}{{f.admin, "Ada Admin", "admin", true}, {f.alice, "Alice Member", "member", true}, {f.bob, "Bob Member", "member", true},
		{f.aiViewer, "Ivy Viewer", "ai-view", true}, {f.unverified, "Uma Unverified", "member", false}} {
		verified := "now()"
		if !u.verified {
			verified = "NULL"
		}
		f.exec(t, `INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,$3,`+verified+`)`, u.id, strings.ToLower(strings.Fields(u.name)[0])+"-"+u.id.String()[:8]+"@vault.test", u.name)
		f.exec(t, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, f.org, u.id, u.role)
	}
	var err error
	if f.service, err = s.AddService(ctx, f.org, f.admin, "Shared service"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f ux1Fixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}

func (f ux1Fixture) assign(t *testing.T, kind string, subject uuid.UUID, title string) (api.VaultEntry, error) {
	t.Helper()
	return f.s.Create(f.ctx, f.org, f.admin, api.VaultCreateInput{Title: title, Kind: "password", Visibility: "assigned", ServiceId: &f.service.Id,
		Secret: ptr("ux1-assigned-secret"), Username: ptr("shared-login"), SubjectKind: ptr(api.VaultCreateInputSubjectKind(kind)), SubjectId: &subject})
}

func (f ux1Fixture) personal(t *testing.T, owner uuid.UUID, title string) api.VaultEntry {
	t.Helper()
	v, err := f.s.Create(f.ctx, f.org, owner, api.VaultCreateInput{Title: title, Kind: "password", Visibility: "personal", ServiceName: ptr("Private notes service"), Secret: ptr("ux1-personal-secret"), Username: ptr("private-login")})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f ux1Fixture) auditRows(t *testing.T, action string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT metadata FROM audit_logs WHERE org_id=$1 AND action=$2 ORDER BY created_at,id`, f.org, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err = json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// V1: the recipient list and target validation use the same eligibility as begin().
func TestVaultRecipientsMustBeAbleToUseVault(t *testing.T) {
	f := newUX1Fixture(t)
	subjects, err := f.s.Subjects(f.ctx, f.org, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]api.VaultSubject{}
	for _, u := range subjects.Users {
		seen[u.Id] = u
	}
	for _, id := range []uuid.UUID{f.admin, f.alice, f.bob} {
		if u, ok := seen[id]; !ok || u.Email == nil || !strings.HasSuffix(*u.Email, "@vault.test") {
			t.Fatalf("eligible recipient %s missing or without email: %+v", id, u)
		}
	}
	for _, id := range []uuid.UUID{f.aiViewer, f.unverified} {
		if _, ok := seen[id]; ok {
			t.Fatal("recipient list offered someone who cannot use Vault")
		}
	}
	for _, id := range []uuid.UUID{f.aiViewer, f.unverified} {
		_, err = f.assign(t, "user", id, "Unusable assignment")
		code(t, err, "vault_recipient_without_access")
	}
	group := uuid.New()
	f.exec(t, `INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Mixed group')`, group, f.org)
	for _, id := range []uuid.UUID{f.alice, f.aiViewer, f.unverified} {
		f.exec(t, `INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, id)
	}
	subjects, err = f.s.Subjects(f.ctx, f.org, f.admin)
	if err != nil || len(subjects.Groups) != 1 {
		t.Fatalf("groups: %+v %v", subjects.Groups, err)
	}
	g := subjects.Groups[0]
	if g.MemberCount == nil || *g.MemberCount != 3 || g.MembersWithoutAccess == nil || len(*g.MembersWithoutAccess) != 2 {
		t.Fatalf("group must name the members who lack access: %+v", g)
	}
	for _, p := range *g.MembersWithoutAccess {
		if p.Id != f.aiViewer && p.Id != f.unverified || p.Email == "" {
			t.Fatalf("wrong member reported without access: %+v", p)
		}
	}
	if _, err = f.assign(t, "group", group, "Group assignment"); err != nil {
		t.Fatal("a group remains assignable", err)
	}
}

// V2 + V5: recipients rotate only; details edits never create versions; admins reassign.
func TestVaultDetailsEditsAndReassignment(t *testing.T) {
	f := newUX1Fixture(t)
	entry, err := f.assign(t, "user", f.alice, "Team login")
	if err != nil {
		t.Fatal(err)
	}
	if !entry.CanEdit || !entry.CanEditDetails || entry.Revision != 1 {
		t.Fatalf("admin flags: %+v", entry)
	}
	ws, err := f.s.List(f.ctx, f.org, f.alice, 50, 0, "")
	if err != nil || len(ws.Entries) != 1 || !ws.Entries[0].CanEdit || ws.Entries[0].CanEditDetails || ws.Entries[0].CanDelete {
		t.Fatalf("recipient flags: %+v %v", ws.Entries, err)
	}
	_, err = f.s.Update(f.ctx, f.org, f.alice, entry.Id, api.VaultUpdateInput{Title: ptr("Renamed by recipient"), Secret: ptr("ux1-rotated"), ExpectedVersion: 1})
	code(t, err, "vault_details_forbidden")
	rotated, err := f.s.Update(f.ctx, f.org, f.alice, entry.Id, api.VaultUpdateInput{Secret: ptr("ux1-rotated"), ExpectedVersion: 1})
	if err != nil || rotated.CurrentVersion != 2 || rotated.Title != "Team login" || rotated.Revision != 2 {
		t.Fatalf("recipient rotation: %+v %v", rotated, err)
	}
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.alice, entry.Id, api.VaultDetailsInput{ExpectedRevision: 2, Title: ptr("Recipient details")})
	code(t, err, "vault_details_forbidden")

	renamed, err := f.s.UpdateDetails(f.ctx, f.org, f.admin, entry.Id, api.VaultDetailsInput{ExpectedRevision: 2, Title: ptr("Team login (prod)"), Username: ptr("new-login")})
	if err != nil || renamed.CurrentVersion != 2 || renamed.Revision != 3 || renamed.Title != "Team login (prod)" || renamed.Username != "new-login" {
		t.Fatalf("details edit: %+v %v", renamed, err)
	}
	history, err := f.s.Versions(f.ctx, f.org, f.admin, entry.Id, 50, 0)
	if err != nil || history.Total != 2 || history.Versions[0].ChangedByEmail == "" {
		t.Fatalf("details edit must not add a version: %+v %v", history, err)
	}
	cur, err := f.s.Reveal(f.ctx, f.org, f.admin, entry.Id, RevealRequest{StepUp: allowStepUp})
	if err != nil || cur.Username != "new-login" || cur.Value != "ux1-rotated" {
		t.Fatalf("current reveal must carry the current username: %+v %v", cur, err)
	}
	old, err := f.s.Reveal(f.ctx, f.org, f.admin, entry.Id, RevealRequest{Version: 1, StepUp: allowStepUp})
	if err != nil || old.Username != "shared-login" {
		t.Fatalf("earlier version keeps its saved username: %+v %v", old, err)
	}
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.admin, entry.Id, api.VaultDetailsInput{ExpectedRevision: 2, Title: ptr("Stale")})
	status(t, err, 409)

	// Reassignment: Alice loses access, Bob gains it; ineligible targets are refused.
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.admin, entry.Id, api.VaultDetailsInput{ExpectedRevision: 3, SubjectKind: ptr(api.VaultDetailsSubjectUser), SubjectId: &f.aiViewer})
	code(t, err, "vault_recipient_without_access")
	moved, err := f.s.UpdateDetails(f.ctx, f.org, f.admin, entry.Id, api.VaultDetailsInput{ExpectedRevision: 3, SubjectKind: ptr(api.VaultDetailsSubjectUser), SubjectId: &f.bob})
	if err != nil || moved.SubjectId == nil || *moved.SubjectId != f.bob || moved.CurrentVersion != 2 {
		t.Fatalf("reassignment: %+v %v", moved, err)
	}
	_, err = f.s.Reveal(f.ctx, f.org, f.alice, entry.Id, RevealRequest{StepUp: allowStepUp})
	status(t, err, 404)
	if _, err = f.s.Reveal(f.ctx, f.org, f.bob, entry.Id, RevealRequest{StepUp: allowStepUp}); err != nil {
		t.Fatal("new recipient cannot open the reassigned entry", err)
	}
	changes := f.auditRows(t, "vault.details_changed")
	if len(changes) != 2 || changes[1]["recipient_from"] == nil || changes[1]["recipient"] == nil {
		t.Fatalf("reassignment audit: %+v", changes)
	}

	// Personal entries: owner-only details, no visibility change, no subject fields.
	mine := f.personal(t, f.alice, "Alice private")
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.admin, mine.Id, api.VaultDetailsInput{ExpectedRevision: 1, Title: ptr("Admin peek")})
	status(t, err, 404)
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.alice, mine.Id, api.VaultDetailsInput{ExpectedRevision: 1, SubjectKind: ptr(api.VaultDetailsSubjectUser), SubjectId: &f.bob})
	code(t, err, "vault_visibility_change_unsupported")
	edited, err := f.s.UpdateDetails(f.ctx, f.org, f.alice, mine.Id, api.VaultDetailsInput{ExpectedRevision: 1, Title: ptr("Alice private (home)"), ServiceName: ptr("Home router")})
	if err != nil || edited.CurrentVersion != 1 || edited.ServiceName != "Home router" || edited.Revision != 2 {
		t.Fatalf("personal details: %+v %v", edited, err)
	}
	_, err = f.s.UpdateDetails(f.ctx, f.org, f.alice, mine.Id, api.VaultDetailsInput{ExpectedRevision: 2, ServiceId: &f.service.Id, ServiceName: ptr("Both")})
	status(t, err, 400)
}

// V3: labels for assigned entries; nothing an admin should not know about personal entries.
func TestVaultAuditCarriesSafeLabels(t *testing.T) {
	f := newUX1Fixture(t)
	mine := f.personal(t, f.alice, "Alice bank")
	shared, err := f.assign(t, "user", f.alice, "Deploy key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Reveal(f.ctx, f.org, f.alice, mine.Id, RevealRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Reveal(f.ctx, f.org, f.alice, shared.Id, RevealRequest{Purpose: "copy", StepUp: allowStepUp}); err != nil {
		t.Fatal(err)
	}
	created := f.auditRows(t, "vault.created")
	if len(created) != 2 {
		t.Fatalf("created rows: %+v", created)
	}
	if created[0]["visibility"] != "personal" || created[0]["kind"] != "password" || created[0]["title"] != nil || created[0]["service"] != nil {
		t.Fatalf("personal audit must not name the entry: %+v", created[0])
	}
	if created[1]["title"] != "Deploy key" || created[1]["service"] != "Shared service" || created[1]["recipient"] == nil || created[1]["recipient_kind"] != "user" {
		t.Fatalf("assigned audit labels: %+v", created[1])
	}
	if r := f.auditRows(t, "vault.revealed"); len(r) != 1 || r[0]["title"] != nil {
		t.Fatalf("personal reveal audit: %+v", r)
	}
	if c := f.auditRows(t, "vault.copied"); len(c) != 1 || c[0]["title"] != "Deploy key" || c[0]["version"] != float64(1) {
		t.Fatalf("copy is its own action: %+v", c)
	}
	var all string
	if err = f.pool.QueryRow(f.ctx, `SELECT string_agg(metadata::text,'') FROM audit_logs WHERE org_id=$1 AND action LIKE 'vault.%'`, f.org).Scan(&all); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"ux1-", "private-login", "Alice bank", "Private notes service", "shared-login"} {
		if strings.Contains(all, leak) {
			t.Fatalf("audit leaked %q", leak)
		}
	}
}

// V4: assigned reveals require step-up inside the transaction; personal ones never do.
func TestVaultRevealStepUpForAssignedEntriesOnly(t *testing.T) {
	f := newUX1Fixture(t)
	mine := f.personal(t, f.alice, "Mine")
	shared, err := f.assign(t, "user", f.alice, "Shared")
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(context.Context) error { return apierr.Forbidden("mfa_step_up_required", "Verify MFA") }
	if _, err = f.s.Reveal(f.ctx, f.org, f.alice, mine.Id, RevealRequest{StepUp: refuse}); err != nil {
		t.Fatal("personal reveal must not ask for step-up", err)
	}
	v, err := f.s.Reveal(f.ctx, f.org, f.alice, shared.Id, RevealRequest{StepUp: refuse})
	code(t, err, "mfa_step_up_required")
	if v.Value != "" {
		t.Fatal("secret returned without step-up")
	}
	_, err = f.s.Reveal(f.ctx, f.org, f.alice, shared.Id, RevealRequest{})
	status(t, err, 403) // fail closed when no step-up check is supplied
	if r := f.auditRows(t, "vault.revealed"); len(r) != 1 {
		t.Fatalf("refused reveals must not be audited as reveals: %d", len(r))
	}
	// A stranger is refused before the step-up runs (no oracle about other entries).
	called := false
	_, err = f.s.Reveal(f.ctx, f.org, f.bob, shared.Id, RevealRequest{StepUp: func(context.Context) error { called = true; return nil }})
	status(t, err, 404)
	if called {
		t.Fatal("step-up ran for someone with no access")
	}
	_, err = f.s.Reveal(f.ctx, f.org, f.alice, shared.Id, RevealRequest{Purpose: "screenshot", StepUp: allowStepUp})
	status(t, err, 400)
}

// V6: personal entries go with the membership; re-joining does not bring them back.
func TestVaultPurgesPersonalEntriesWhenMembershipEnds(t *testing.T) {
	f := newUX1Fixture(t)
	f.exec(t, `UPDATE memberships SET role='admin' WHERE org_id=$1 AND user_id=$2`, f.org, f.alice)
	mine := f.personal(t, f.alice, "Alice only")
	f.personal(t, f.alice, "Alice second")
	createdByAlice, err := f.s.Create(f.ctx, f.org, f.alice, api.VaultCreateInput{Title: "Team asset", Kind: "password", Visibility: "assigned", ServiceId: &f.service.Id,
		Secret: ptr("ux1-team"), SubjectKind: ptr(api.VaultCreateInputSubjectKind("user")), SubjectId: &f.bob})
	if err != nil {
		t.Fatal(err)
	}
	bobs := f.personal(t, f.bob, "Bob only")
	count := func(owner uuid.UUID) (n int) {
		t.Helper()
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM vault_entries e JOIN vault_versions v ON v.org_id=e.org_id AND v.entry_id=e.id
 WHERE e.org_id=$1 AND e.owner_user_id=$2 AND e.visibility='personal'`, f.org, owner).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Route 1: hard removal, then re-added.
	f.exec(t, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.alice)
	if count(f.alice) != 0 {
		t.Fatal("personal entries survived membership removal")
	}
	if _, err = f.s.Reveal(f.ctx, f.org, f.bob, createdByAlice.Id, RevealRequest{StepUp: allowStepUp}); err != nil {
		t.Fatal("assigned entries the person created must stay", err)
	}
	purged := f.auditRows(t, "vault.personal_entries_purged")
	if len(purged) != 1 || purged[0]["entries"] != float64(2) || purged[0]["reason"] != "membership_removed" {
		t.Fatalf("purge audit: %+v", purged)
	}
	var system string
	if err = f.pool.QueryRow(f.ctx, `SELECT actor_system FROM audit_logs WHERE org_id=$1 AND action='vault.personal_entries_purged'`, f.org).Scan(&system); err != nil || system != "vault" {
		t.Fatalf("purge actor: %q %v", system, err)
	}
	f.exec(t, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, f.alice)
	ws, err := f.s.List(f.ctx, f.org, f.alice, 50, 0, "")
	if err != nil || ws.Total != 0 {
		t.Fatalf("re-invited member got entries back: %+v %v", ws, err)
	}
	_, err = f.s.Reveal(f.ctx, f.org, f.alice, mine.Id, RevealRequest{})
	status(t, err, 404)

	// Route 2: organization access revoked by directory sync, then restored.
	if count(f.bob) != 1 {
		t.Fatal("another member's entries were touched")
	}
	f.exec(t, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, f.bob)
	f.exec(t, `UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, f.org, f.bob)
	if count(f.bob) != 0 {
		t.Fatal("personal entries survived organization access revocation")
	}
	_, err = f.s.Reveal(f.ctx, f.org, f.bob, bobs.Id, RevealRequest{})
	status(t, err, 404)
	if p := f.auditRows(t, "vault.personal_entries_purged"); len(p) != 2 || p[1]["reason"] != "organization_access_revoked" {
		t.Fatalf("revocation purge audit: %+v", p)
	}
	// Deactivation is reversible and keeps the membership: nothing is purged.
	keep := f.personal(t, f.alice, "Kept through deactivation")
	f.exec(t, `UPDATE users SET status='deactivated' WHERE id=$1`, f.alice)
	f.exec(t, `UPDATE users SET status='active' WHERE id=$1`, f.alice)
	if _, err = f.s.Reveal(f.ctx, f.org, f.alice, keep.Id, RevealRequest{}); err != nil {
		t.Fatal("deactivation must not purge", err)
	}
}

// V7: adding details to a quick password keeps version 1.
func TestVaultConfigureDoesNotDuplicateTheVersion(t *testing.T) {
	f := newUX1Fixture(t)
	draft, err := f.s.QuickCreate(f.ctx, f.org, f.alice, api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("ux1-quick")})
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.s.Configure(f.ctx, f.org, f.alice, draft.Id, api.VaultConfigureInput{Title: "Router", Visibility: "personal", ServiceName: ptr("Home"), Username: ptr("root"), ExpectedVersion: 1})
	if err != nil || !done.Configured || done.CurrentVersion != 1 || done.Username != "root" || done.Revision != 2 {
		t.Fatalf("configure: %+v %v", done, err)
	}
	h, err := f.s.Versions(f.ctx, f.org, f.alice, draft.Id, 50, 0)
	if err != nil || h.Total != 1 {
		t.Fatalf("configure wrote a duplicate version: %+v %v", h, err)
	}
	v, err := f.s.Reveal(f.ctx, f.org, f.alice, draft.Id, RevealRequest{})
	if err != nil || v.Value != "ux1-quick" || v.Username != "root" || v.Version != 1 {
		t.Fatalf("configured reveal: %+v %v", v, err)
	}
}

// V10 + V16: list views and literal search.
func TestVaultListViewsAndLiteralSearch(t *testing.T) {
	f := newUX1Fixture(t)
	f.personal(t, f.alice, "100% literal_title")
	f.personal(t, f.alice, "Other title")
	if _, err := f.assign(t, "user", f.alice, "Assigned to Alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.assign(t, "user", f.bob, "Assigned to Bob"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user    uuid.UUID
		view, q string
		want    int
	}{
		{f.alice, "all", "", 3}, {f.alice, "personal", "", 2}, {f.alice, "shared", "", 1}, {f.alice, "assigned", "", 1},
		{f.admin, "assigned", "", 2}, {f.admin, "shared", "", 0}, {f.admin, "personal", "", 0},
		{f.alice, "all", "%", 1}, {f.alice, "all", "_", 1}, {f.alice, "all", `\`, 0}, {f.alice, "all", "0% l", 1},
	} {
		ws, err := f.s.ListView(f.ctx, f.org, tc.user, 50, 0, tc.q, tc.view)
		if err != nil || ws.Total != tc.want || len(ws.Entries) != tc.want {
			t.Fatalf("view=%s q=%q: total=%d err=%v want %d", tc.view, tc.q, ws.Total, err, tc.want)
		}
	}
	_, err := f.s.ListView(f.ctx, f.org, f.alice, 50, 0, "", "everything")
	status(t, err, 400)
}

// V18: old quick-request idempotency rows are pruned; recent ones stay.
func TestVaultPrunesOldQuickRequests(t *testing.T) {
	f := newUX1Fixture(t)
	recent, err := f.s.QuickCreate(f.ctx, f.org, f.alice, api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("ux1-recent")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.QuickCreate(f.ctx, f.org, f.alice, api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("ux1-old")}); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE vault_quick_requests SET created_at=now()-interval '31 days' WHERE entry_id<>$1`, recent.Id)
	n, err := f.s.PruneQuickRequests(f.ctx, QuickRequestRetention, 1000)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	var left int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM vault_quick_requests`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("remaining quick requests: %d %v", left, err)
	}
	var entries int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM vault_entries WHERE org_id=$1`, f.org).Scan(&entries); err != nil || entries != 2 {
		t.Fatal("pruning must not delete saved passwords")
	}
}

// V19: new versions use associated data; v1 rows still open; payloads cannot be moved.
func TestVaultEnvelopeV2BindsAssociatedDataAndReadsV1(t *testing.T) {
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, sealer)
	org, id := uuid.New(), uuid.New()
	sealed, err := s.seal(org, id, 2, "ux1-v2-value", "user")
	if err != nil || !strings.HasPrefix(sealed, "v2.") {
		t.Fatalf("new writes must use the v2 envelope: %q %v", sealed, err)
	}
	if v, e := s.open(org, id, 2, sealed); e != nil || v.Value != "ux1-v2-value" {
		t.Fatal("v2 round trip", e)
	}
	for _, tc := range []struct {
		org, id uuid.UUID
		version int
	}{{uuid.New(), id, 2}, {org, uuid.New(), 2}, {org, id, 3}} {
		_, e := s.open(tc.org, tc.id, tc.version, sealed)
		status(t, e, 500)
	}
	raw, _ := json.Marshal(envelope{"tunnex-vault-v1", org, id, 1, "ux1-legacy", "legacy-user"})
	legacy, err := sealer.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v, e := s.open(org, id, 1, legacy); e != nil || v.Value != "ux1-legacy" || v.Username != "legacy-user" {
		t.Fatal("v1 rows must still open", e)
	}
	// A v1 payload relabelled as v2 (or the reverse) must not open.
	if _, e := s.open(org, id, 1, "v2."+legacy); e == nil {
		t.Fatal("v1 ciphertext accepted as v2")
	}
	if _, e := s.open(org, id, 2, strings.TrimPrefix(sealed, "v2.")); e == nil {
		t.Fatal("v2 ciphertext accepted as v1")
	}
}
