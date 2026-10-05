package sandboxes

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"slices"
	"strings"
	"testing"
	"time"
)

func makeSetupAdmin(t *testing.T, f fixture) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `UPDATE memberships SET role='owner',roles=ARRAY['owner']::text[] WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
}
func TestSandboxSetupPostgresPermissionsCASAuditAndClosedRuntime(t *testing.T) {
	f := newFixture(t)
	status, err := f.store.Setup(f.ctx, f.org, f.user)
	if err != nil || status.CanAdmin {
		t.Fatal("member admin claim", err)
	}
	settings := status.Settings
	next := settings
	next.MaxTotal++
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, settings, next, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("member settings write", err)
	}
	if err = f.store.PublishTemplate(f.ctx, f.org, f.user, f.template, true, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("member catalog write", err)
	}
	makeSetupAdmin(t, f)
	notifications := 0
	f.store.WithPolicyNotify(func(_ctx context.Context, _org uuid.UUID) { notifications++ })
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, settings, next, false); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, settings, next, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale settings overwritten", err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, next, next, false); err != nil {
		t.Fatal(err)
	}
	next2 := next
	next2.Enabled = false
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, next, next2, false); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, next2, next, false); !errors.Is(err, ErrDisabled) {
		t.Fatal("closed runtime enabled", err)
	}
	if err = f.store.PublishTemplate(f.ctx, f.org, f.user, f.template, true, false); err != nil {
		t.Fatal(err)
	}
	if err = f.store.PublishTemplate(f.ctx, f.org, f.user, f.template, true, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale publication overwritten", err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, next2, next, true); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing catalog enabled", err)
	}
	status, err = f.store.Setup(f.ctx, f.org, f.user)
	if err != nil || len(status.Catalog) != 1 || status.Catalog[0].Enabled || !slices.Contains(status.BlockedReasons, "organization_disabled") || !slices.Contains(status.BlockedReasons, "no_published_templates") {
		t.Fatal("admin blocked/catalog status", status, err)
	}
	member, err := f.store.Setup(f.ctx, f.org, f.other)
	if err != nil || len(member.Catalog) != 0 {
		t.Fatal("unpublished catalog leaked", err)
	}
	if _, err = f.store.Setup(f.ctx, uuid.New(), f.user); !errors.Is(err, ErrForbidden) {
		t.Fatal("cross org status", err)
	}
	var audits int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action IN ('sandbox.settings_update','sandbox.template_publication')`, f.org).Scan(&audits); err != nil || audits != 3 || notifications != 3 {
		t.Fatal("audit/noop/policy notification", audits, notifications, err)
	}
}
func TestSandboxSetupPostgresActivationRequiresPolicyRuntimeAndBoundProfile(t *testing.T) {
	f := newFixture(t)
	makeSetupAdmin(t, f)
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	status, err := f.store.Setup(f.ctx, f.org, f.user)
	if err != nil {
		t.Fatal(err)
	}
	next := status.Settings
	next.Enabled = true
	b := boundedTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	if _, err = f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, status.Settings, next, true); !errors.Is(err, ErrDisabled) {
		t.Fatal("unqualified profile activated", err)
	}
	b.TemplateID = uuid.New()
	b.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	f.store.boundedRuntime = &b
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'bounded setup',$3,'[]',128,3600,true)`, b.TemplateID, f.org, b.ImageDigest); err != nil {
		t.Fatal(err)
	}
	f.store.boundedRuntime.ExpiresAt = time.Now().Add(-time.Second)
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, status.Settings, next, true); !errors.Is(err, ErrDisabled) {
		t.Fatal("expired runtime activated", err)
	}
	f.store.boundedRuntime.ExpiresAt = time.Now().Add(time.Hour)
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET zero_trust_mode='off' WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, status.Settings, next, true); !errors.Is(err, ErrDisabled) {
		t.Fatal("non-enforcing activated", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, status.Settings, next, true); err != nil {
		t.Fatal("qualified activation failed", err)
	}
}
