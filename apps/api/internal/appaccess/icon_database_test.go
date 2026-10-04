package appaccess

import (
	"context"
	"image/color"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestApplicationIconLocalDatabase(t *testing.T) {
	p := grantPool(t) // Explicit random child DB; never migrate the parent fixture.
	ctx := context.Background()
	if err := db.MigrateTo(p.Config().ConnString(), 173); err != nil {
		t.Fatal(err)
	}
	org, actor, gateway, appID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Icons',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Icon admin',now())", actor, actor.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'icons','icons-cert',now()+interval '1 day','gateway')", gateway, org)
	// Seed a real pre-upload revision with the old column set, then upgrade.
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, item := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO app_access_applications(id,org_id)VALUES($1,$2)", []any{appID, org}},
		{"INSERT INTO app_access_hostnames(hostname,org_id,app_id)VALUES('legacy.apps.fixture.test',$1,$2)", []any{org, appID}},
		{"INSERT INTO app_access_revisions(org_id,app_id,revision,name,icon,origin_url,gateway_id,public_hostname,idle_timeout_seconds,absolute_timeout_seconds,digest)VALUES($1,$2,1,'Legacy','globe','http://origin',$3,'legacy.apps.fixture.test',60,300,repeat('a',64))", []any{org, appID, gateway}},
	} {
		if _, err = tx.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.MigrateTo(p.Config().ConnString(), 174); err != nil {
		t.Fatal(err)
	}
	s := NewService(p, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	legacy, err := s.GetApplication(ctx, org, appID)
	if err != nil || legacy.Draft.IconDataURL != "" || legacy.Draft.Icon != "globe" || legacy.Draft.Digest != strings.Repeat("a", 64) {
		t.Fatal("migration changed legacy data", err)
	}
	// Before uploads exist, reversible schema down/up retains the old revision.
	if err = db.MigrateTo(p.Config().ConnString(), 173); err != nil {
		t.Fatal(err)
	}
	var oldIcon, oldDigest string
	if err = p.QueryRow(ctx, "SELECT icon,digest FROM app_access_revisions WHERE org_id=$1 AND app_id=$2 AND revision=1", org, appID).Scan(&oldIcon, &oldDigest); err != nil || oldIcon != "globe" || oldDigest != legacy.Draft.Digest {
		t.Fatal("legacy binary projection changed on rollback", err)
	}
	if err = db.MigrateTo(p.Config().ConnString(), 174); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateSettings(ctx, org, actor, true, 1, true); err != nil {
		t.Fatal(err)
	}
	in := DraftInput{Name: "Uploaded", Icon: "dashboard", IconDataURL: iconFixture(t, "jpeg", 24, color.NRGBA{R: 255, A: 255}), IconDataURLSet: true, OriginURL: "https://origin", GatewayID: gateway, PublicHostname: "uploaded.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	created, err := s.CreateDraft(ctx, org, actor, in, true)
	if err != nil || !strings.HasPrefix(created.Draft.IconDataURL, "data:image/png;base64,") {
		t.Fatal("create lost icon", err)
	}
	original := created.Draft.IconDataURL
	in.Name, in.IconDataURL, in.IconDataURLSet = "Renamed", "", false
	preserved, err := s.UpdateDraft(ctx, org, actor, created.ID, in, created.Version, true)
	if err != nil || preserved.Draft.IconDataURL != original {
		t.Fatal("omitted update erased image", err)
	}
	in.IconDataURL, in.IconDataURLSet = iconFixture(t, "png", 24, color.NRGBA{B: 255, A: 255}), true
	replaced, err := s.UpdateDraft(ctx, org, actor, created.ID, in, preserved.Version, true)
	if err != nil || replaced.Draft.IconDataURL == original || replaced.Draft.Digest == preserved.Draft.Digest {
		t.Fatal("replace did not change revision image", err)
	}
	in.IconDataURL = ""
	removed, err := s.UpdateDraft(ctx, org, actor, created.ID, in, replaced.Version, true)
	if err != nil || removed.Draft.IconDataURL != "" || removed.Draft.Icon != "dashboard" {
		t.Fatal("remove did not restore default glyph", err)
	}
	historical, err := s.GetRevision(ctx, org, created.ID, created.DraftRevision)
	if err != nil || historical.IconDataURL != original {
		t.Fatal("replace/remove changed immutable icon", err)
	}
	_, err = s.GetRevision(ctx, uuid.New(), created.ID, created.DraftRevision)
	code(t, err, "application_not_found")
	// Old binaries can still explicitly read their known columns on schema174.
	if err = p.QueryRow(ctx, "SELECT icon,digest FROM app_access_revisions WHERE org_id=$1 AND app_id=$2 AND revision=$3", org, created.ID, created.DraftRevision).Scan(&oldIcon, &oldDigest); err != nil || oldIcon != "dashboard" || oldDigest != created.Draft.Digest {
		t.Fatal("additive schema broke legacy reads", err)
	}
	if err = db.MigrateTo(p.Config().ConnString(), 173); err == nil || !strings.Contains(err.Error(), "uploaded icons are retained") {
		t.Fatal("destructive icon downgrade accepted", err)
	}
	var retained string
	if err = p.QueryRow(ctx, "SELECT icon_data_url FROM app_access_revisions WHERE org_id=$1 AND app_id=$2 AND revision=$3", org, created.ID, created.DraftRevision).Scan(&retained); err != nil || retained != original {
		t.Fatal("refused downgrade lost image", err)
	}
}
