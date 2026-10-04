package appaccess

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"image/color"
	"testing"
	"time"
)

func TestPublishedCatalogLocalDatabase(t *testing.T) {
	p := grantPool(t)
	if e := db.MigrateTo(p.Config().ConnString(), 174); e != nil {
		t.Fatal(e)
	}
	c := context.Background()
	org, user, gateway := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := p.Exec(c, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Catalog',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Catalog',now())", user, user.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, user)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'catalog','catalog-cert',now()+interval '1 day','gateway')", gateway, org)
	s := NewService(p, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"})
	if _, e := s.UpdateSettings(c, org, user, true, 1, true); e != nil {
		t.Fatal(e)
	}
	create := func(name, host string) Application {
		t.Helper()
		a, e := s.CreateDraft(c, org, user, DraftInput{Name: name, Description: "published description", Icon: "app", IconDataURL: iconFixture(t, "png", 24, color.Black), OriginURL: "http://origin", GatewayID: gateway, PublicHostname: host + ".apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	draft := create("A Draft", "catalog-draft")
	denied := create("B Denied", "catalog-denied")
	allowed := create("C Published", "catalog-allowed")
	publish := func(a Application) {
		exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", org, a.ID, gateway, a.Draft.Revision, a.Draft.Digest, a.Draft.PublicHostname)
	}
	publish(denied)
	publish(allowed) // isolated positive publication fixtures only; native rows remain empty.
	filtered, e := sqlc.New(p).ListAppAccessApplicationIDs(c, sqlc.ListAppAccessApplicationIDsParams{OrgID: org, Search: "", PageLimit: 1, PublicationState: "published"})
	if e != nil || len(filtered) != 1 || filtered[0] != denied.ID {
		t.Fatal("publication filter before pagination", e, filtered)
	}
	filtered, e = sqlc.New(p).ListAppAccessApplicationIDs(c, sqlc.ListAppAccessApplicationIDsParams{OrgID: org, Search: "", PageLimit: 1, PublicationState: "unpublished"})
	if e != nil || len(filtered) != 1 || filtered[0] != draft.ID {
		t.Fatal("unpublished filter", e, filtered)
	}

	for _, a := range []Application{draft, allowed} {
		if _, e := s.CreateGrant(c, org, user, GrantInput{AppID: a.ID, SubjectKind: "user", SubjectID: user, Enabled: true}, true); e != nil {
			t.Fatal(e)
		}
	}
	newer := allowed.Draft.DraftInput
	newer.Name = "Z Unpublished"
	newer.Description = "new draft only"
	newer.PublicHostname = "catalog-unpublished-change.apps.example.net"
	newer.OriginURL = "http://unpublished-only.internal"
	newer.Icon = "terminal"
	newer.IconDataURL = iconFixture(t, "png", 24, color.White)
	newer.IconDataURLSet = true
	updated, e := s.UpdateDraft(c, org, user, allowed.ID, newer, allowed.Version, true)
	if e != nil {
		t.Fatal(e)
	}
	count, e := sqlc.New(p).AppAccessPublicationMatchingUserCount(c, sqlc.AppAccessPublicationMatchingUserCountParams{OrgID: org, AppID: allowed.ID, EvaluatedAt: time.Now(), EligibleRoles: []string{"owner", "admin", "member"}})
	if e != nil || count != 1 {
		t.Fatal("explicit publication match count", count, e)
	}
	count, e = sqlc.New(p).AppAccessPublicationMatchingUserCount(c, sqlc.AppAccessPublicationMatchingUserCountParams{OrgID: org, AppID: denied.ID, EvaluatedAt: time.Now(), EligibleRoles: []string{"owner", "admin", "member"}})
	if e != nil || count != 0 {
		t.Fatal("default-denied publication match count", count, e)
	}
	args := sqlc.ListMyAppAccessPublishedCandidatesParams{OrgID: org, UserID: user, EvaluatedAt: time.Now(), PageLimit: 1, EligibleRoles: []string{"owner", "admin", "member"}}
	q := sqlc.New(p)
	rows, e := q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 1 || rows[0].AppID != allowed.ID || rows[0].Name != "C Published" || rows[0].Description != "published description" || rows[0].IconDataUrl != updated.Draft.IconDataURL || rows[0].Icon != "terminal" || rows[0].Hostname != allowed.Draft.PublicHostname || rows[0].Revision != allowed.DraftRevision || rows[0].Digest != allowed.Draft.Digest {
		t.Fatal("draft/denied rows consumed page or metadata drifted", e, rows)
	}
	// Branding replacement/removal takes effect on save; immutable routing and
	// publication metadata remain bound to the active revision throughout.
	for _, branding := range []struct{ icon, image string }{
		{"globe", iconFixture(t, "png", 24, color.NRGBA{R: 255, A: 255})},
		{"dashboard", ""},
	} {
		newer.Icon, newer.IconDataURL, newer.IconDataURLSet = branding.icon, branding.image, true
		updated, e = s.UpdateDraft(c, org, user, allowed.ID, newer, updated.Version, true)
		if e != nil {
			t.Fatal(e)
		}
		rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
		if e != nil || len(rows) != 1 || rows[0].Icon != branding.icon || rows[0].IconDataUrl != updated.Draft.IconDataURL || rows[0].Name != allowed.Draft.Name || rows[0].Description != allowed.Draft.Description || rows[0].Hostname != allowed.Draft.PublicHostname || rows[0].Revision != allowed.DraftRevision || rows[0].Digest != allowed.Draft.Digest {
			t.Fatal("saved branding did not update independently of published authority", e)
		}
	}
	args.Search = "Published"
	rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 1 {
		t.Fatal("published metadata search", e)
	}
	args.Search = "Unpublished"
	rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 0 {
		t.Fatal("draft metadata became serving search", e)
	}
	args.Search = ""
	args.PageOffset = 1
	rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 0 {
		t.Fatal("offset applied before grant filter", e)
	}
	args.PageOffset = 0
	args.OrgID = uuid.New()
	rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 0 {
		t.Fatal("foreign tenant catalog", e)
	}
	args.OrgID = org
	exec("UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2", org, user)
	rows, e = q.ListMyAppAccessPublishedCandidates(c, args)
	if e != nil || len(rows) != 0 {
		t.Fatal("revoked member catalog", e)
	}
	p.Close()
	for _, lookup := range []func() error{
		func() error { _, e := s.lookupServingRoute(c, allowed.Draft.PublicHostname, true); return e },
		func() error { _, e := s.lookupServingApplication(c, org, allowed.ID, true); return e },
	} {
		var unavailable *apierr.Error
		if e := lookup(); !errors.As(e, &unavailable) || unavailable.Status != 503 {
			t.Fatal("database failure disguised as missing route", e)
		}
	}

}
