package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type installationFake struct {
	fakeStore
	ever       int64
	fail       string
	steps      []string
	org        sqlc.CreateOrganizationParams
	membership sqlc.UpsertMembershipParams
	token      sqlc.CreateJoinTokenParams
	audits     []sqlc.InsertAuditLogParams
}

func (f *installationFake) step(name string) error {
	f.steps = append(f.steps, name)
	if f.fail == name {
		return errors.New("injected failure")
	}
	return nil
}
func (f *installationFake) CreateBootstrapAdmin(ctx context.Context, p sqlc.CreateBootstrapAdminParams) (sqlc.User, error) {
	u, err := f.fakeStore.CreateBootstrapAdmin(ctx, p)
	u.ID = uuid.MustParse("01900000-0000-7000-8000-000000000001")
	return u, err
}
func (f *installationFake) CountOrganizationsEver(context.Context) (int64, error) {
	return f.ever, f.step("count-orgs")
}
func (f *installationFake) CreateOrganization(_ context.Context, p sqlc.CreateOrganizationParams) (sqlc.Organization, error) {
	f.org = p
	return sqlc.Organization{ID: uuid.New(), Name: p.Name, Slug: p.Slug}, f.step("org")
}
func (f *installationFake) UpsertMembership(_ context.Context, p sqlc.UpsertMembershipParams) (sqlc.Membership, error) {
	f.membership = p
	return sqlc.Membership{}, f.step("membership")
}
func (f *installationFake) CreateJoinToken(_ context.Context, p sqlc.CreateJoinTokenParams) (sqlc.NodeJoinToken, error) {
	f.token = p
	return sqlc.NodeJoinToken{}, f.step("token")
}
func (f *installationFake) InsertAuditLog(_ context.Context, p sqlc.InsertAuditLogParams) (sqlc.AuditLog, error) {
	f.audits = append(f.audits, p)
	return sqlc.AuditLog{}, f.step(p.Action)
}

func TestInstallationCreatesOwnerAndPinnedGatewayBeforeCredential(t *testing.T) {
	f := &installationFake{}
	logger, logs, out := capture()
	m := &fakeMailer{}
	hash := strings.Repeat("ab", 32)
	before := time.Now()
	s := &installationStore{installationQueries: f, intent: Installation{OrganizationName: "Acme", GatewayName: "quickstart-gateway", GatewayTokenHash: hash}, commit: func(context.Context) error {
		if out.Len() != 0 || len(m.messages) != 0 {
			t.Fatal("credential released before commit")
		}
		return f.step("commit")
	}}
	if err := EnsureAdmin(context.Background(), s, logger, out, "owner@example.com", m); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.steps, ","); got != "count-orgs,org,membership,org.created,token,node.token_issued,commit" {
		t.Fatal(got)
	}
	if f.org.Name != "Acme" || f.membership.Role != "owner" || f.membership.OrgID != f.token.OrgID {
		t.Fatal("wrong organization ownership")
	}
	if *f.token.NodeName != "quickstart-gateway" || f.token.EnrolsKind != "gateway" || len(f.token.TokenHash) != 32 || !f.token.IssuedBy.Valid {
		t.Fatal("unbound token")
	}
	if f.token.ExpiresAt.Before(before.Add(59*time.Minute)) || f.token.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Fatal("wrong expiry")
	}
	if !strings.Contains(out.String(), "password") || len(m.messages) != 1 {
		t.Fatal("credential missing after commit")
	}
	if strings.Contains(out.String()+logs.String(), hash) {
		t.Fatal("token hash disclosed")
	}
	for _, a := range f.audits {
		if strings.Contains(string(a.Metadata), hash) {
			t.Fatal("token hash audited")
		}
	}
}

func TestInstallationFailuresNeverReleaseCredential(t *testing.T) {
	for _, stage := range []string{"count-orgs", "org", "membership", "org.created", "token", "node.token_issued", "commit"} {
		t.Run(stage, func(t *testing.T) {
			f := &installationFake{fail: stage}
			logger, _, out := capture()
			m := &fakeMailer{}
			s := &installationStore{installationQueries: f, intent: Installation{OrganizationName: "Acme", GatewayName: "local", GatewayTokenHash: strings.Repeat("ab", 32)}, commit: func(context.Context) error { return f.step("commit") }}
			if err := EnsureAdmin(context.Background(), s, logger, out, "", m); err == nil {
				t.Fatal("failure swallowed")
			}
			if out.Len() != 0 || len(m.messages) != 0 {
				t.Fatal("credential released for failed setup")
			}
			if stage != "commit" && f.steps[len(f.steps)-1] == "commit" {
				t.Fatal("committed failed setup")
			}
		})
	}
}

func TestInstallationRestartIsInertEvenWithChangedIntent(t *testing.T) {
	f := &installationFake{fakeStore: fakeStore{users: 1}}
	logger, _, out := capture()
	s := &installationStore{installationQueries: f, intent: Installation{OrganizationName: "Another org", GatewayTokenHash: "invalid"}, commit: func(context.Context) error { t.Fatal("restart committed bootstrap"); return nil }}
	if err := EnsureAdmin(context.Background(), s, logger, out, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(f.steps) != 0 || len(f.created) != 0 || out.Len() != 0 {
		t.Fatal("restart changed installation")
	}
}

func TestInstallationSeparateGatewayDoesNotMintToken(t *testing.T) {
	f := &installationFake{}
	logger, _, out := capture()
	s := &installationStore{installationQueries: f, intent: Installation{OrganizationName: "First org"}, commit: func(context.Context) error { return nil }}
	if err := EnsureAdmin(context.Background(), s, logger, out, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(f.token.TokenHash) != 0 || len(f.audits) != 1 {
		t.Fatal("unexpected gateway grant")
	}
}

func TestInstallationRefusesMalformedIntentAndHistoricalOrganization(t *testing.T) {
	for _, intent := range []Installation{
		{OrganizationName: " \n "}, {OrganizationName: "A\nB"}, {OrganizationName: strings.Repeat("a", 121)},
		{OrganizationName: "Acme", GatewayTokenHash: "bad", GatewayName: "local"},
		{GatewayTokenHash: strings.Repeat("ab", 32), GatewayName: "local"},
		{OrganizationName: "Acme", GatewayTokenHash: strings.Repeat("ab", 32)},
	} {
		f := &installationFake{}
		logger, _, out := capture()
		s := &installationStore{installationQueries: f, intent: intent, commit: func(context.Context) error { t.Fatal("invalid intent committed"); return nil }}
		if EnsureAdmin(context.Background(), s, logger, out, "", nil) == nil || len(f.created) != 0 {
			t.Fatal("invalid intent accepted")
		}
	}
	f := &installationFake{ever: 1}
	logger, _, out := capture()
	s := &installationStore{installationQueries: f, intent: Installation{OrganizationName: "Acme"}}
	if EnsureAdmin(context.Background(), s, logger, out, "", nil) == nil || len(f.created) != 0 {
		t.Fatal("historical org accepted")
	}
}
