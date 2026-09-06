package idpsync_test

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsync"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"testing"
	"time"
)

func TestOktaImportedOwnershipAndExpiryIntegration(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, connection, group := uuid.New(), uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO organizations(id,name,slug) VALUES($1,'Okta review',$2)`, org, "okta-"+org.String())
	exec(t, pool, `INSERT INTO sso_connections(id,org_id,name,provider,issuer_url,client_id,client_secret_sealed,enabled,revision,tested_revision) VALUES($1,$2,'Workforce','okta','https://company.okta.com','sso-client','test',true,1,1)`, connection, org)
	exec(t, pool, `INSERT INTO idp_sync_configs(org_id,provider,client_id,secret_sealed,enabled,okta_org_url,sso_connection_id) VALUES($1,'okta','directory-client','test',true,'https://company.okta.com',$2)`, org, connection)
	exec(t, pool, `INSERT INTO user_groups(id,org_id,name,origin,idp_provider,idp_group_id) VALUES($1,$2,'Engineering','idp_sync','okta','00gEngineering')`, group, org)
	deprov := &recordingDeprov{}
	svc := idpsync.NewService(pool, testSealer(t), &nopPusher{}, deprov, testLogger()).WithLicence(licence.NewTestManager("trial", time.Now().Add(time.Hour)))
	member := idpsync.DirectoryMember{ExternalID: "00u" + uuid.NewString(), Email: uuid.NewString() + "@example.com", Status: idpsync.StatusActive}
	uid, found, err := svc.ResolveDirectoryMember(ctx, org, group, "okta", member)
	if err != nil || !found {
		t.Fatalf("import failed: %v", err)
	}
	var manual, managed int
	var verified bool
	var role string
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE source_type='manual'), count(*) FILTER(WHERE source_type='idp_sync') FROM membership_access_sources WHERE org_id=$1 AND user_id=$2`, org, uid).Scan(&manual, &managed); err != nil {
		t.Fatal(err)
	}
	if manual != 0 || managed != 1 {
		t.Fatalf("wrong provenance: manual=%d directory=%d", manual, managed)
	}
	if err = pool.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1`, uid).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("directory email trusted before verified token")
	}
	if err = pool.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2`, org, uid).Scan(&role); err != nil || role != "member" {
		t.Fatal("import gave unexpected role")
	}
	again, found, err := svc.ResolveDirectoryMember(ctx, org, group, "okta", member)
	if err != nil || !found || again != uid {
		t.Fatal("stable subject not idempotent")
	}
	svc.WithLicence(licence.NewTestManager("trial", time.Now().Add(-time.Second)))
	blocked := idpsync.DirectoryMember{ExternalID: "00u" + uuid.NewString(), Email: uuid.NewString() + "@example.com", Status: idpsync.StatusActive}
	if _, found, err = svc.ResolveDirectoryMember(ctx, org, group, "okta", blocked); err != nil || found {
		t.Fatalf("expired trial imported user: found=%v error=%v", found, err)
	}
	var count int
	pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, blocked.Email).Scan(&count)
	if count != 0 {
		t.Fatal("expired trial created orphan user")
	}
	if changed, err := svc.RemoveIdpGroupMember(ctx, org, group, uid); err != nil || !changed {
		t.Fatalf("removal failed: %v", err)
	}
	if deprov.calls != 1 {
		t.Fatal("last mapped group failed to invoke org access revocation")
	}
}
