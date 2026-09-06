package sso

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strings"
	"testing"
	"time"
)

func TestConnectionFlowBindsRevisionOrgAndInitiatingAdmin(t *testing.T) {
	id, org, actor := uuid.New(), uuid.New(), uuid.New()
	c := sqlc.SsoConnection{ID: id, OrgID: org, Revision: 2, Enabled: true}
	f := connectionFlow{ConnectionID: id, OrgID: org, Actor: actor, Revision: 2, Mode: "test"}
	if !connectionFlowCurrent(f, c, actor) {
		t.Fatal("valid test refused")
	}
	if connectionFlowCurrent(f, c, uuid.New()) || connectionFlowCurrent(f, c, uuid.Nil) {
		t.Fatal("test accepted another session")
	}
	other := c
	other.Revision = 3
	if connectionFlowCurrent(f, other, actor) {
		t.Fatal("stale test accepted")
	}
	other = c
	other.OrgID = uuid.New()
	if connectionFlowCurrent(f, other, actor) {
		t.Fatal("cross-org test accepted")
	}
	f.Mode = "login"
	if !connectionFlowCurrent(f, c, uuid.Nil) {
		t.Fatal("enabled login refused")
	}
	c.Enabled = false
	if connectionFlowCurrent(f, c, uuid.Nil) {
		t.Fatal("disabled login accepted")
	}
}

func TestConnectionCallbackRejectsAnotherBrowserWithoutConsumingFlow(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	svc := &Service{flows: NewFlowStore(rdb, time.Minute)}
	binding := strings.Repeat("a", 32)
	flow := connectionFlow{ConnectionID: uuid.New(), OrgID: uuid.New(), Actor: uuid.New(), Mode: "test", BrowserHash: sha256.Sum256([]byte(binding))}
	raw, _ := json.Marshal(flow)
	ctx := context.Background()
	rdb.Set(ctx, "ssoconnection:flow", raw, time.Minute)
	for _, wrong := range []string{"", strings.Repeat("b", 32)} {
		result, err := svc.CompleteConnection(ctx, "", "flow", wrong, flow.Actor)
		if err == nil || result.UserID != uuid.Nil {
			t.Fatal("cross-browser callback accepted")
		}
		if !mr.Exists("ssoconnection:flow") {
			t.Fatal("another browser consumed the legitimate flow")
		}
	}
	result, err := svc.CompleteConnection(ctx, "", "flow", binding, flow.Actor)
	if err == nil || !result.Test {
		t.Fatal("bound cancelled flow should return test cancellation")
	}
	if mr.Exists("ssoconnection:flow") {
		t.Fatal("completed flow can replay")
	}
	if _, err = svc.CompleteConnection(ctx, "", "flow", binding, flow.Actor); err == nil {
		t.Fatal("replay accepted")
	}
}
func TestSelfLinkRequiresActiveConnectionAndSameActor(t *testing.T) {
	c := sqlc.SsoConnection{ID: uuid.New(), OrgID: uuid.New(), Revision: 1, Enabled: true}
	actor := uuid.New()
	f := connectionFlow{ConnectionID: c.ID, OrgID: c.OrgID, Revision: 1, Actor: actor, Mode: "link", Link: true}
	if !connectionFlowCurrent(f, c, actor) {
		t.Fatal("member self-link refused")
	}
	if connectionFlowCurrent(f, c, uuid.New()) {
		t.Fatal("another actor can link")
	}
	c.Enabled = false
	if connectionFlowCurrent(f, c, actor) {
		t.Fatal("disabled self-link accepted")
	}
}

func TestConnectionNamespaceAndActivationIntegration(t *testing.T) {
	h := newFlowHarness(t) // Requires explicitly isolated TUNNEX_TEST_DATABASE_URL.
	actor := uuid.New()
	_, err := h.tx.Exec(h.ctx, "INSERT INTO users (id,email,name,email_verified_at) VALUES ($1,$2,'Admin',now())", actor, actor.String()+"@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secret := "test-only-client-secret"
	id := uuid.New()
	input := ConnectionInput{Name: "Workforce", Provider: "oidc", Issuer: "https://identity.example.com", ClientID: "client", Secret: &secret}
	c, err := h.svc.SaveConnection(h.ctx, actor, h.org, id, input)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled {
		t.Fatal("new connection is enabled")
	}
	if _, err = h.svc.ActivateConnection(h.ctx, actor, h.org, id, c.Revision, true); code(err) != "sso_test_required" {
		t.Fatalf("unverified enable: %v", err)
	}
	_, err = h.q.VerifySSOConnection(h.ctx, sqlc.VerifySSOConnectionParams{ID: id, Revision: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.svc.ActivateConnection(h.ctx, actor, h.org, id, c.Revision, true); err != nil {
		t.Fatal(err)
	}
	if err = h.q.LinkSSOConnectionIdentity(h.ctx, sqlc.LinkSSOConnectionIdentityParams{ConnectionID: id, IssuerUrl: input.Issuer, Subject: "subject", UserID: actor}); err != nil {
		t.Fatal(err)
	}
	input.Issuer = "https://other.example.com"
	if _, err = h.svc.SaveConnection(h.ctx, actor, h.org, id, input); code(err) != "sso_identity_namespace_locked" {
		t.Fatalf("issuer mutation accepted: %v", err)
	}
	input.Issuer = "https://identity.example.com"
	input.Secret = nil
	c, err = h.svc.SaveConnection(h.ctx, actor, h.org, id, input)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.TestedRevision != nil {
		t.Fatal("save preserved old verification")
	}
}
