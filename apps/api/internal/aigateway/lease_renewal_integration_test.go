package aigateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AI-COMPAT-1: an in-flight workload request renews its lease from the facts
// its bearer proved, so it survives token expiry and rotation, and stops as
// soon as the instance, workload or model grant is no longer live.
func TestWorkloadLeaseRenewalPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
	r := f.enroll(f.key(false, 1))
	token := f.token(r)
	grant := f.admitted(token, "openrouter/a", r)
	if grant.Renew == nil {
		t.Fatal("workload grant has no renewal")
	}
	// The bearer expires and is removed by later rotations; renewal continues.
	if _, err := pool.Exec(ctx, `DELETE FROM ai_workload_tokens WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	f.rejected(token, "openrouter/a", 401)
	next, err := grant.Renew(ctx)
	if err != nil || next.Instance != grant.Instance || next.Agent != grant.Agent || next.VirtualKey != grant.VirtualKey || next.SubjectKind != "workload" {
		t.Fatalf("renewal after bearer removal failed: %v", err)
	}
	// Removing the model from the workload's grant ends renewal.
	f.update(true, nil, "applied")
	if _, err := grant.Renew(ctx); err == nil {
		t.Fatal("renewal survived model removal")
	}

	g := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
	r2 := g.enroll(g.key(false, 1))
	grant2 := g.admitted(g.token(r2), "openrouter/a", r2)
	if _, err := pool.Exec(ctx, `UPDATE ai_workload_instances SET state='retired' WHERE org_id=$1 AND id=$2`, g.org, r2.receipt.InstanceId); err != nil {
		t.Fatal(err)
	}
	if _, err := grant2.Renew(ctx); err == nil {
		t.Fatal("renewal survived instance retirement")
	}

	h := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
	r3 := h.enroll(h.key(false, 1))
	grant3 := h.admitted(h.token(r3), "openrouter/a", r3)
	if _, err := pool.Exec(ctx, `UPDATE organizations SET ai_gateway_enabled=false WHERE id=$1`, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := grant3.Renew(ctx); err == nil {
		t.Fatal("renewal survived organization AI switch-off")
	}
}

// Agent requests renew from the device and runtime credential revision their
// five-minute AI credential proved, not from that credential's row.
func TestAgentLeaseRenewalPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	if a := f.reconcile(); a.Status != "applied" {
		t.Fatalf("not applied: %+v", a)
	}
	c := f.mint()
	grant, err := f.service.Authorize(ctx, c.Token, "openrouter/a")
	if err != nil || grant.Renew == nil {
		t.Fatalf("agent grant without renewal: %v", err)
	}
	f.exec(`DELETE FROM ai_gateway_credentials WHERE org_id=$1`, f.org)
	if _, err := f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
		t.Fatal("removed credential admitted a new request")
	}
	next, err := grant.Renew(ctx)
	if err != nil || next.Agent != grant.Agent || next.VirtualKey != grant.VirtualKey {
		t.Fatalf("renewal after credential rotation failed: %v", err)
	}
	f.exec(`UPDATE agent_runtime_credentials SET state='revoked',revoked_at=now() WHERE org_id=$1 AND device_id=$2`, f.org, f.device)
	if _, err := grant.Renew(ctx); err == nil {
		t.Fatal("renewal survived runtime credential revocation")
	}
}

// User (console and VPN) grants renew through the same resolver; removing the
// user from the granted group ends renewal.
func TestUserLeaseRenewalPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	f.policies.engine = newProviderFixtureEngine()
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "Renewal provider", Models: []string{"openrouter/renew"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, user := uuid.New(), uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Renewal')`, group, f.org)
	f.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'User',now())`, user, user.String()+"@test.local")
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, user)
	if _, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, "openrouter/renew", true, 0); err != nil {
		t.Fatal(err)
	}
	grant, err := f.policies.ResolveUserModel(ctx, f.org, user, "openrouter/renew")
	if err != nil || grant.Renew == nil {
		t.Fatalf("user grant without renewal: %v", err)
	}
	if next, err := grant.Renew(ctx); err != nil || next.Agent != grant.Agent {
		t.Fatalf("renewal failed: %v", err)
	}
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND user_id=$2`, f.org, user)
	if _, err := grant.Renew(ctx); err == nil {
		t.Fatal("renewal survived group removal")
	}
}

// Renewal of a user request re-checks the grant it was admitted with (same
// virtual key) and does not repeat the group's daily cost admission.
func TestUserLeaseRenewalPinsGrantAndSkipsCostPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	const model = "openrouter/pinned"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "Pinned provider", Models: []string{model}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	limited, open, user := uuid.New(), uuid.New(), uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Limited'),($3,$2,'Open')`, limited, f.org, open)
	f.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'User',now())`, user, user.String()+"@test.local")
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$4),($1,$3,$4)`, f.org, limited, open, user)
	gl, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, limited, p.ID, model, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, open, p.ID, model, true, 0); err != nil {
		t.Fatal(err)
	}
	spend := 0.0
	engine.usageFor = func([]string) (float64, error) { return spend, nil }
	if _, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, limited, floatPtr(10), 0); err != nil {
		t.Fatal(err)
	}
	// Only the limited group remains: admitted under its limit.
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, open, user)
	grant, err := f.policies.ResolveUserModel(ctx, f.org, user, model)
	if err != nil || grant.Renew == nil {
		t.Fatalf("admission: %v", err)
	}
	limitedKey, _ := openBoundKey(f.policies.sealer, userGrantKeyPurpose, f.org, gl.ID, gl.native, gl.bindingRevision, gl.sealed)
	if grant.VirtualKey != limitedKey {
		t.Fatal("admitted through an unexpected grant")
	}
	// The threshold is reached mid-request: new requests are refused, the
	// in-flight one renews (admission is per request).
	spend = 50
	if _, err := f.policies.ResolveUserModel(ctx, f.org, user, model); err == nil {
		t.Fatal("new request admitted past the threshold")
	}
	next, err := grant.Renew(ctx)
	if err != nil || next.VirtualKey != grant.VirtualKey {
		t.Fatalf("renewal repeated cost admission or switched grants: %v", err)
	}
	// Leaving the admitted group ends renewal even though another group
	// (re-added) still grants the model: renewal is pinned to the grant.
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, open, user)
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, limited, user)
	if _, err := grant.Renew(ctx); err == nil {
		t.Fatal("renewal switched to another group's grant")
	}
}

// Long requests through the adapter with the real resolvers: the adapter
// cancels admission's context after authorization, so renewal must not depend
// on it. Covers the workload, agent (tnx_ai_) and console user paths.
func TestLongRequestsThroughAdapterRenewPostgres(t *testing.T) {
	restore := SetGrantLeaseForTests(600 * time.Millisecond)
	defer restore()
	ctx, pool := testpostgres.New(t)
	const hold = 1500 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			for end := time.Now().Add(hold); time.Now().Before(end); {
				io.WriteString(w, "data: {}\n\n")
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
			io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		time.Sleep(hold)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"done":true}`)
	}))
	defer upstream.Close()
	run := func(t *testing.T, name string, authorize Authorize, model string) {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s stream=%v", name, stream), func(t *testing.T) {
				a, err := NewAdapter(upstream.URL, func(context.Context, string, string) (Grant, error) { return Grant{}, errors.New("unused") })
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a.ServeAuthorized(w, r, authorize) }))
				defer server.Close()
				body := `{"model":"` + model + `","messages":[{"role":"user","content":"x"}]` + map[bool]string{true: `,"stream":true`}[stream] + `}`
				res, err := (&http.Client{Timeout: 10 * time.Second}).Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(res.Body)
				res.Body.Close()
				want := `{"done":true}`
				if stream {
					want = "[DONE]"
				}
				if err != nil || res.StatusCode != 200 || !strings.Contains(string(data), want) {
					t.Fatalf("status=%d err=%v body=%.120s", res.StatusCode, err, data)
				}
			})
		}
	}
	// Workload.
	w := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
	r := w.enroll(w.key(false, 1))
	token := w.token(r)
	run(t, "workload", func(ctx context.Context, _ string, model string) (Grant, error) {
		return w.workloads.Authorize(ctx, token, model)
	}, "openrouter/a")
	// Agent AI credential.
	f := newPolicyFixture(t, ctx, pool)
	if a := f.reconcile(); a.Status != "applied" {
		t.Fatalf("not applied: %+v", a)
	}
	c := f.mint()
	run(t, "agent", func(ctx context.Context, _ string, model string) (Grant, error) {
		return f.service.Authorize(ctx, c.Token, model)
	}, "openrouter/a")
	// Console user.
	u := newPolicyFixture(t, ctx, pool)
	u.policies.engine = newProviderFixtureEngine()
	u.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	p, err := u.policies.CreateProvider(ctx, u.org, u.owner, ProviderInput{Provider: "openrouter", Name: "Long provider", Models: []string{"openrouter/long"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, user := uuid.New(), uuid.New()
	u.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Long')`, group, u.org)
	u.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'User',now())`, user, user.String()+"@test.local")
	u.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, u.org, user)
	u.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, u.org, group, user)
	if _, err := u.policies.PutUserModelGrant(ctx, u.org, u.owner, group, p.ID, "openrouter/long", true, 0); err != nil {
		t.Fatal(err)
	}
	run(t, "user", func(ctx context.Context, _ string, model string) (Grant, error) {
		return u.policies.ResolveUserModel(ctx, u.org, user, model)
	}, "openrouter/long")
}
