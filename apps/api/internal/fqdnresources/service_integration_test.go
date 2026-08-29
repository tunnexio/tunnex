package fqdnresources

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// This proof owns a fresh database through migration 0116. It deliberately
// never connects test behavior to a shared application stack.
func TestPostgresResourceContractFailClosedAndBounded(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable Postgres resource-contract proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s21_resource_contract_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	// Register cleanup before migration or pool setup: either can fail after the
	// database exists. The admin pool stays open until DROP has completed.
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("cleanup disposable proof database %s: %v", name, err)
		}
		admin.Close()
	}()
	testURL := *base
	testURL.Path = "/" + name
	if err := db.MigrateTo(testURL.String(), 118); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	// This defer runs first, so the registered database cleanup can DROP using
	// the still-open admin pool.
	defer pool.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}

	org, site, gateway, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'resource contract',$2,'10.248.0.0/24')`, org, "resource-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "resource-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal',$3,$4)`, resource, org, site, gateway)
	config := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, config, org)
	svc := New(pool)
	draft := uuid.New()
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn) VALUES($1,$2,'draft','draft.internal')`, draft, org)
	if got, err := svc.Detail(ctx, org, draft); err != nil || got.Resource.State != "draft" || got.NextAction != "edit_resource" {
		t.Fatalf("unbound draft projection=%+v err=%v", got, err)
	}
	if got, err := svc.Detail(ctx, org, resource); err != nil || got.Resource.State != "resolving" || got.NextAction != "wait_for_resolution" {
		t.Fatalf("bound resource with no generation projection=%+v err=%v", got, err)
	}
	publish := func(configID uuid.UUID, generation int64, address string) {
		t.Helper()
		id := uuid.New()
		now := time.Now().UTC().Truncate(time.Second)
		exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,$4,$5,$6,$7,'pending','5 minutes',$8)`, id, org, resource, generation, gateway, site, configID, now)
		exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,$3::inet)`, id, org, address)
		exec(`UPDATE fqdn_resource_answer_generations SET state='active',activated_at=resolved_at,last_good_at=resolved_at WHERE id=$1`, id)
	}
	pending := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,1,$4,$5,$6,'pending','5 minutes',$7)`, pending, org, resource, gateway, site, config, now)
	if got, err := svc.Detail(ctx, org, resource); err != nil || got.Resource.State != "resolving" || got.ServerReason != nil || len(got.ActiveAnswers) != 0 {
		t.Fatalf("pending generation projection=%+v err=%v", got, err)
	}
	exec(`UPDATE fqdn_resource_answer_generations SET state='withdrawn',ended_at=now(),failure_code='timeout' WHERE id=$1`, pending)
	if got, err := svc.Detail(ctx, org, resource); err != nil || got.Resource.State != "failed" || got.ServerReason == nil || *got.ServerReason != "timeout" || len(got.ActiveAnswers) != 0 {
		t.Fatalf("failed generation projection=%+v err=%v", got, err)
	}
	nxdomain := uuid.New()
	exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,state,effective_ttl,resolved_at,ended_at,failure_code) VALUES($1,$2,$3,2,$4,$5,$6,'withdrawn','5 minutes',$7,$7,'NXDOMAIN')`, nxdomain, org, resource, gateway, site, config, now)
	if got, err := svc.Detail(ctx, org, resource); err != nil || got.Resource.State != "nxdomain" || got.ServerReason == nil || *got.ServerReason != "NXDOMAIN" || len(got.ActiveAnswers) != 0 {
		t.Fatalf("NXDOMAIN generation projection=%+v err=%v", got, err)
	}
	publish(config, 3, "10.2.3.4")
	if got, err := svc.Detail(ctx, org, resource); err != nil || got.Resource.State != "healthy" || len(got.ActiveAnswers) != 1 {
		t.Fatalf("eligible active generation projection=%+v err=%v", got, err)
	}

	// The outer joins in resourceQuery must not lock their nullable sides. A
	// successful ordinary update proves PostgreSQL reached the mutation logic.
	updated, err := svc.Update(ctx, org, resource, Input{Name: "orders renamed", FQDN: "orders.internal", Protocol: "any", Context: &Context{SiteID: site, GatewayID: gateway}}, uuid.Nil, "resource-contract-test", "")
	if err != nil || updated.Name != "orders renamed" {
		t.Fatalf("ordinary update did not reach mutation logic: resource=%+v err=%v", updated, err)
	}

	for n := 0; n < 33; n++ {
		group, rule := uuid.New(), uuid.New()
		exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,$3)`, group, org, "group-"+group.String())
		expires := any(nil)
		if n == 32 {
			expires = time.Now().Add(-time.Minute)
		}
		exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_group_id,dst_kind,dst_fqdn_resource_id,expires_at) VALUES($1,$2,'group',$3,'fqdn_resource',$4,$5)`, rule, org, group, resource, expires)
	}
	impact, err := svc.Impact(ctx, org, resource)
	if err != nil || impact.ReferencingRuleCount != 33 || len(impact.ReferencingRuleIDs) != 32 || !impact.RuleIDsTruncated {
		t.Fatalf("bounded resource impact=%+v err=%v", impact, err)
	}
	setting, err := svc.SettingImpact(ctx, org)
	if err != nil || setting.EnforcementReadyRuleCount != 32 || len(setting.EnforcementReadyRuleIDs) != 32 || setting.RuleIDsTruncated {
		t.Fatalf("expired rule leaked into opt-in impact=%+v err=%v", setting, err)
	}
	if setting.ExpectedImpactToken == nil {
		t.Fatalf("setting impact omitted confirmation token: %+v", setting)
	}
	if err := svc.SetSetting(ctx, org, true, setting.ExpectedImpactToken, uuid.Nil, "resource-contract-test", ""); err != nil {
		t.Fatalf("valid unchanged setting confirmation token must commit: %v", err)
	}

	// These barriers prove the org advisory lock makes a preview confirmation
	// atomic with writers that otherwise touch neither the resource nor setting
	// row. A successful early UPDATE would be an unconfirmed-impact commit.
	second := uuid.New()
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'second','second.internal',$3,$4)`, second, org, site, gateway)
	previewInput := Input{Name: "second", FQDN: "changed.internal", Protocol: "any", Context: &Context{SiteID: site, GatewayID: gateway}}
	preview, err := svc.Preview(ctx, org, second, previewInput)
	if err != nil || preview.ExpectedImpactToken == nil || !preview.MutationAllowed {
		t.Fatalf("mutation preview=%+v err=%v", preview, err)
	}
	group, rule := uuid.New(), uuid.New()
	policyHeld, releasePolicy, policyDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		tx, e := pool.Begin(ctx)
		if e == nil {
			_, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, org)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'barrier-group')`, group, org)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO policy_rules(id,org_id,src_kind,src_group_id,dst_kind,dst_fqdn_resource_id) VALUES($1,$2,'group',$3,'fqdn_resource',$4)`, rule, org, group, second)
		}
		close(policyHeld)
		if e == nil {
			<-releasePolicy
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		policyDone <- e
	}()
	<-policyHeld
	updateDone := make(chan error, 1)
	go func() {
		_, e := svc.Update(ctx, org, second, Input{Name: "second", FQDN: "changed.internal", Protocol: "any", Context: &Context{SiteID: site, GatewayID: gateway}, ExpectedImpactToken: preview.ExpectedImpactToken}, uuid.Nil, "resource-contract-test", "")
		updateDone <- e
	}()
	select {
	case e := <-updateDone:
		t.Fatalf("update escaped org lock before policy writer commit: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(releasePolicy)
	if e := <-policyDone; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-updateDone:
		var ae *apierr.Error
		if !errors.As(e, &ae) || ae.Code != "fqdn_resource_stale_preview" {
			t.Fatalf("update did not reject concurrent policy impact: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("update deadlocked behind policy writer")
	}

	settingBefore, err := svc.SettingImpact(ctx, org)
	if err != nil || settingBefore.ExpectedImpactToken == nil {
		t.Fatalf("setting impact before writer=%+v err=%v", settingBefore, err)
	}
	generationHeld, releaseGeneration, generationDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		tx, e := pool.Begin(ctx)
		if e == nil {
			_, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, org)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='withdrawn',ended_at=now(),failure_code='barrier' WHERE org_id=$1 AND resource_id=$2 AND state='active'`, org, resource)
		}
		close(generationHeld)
		if e == nil {
			<-releaseGeneration
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		generationDone <- e
	}()
	<-generationHeld
	settingDone := make(chan error, 1)
	go func() {
		settingDone <- svc.SetSetting(ctx, org, true, settingBefore.ExpectedImpactToken, uuid.Nil, "resource-contract-test", "")
	}()
	select {
	case e := <-settingDone:
		t.Fatalf("setting escaped org lock before generation writer commit: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseGeneration)
	if e := <-generationDone; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-settingDone:
		var ae *apierr.Error
		if !errors.As(e, &ae) || ae.Code != "fqdn_resource_stale_preview" {
			t.Fatalf("setting did not reject concurrent generation impact: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("setting deadlocked behind generation writer")
	}

	// The stale-token race withdrew generation 3. Publish a *new* active
	// generation under the old active config, so replacement proves config
	// identity (rather than merely a previously withdrawn generation) withdraws
	// compiler eligibility immediately.
	publish(config, 4, "10.2.3.5")
	assertHealthy := func(stage string) {
		t.Helper()
		detail, err := svc.Detail(ctx, org, resource)
		get, getErr := svc.Get(ctx, org, resource)
		list, listErr := svc.List(ctx, org)
		var listed *Resource
		for i := range list {
			if list[i].ID == resource {
				listed = &list[i]
				break
			}
		}
		if err != nil || getErr != nil || listErr != nil || listed == nil || detail.Resource.State != "healthy" || get.State != "healthy" || listed.State != "healthy" || detail.Resource.Generation == nil || get.Generation == nil || listed.Generation == nil || len(detail.ActiveAnswers) != 1 {
			t.Fatalf("%s projections did not expose current active generation: detail=%+v get=%+v list=%+v errs=%v/%v/%v", stage, detail, get, list, err, getErr, listErr)
		}
	}
	assertHealthy("old active config")
	// Readers do not take the writer lock. While the replacement commits, each
	// one must nevertheless return one coherent snapshot: healthy can only be
	// paired with the old configuration, never the replacement configuration.
	type replacementResult struct {
		config ResolverConfig
		err    error
	}
	replacementDone := make(chan replacementResult, 1)
	go func() {
		configured, e := svc.SetResolverConfig(ctx, org, site, gateway, uuid.Nil, "resource-contract-test", "", nil, []ResolverEndpoint{{Address: "10.53.0.54", Port: 53, Transport: "tcp"}})
		replacementDone <- replacementResult{config: configured, err: e}
	}()
	var replacement ResolverConfig
	replacementTimeout := time.NewTimer(2 * time.Second)
	defer replacementTimeout.Stop()
replacementReadLoop:
	for {
		detail, detailErr := svc.Detail(ctx, org, resource)
		get, getErr := svc.Get(ctx, org, resource)
		list, listErr := svc.List(ctx, org)
		var listed *Resource
		for i := range list {
			if list[i].ID == resource {
				listed = &list[i]
				break
			}
		}
		for _, projection := range []Resource{detail.Resource, get} {
			if projection.State == "healthy" && (projection.Context == nil || projection.Context.Config == nil || projection.Context.Config.ID != config) {
				t.Fatalf("replacement read mixed active generation with replacement context: %+v", projection)
			}
		}
		if listed == nil || detailErr != nil || getErr != nil || listErr != nil {
			t.Fatalf("concurrent replacement projection failed: detail=%v get=%v list=%v listed=%+v", detailErr, getErr, listErr, listed)
		}
		if listed.State == "healthy" && (listed.Context == nil || listed.Context.Config == nil || listed.Context.Config.ID != config) {
			t.Fatalf("replacement list mixed active generation with replacement context: %+v", listed)
		}
		select {
		case result := <-replacementDone:
			if result.err != nil {
				t.Fatal(result.err)
			}
			replacement = result.config
			break replacementReadLoop
		case <-replacementTimeout.C:
			t.Fatal("resolver replacement deadlocked")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if replacement.ID == uuid.Nil || replacement.ID == config {
		t.Fatal("resolver replacement did not create a new immutable revision")
	}
	assertUnavailable := func(stage string) {
		t.Helper()
		detail, err := svc.Detail(ctx, org, resource)
		get, getErr := svc.Get(ctx, org, resource)
		list, listErr := svc.List(ctx, org)
		var listed *Resource
		for i := range list {
			if list[i].ID == resource {
				listed = &list[i]
				break
			}
		}
		if err != nil || getErr != nil || listErr != nil || detail.Resource.State == "healthy" || get.State == "healthy" || listed == nil || listed.State == "healthy" || detail.Resource.Generation != nil || get.Generation != nil || listed.Generation != nil || detail.Resource.AnswerCount != 0 || get.AnswerCount != 0 || listed.AnswerCount != 0 || detail.Resource.EffectiveTTLSeconds != nil || get.EffectiveTTLSeconds != nil || listed.EffectiveTTLSeconds != nil || detail.Resource.RefreshedAt != nil || get.RefreshedAt != nil || listed.RefreshedAt != nil || detail.FreshUntilAt != nil || len(detail.ActiveAnswers) != 0 {
			t.Fatalf("%s projections retained eligible health: detail=%+v get=%+v list=%+v errs=%v/%v/%v", stage, detail, get, list, err, getErr, listErr)
		}
	}
	assertUnavailable("replacement")
	if err := svc.DeleteResolverConfig(ctx, org, site, gateway, uuid.Nil, "resource-contract-test", ""); err != nil {
		t.Fatal(err)
	}
	assertUnavailable("removal")
}
