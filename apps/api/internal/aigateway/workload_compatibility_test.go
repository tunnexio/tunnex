package aigateway

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestWorkloadCompatibilityPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	t.Run("idle_retirement_rechecks_renewal_and_preserves_durable_instances", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(true, 0)
		idle, renewed := f.enroll(key), f.enroll(key)
		durableKey, err := f.workloads.CreateKey(ctx, f.org, f.owner, f.workload.Id, api.AIWorkloadKeyInput{
			Name: "durable-instance", Reusable: false, MaxUses: 1, Ephemeral: false, ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		durable := f.enroll(durableKey)
		idleToken, durableToken := f.token(idle), f.token(durable)
		f.exec(`UPDATE ai_workload_instances SET last_contact_at=now()-interval '25 hours' WHERE org_id=$1 AND workload_id=$2`, f.org, f.workload.Id)
		assertState := func(r workloadLifecycleReplica, want string) {
			t.Helper()
			var got string
			if err := pool.QueryRow(ctx, `SELECT state FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND id=$3`, f.org, f.workload.Id, r.receipt.InstanceId).Scan(&got); err != nil || got != want {
				t.Fatalf("instance state=%s, want %s: %v", got, want, err)
			}
		}
		if err := f.workloads.Maintain(ctx, 100); err != nil {
			t.Fatal(err)
		}
		assertState(idle, "active")
		assertState(durable, "active")
		candidate := workloadInstance{org: f.org, workload: f.workload.Id, id: renewed.receipt.InstanceId}
		renewedToken := f.token(renewed)
		if err := f.workloads.retireIdle(ctx, candidate); err != nil {
			t.Fatal(err)
		}
		assertState(renewed, "active")
		f.admitted(renewedToken, "openrouter/a", renewed)
		f.workloads.maintenanceMu.Lock()
		f.workloads.recoverySince = time.Now().Add(-11 * time.Minute)
		f.workloads.lastMaintenance = time.Now().Add(-2 * time.Minute)
		f.workloads.maintenanceMu.Unlock()
		if err := f.workloads.Maintain(ctx, 100); err != nil {
			t.Fatal(err)
		}
		assertState(idle, "active")
		f.workloads.maintenanceMu.Lock()
		f.workloads.recoverySince = time.Now().Add(-11 * time.Minute)
		f.workloads.lastMaintenance = time.Now()
		f.workloads.maintenanceMu.Unlock()
		if err := f.workloads.Maintain(ctx, 100); err != nil {
			t.Fatal(err)
		}
		assertState(idle, "retired")
		assertState(renewed, "active")
		assertState(durable, "active")
		f.rejected(idleToken, "openrouter/a", 401)
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, idle)); usageStatus(err) != 401 {
			t.Fatalf("idle retirement retained token issuance: %v", err)
		}
		f.admitted(durableToken, "openrouter/a", durable)
		var audits int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND target_id=$2 AND action='ai_workload.instance_idle_retired' AND actor_system='workload-identity'`, f.org, idle.receipt.InstanceId.String()).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("idle retirement audit count=%d: %v", audits, err)
		}

		hash := sha256.Sum256([]byte(renewedToken))
		f.exec(`INSERT INTO ai_workload_tokens(token_hash,org_id,workload_id,instance_id,audience,key_generation,workload_epoch,org_revision,expires_at)
		 SELECT decode(lpad(to_hex(i),64,'0'),'hex'),org_id,workload_id,instance_id,audience,key_generation,workload_epoch,org_revision,now()-interval '1 minute'
		 FROM ai_workload_tokens CROSS JOIN generate_series(1,7) i WHERE token_hash=$1`, hash[:])
		f.exec(`INSERT INTO ai_workload_assertions(instance_id,jti,expires_at) SELECT $1,'expired-assertion-'||i,now()-interval '1 minute' FROM generate_series(1,7) i`, renewed.receipt.InstanceId)
		counts := func() (int, int, int, int) {
			t.Helper()
			var expiredTokens, liveTokens, expiredProofs, liveProofs int
			if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE expires_at<=now()),count(*) FILTER (WHERE expires_at>now()) FROM ai_workload_tokens WHERE org_id=$1`, f.org).Scan(&expiredTokens, &liveTokens); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE expires_at<=now()),count(*) FILTER (WHERE expires_at>now()) FROM ai_workload_assertions WHERE instance_id=$1`, renewed.receipt.InstanceId).Scan(&expiredProofs, &liveProofs); err != nil {
				t.Fatal(err)
			}
			return expiredTokens, liveTokens, expiredProofs, liveProofs
		}
		expiredTokens, liveTokens, expiredProofs, liveProofs := counts()
		if expiredTokens != 7 || expiredProofs != 7 || liveTokens == 0 || liveProofs == 0 {
			t.Fatal("cleanup fixture does not contain both expired and live authority")
		}
		if err := f.workloads.Maintain(ctx, 3); err != nil {
			t.Fatal(err)
		}
		a, b, c, d := counts()
		if a != 4 || c != 4 || b != liveTokens || d != liveProofs {
			t.Fatalf("cleanup exceeded batch or removed live authority: expired tokens=%d proofs=%d; live tokens=%d proofs=%d", a, c, b, d)
		}
		f.admitted(renewedToken, "openrouter/a", renewed)
	})

	t.Run("provider_edits_respect_active_workload_references", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		r := f.enroll(f.key(true, 0))
		token := f.token(r)
		connection := f.workload.Models[0].ConnectionId
		provider, err := scanProvider(pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2`, f.org, connection))
		if err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		legacy := f.mint()
		for _, change := range []ProviderInput{
			{Name: provider.Name, Provider: provider.Provider, Enabled: true, Models: []string{"openrouter/b"}},
			{Name: provider.Name, Provider: provider.Provider, Enabled: true, Models: slices.Clone(provider.Models), ModelModes: map[string]ModelMode{"openrouter/a": ModeEmbedding}},
		} {
			if _, err := f.policies.UpdateProvider(ctx, f.org, f.owner, connection, change, provider.Revision); usageStatus(err) != 409 {
				t.Fatalf("active workload model removed or mode changed: %v", err)
			}
			f.admitted(token, "openrouter/a", r)
		}
		if err := f.policies.DeleteProvider(ctx, f.org, f.owner, connection, provider.Revision); usageStatus(err) != 409 {
			t.Fatalf("active workload provider deleted: %v", err)
		}
		unchanged, err := scanProvider(pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2`, f.org, connection))
		if err != nil || unchanged.Revision != provider.Revision || !slices.Equal(unchanged.Models, provider.Models) || unchanged.ModelModes["openrouter/a"] != ModeChat {
			t.Fatalf("refused edits mutated provider state: %v", err)
		}
		f.update(false, f.workload.Models, "revoked")
		provider, err = f.policies.UpdateProvider(ctx, f.org, f.owner, connection, ProviderInput{
			Name: provider.Name, Provider: provider.Provider, Enabled: true, Models: []string{"openrouter/b"},
		}, provider.Revision)
		if err != nil || provider.Status != "applied" {
			t.Fatalf("disabled workload blocked provider update: %v", err)
		}
		if err := f.policies.DeleteProvider(ctx, f.org, f.owner, connection, provider.Revision); err != nil {
			t.Fatalf("disabled workload blocked provider deletion: %v", err)
		}
		if _, err := f.service.Authorize(ctx, legacy.Token, "openrouter/a"); err != nil {
			t.Fatalf("workload provider changes broke independent legacy model access: %v", err)
		}
	})

	t.Run("retained_usage_is_stable_across_replicas_policy_changes_and_disable", func(t *testing.T) {
		threshold := 1.0
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, &threshold)
		f.reconcile()
		legacyNative, _ := f.binding(f.team)
		var native string
		if err := pool.QueryRow(ctx, `SELECT native_key_id FROM ai_workloads WHERE org_id=$1 AND id=$2`, f.org, f.workload.Id).Scan(&native); err != nil || native == "" || native == legacyNative {
			t.Fatalf("workload and legacy billing identities were not separate: %v", err)
		}
		ids := func(team, device *uuid.UUID) []string {
			t.Helper()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackAI(tx)
			out, err := bindingUsageIDs(ctx, tx, f.org, team, device)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		before := ids(nil, nil)
		expected := []string{legacyNative, native}
		slices.Sort(expected)
		if !slices.Equal(before, expected) {
			t.Fatal("organization usage omitted workload or legacy attribution")
		}
		key := f.key(true, 0)
		var first, last workloadLifecycleReplica
		for i := 0; i < 20; i++ {
			r := f.enroll(key)
			if i == 0 {
				first = r
			}
			last = r
		}
		if !slices.Equal(ids(nil, nil), before) || !slices.Equal(ids(&f.team, nil), []string{legacyNative}) || !slices.Equal(ids(nil, &f.device), []string{legacyNative}) {
			t.Fatal("replicas multiplied usage identities or polluted legacy filters")
		}
		engine := &workloadLifecycleUsage{providerFixtureEngine: f.provider, native: native, cost: .75}
		f.policies.engine = engine
		firstToken, lastToken := f.token(first), f.token(last)
		f.admitted(firstToken, "openrouter/a", first)
		f.admitted(lastToken, "openrouter/a", last)
		f.update(true, f.workload.Models, "applied")
		if !slices.Equal(ids(nil, nil), before) {
			t.Fatal("policy revision reset retained billing identity")
		}
		engine.mu.Lock()
		engine.cost = 1
		engine.mu.Unlock()
		for _, token := range []string{firstToken, lastToken} {
			_, err := f.workloads.Authorize(ctx, token, "openrouter/a")
			requireDailyThreshold(t, err)
		}
		engine.mu.Lock()
		badScope := engine.badScope
		engine.mu.Unlock()
		if badScope {
			t.Fatal("threshold mixed workload costs with legacy billing")
		}
		f.update(false, f.workload.Models, "revoked")
		if !slices.Equal(ids(nil, nil), before) || !slices.Equal(ids(&f.team, nil), []string{legacyNative}) {
			t.Fatal("disabled workload disappeared from historical usage or changed legacy scope")
		}
	})

	t.Run("video_jobs_are_owned_by_workload_across_replacement_instances", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/b"}, nil)
		connection := f.workload.Models[0].ConnectionId
		provider, err := scanProvider(pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2`, f.org, connection))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.policies.UpdateProvider(ctx, f.org, f.owner, connection, ProviderInput{
			Name: provider.Name, Provider: provider.Provider, Enabled: true, Models: provider.Models, ModelModes: map[string]ModelMode{"openrouter/a": ModeVideoGeneration},
		}, provider.Revision); err != nil {
			t.Fatal(err)
		}
		f.update(true, []api.AIWorkloadModel{{ConnectionId: connection, Model: "openrouter/a", Mode: "video_generation"}}, "applied")
		key := f.key(true, 0)
		a, b := f.enroll(key), f.enroll(key)
		ta, tb := f.token(a), f.token(b)
		ga, gb := f.admitted(ta, "openrouter/a", a), f.admitted(tb, "openrouter/a", b)
		store := videoStore{pool}
		body := []byte(`{"model":"openrouter/a","prompt":"fixture"}`)
		job, fresh, err := store.reserve(ctx, ga, "openrouter/a", "workload-video-request-01", body)
		if err != nil || !fresh || job.SubjectKind != "workload" || job.Agent != f.workload.Id {
			t.Fatalf("workload video reservation failed: %v", err)
		}
		retry, fresh, err := store.reserve(ctx, gb, "openrouter/a", "workload-video-request-01", body)
		if err != nil || fresh || retry.ID != job.ID {
			t.Fatalf("replacement instance lost workload idempotency: %v", err)
		}
		if _, _, err := store.reserve(ctx, gb, "openrouter/a", "workload-video-request-01", []byte(`{"different":true}`)); !errors.Is(err, errVideoConflict) {
			t.Fatalf("changed video request reused reserved handle: %v", err)
		}
		var exclusiveWorkload, syntheticIdentity bool
		if err := pool.QueryRow(ctx, `SELECT workload_id=$2 AND device_id IS NULL AND user_id IS NULL FROM ai_video_jobs WHERE id=$1`, job.ID, f.workload.Id).Scan(&exclusiveWorkload); err != nil || !exclusiveWorkload {
			t.Fatalf("video ownership used human or device fields: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=ANY($1::uuid[])) OR EXISTS(SELECT 1 FROM devices WHERE id=ANY($1::uuid[]))`, []uuid.UUID{f.workload.Id, a.receipt.InstanceId, b.receipt.InstanceId}).Scan(&syntheticIdentity); err != nil || syntheticIdentity {
			t.Fatalf("workload created synthetic human/device identity: %v", err)
		}
		foreignWorkload, err := f.workloads.Put(ctx, f.org, f.owner, uuid.Nil, api.AIWorkloadInput{Name: "production/other-bot", Enabled: true, Models: f.workload.Models})
		if err != nil || foreignWorkload.Status != "applied" {
			t.Fatalf("foreign workload fixture: %v", err)
		}
		foreign := *f
		foreign.workload = foreignWorkload
		otherReplica := foreign.enroll(foreign.key(true, 0))
		otherToken := foreign.token(otherReplica)
		otherGrant := foreign.admitted(otherToken, "openrouter/a", otherReplica)
		otherJob, fresh, err := store.reserve(ctx, otherGrant, "openrouter/a", "workload-video-request-01", body)
		if err != nil || !fresh || otherJob.ID == job.ID {
			t.Fatalf("idempotency leaked across workloads: %v", err)
		}
		for _, forged := range []videoJob{
			{ID: job.ID, Org: job.Org, Agent: foreignWorkload.Id, SubjectKind: "workload"},
			{ID: job.ID, Org: job.Org, Agent: job.Agent, SubjectKind: "user"},
			{ID: job.ID, Org: job.Org, Agent: job.Agent, SubjectKind: ""},
		} {
			if err := store.update(ctx, forged, "fixture:openrouter", "completed"); err == nil {
				t.Fatal("foreign workload or subject kind updated video job")
			}
		}
		if err := store.update(ctx, job, "fixture:openrouter", "queued"); err != nil {
			t.Fatal(err)
		}
		var arrivals atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			arrivals.Add(1)
			if r.Method != http.MethodGet || r.URL.Path != "/v1/videos/fixture:openrouter" || r.Header.Get("X-Bf-Vk") != ga.VirtualKey {
				t.Error("video retrieval used wrong upstream or native identity")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"fixture:openrouter","status":"completed"}`)
		}))
		defer upstream.Close()
		adapter, err := NewAdapter(upstream.URL, f.workloads.Authorize)
		if err != nil {
			t.Fatal(err)
		}
		adapter.ConfigureVideoStore(pool)
		server := httptest.NewServer(adapter.video)
		defer server.Close()
		get := func(token string) (int, []byte) {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/videos/"+job.ID.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			return response.StatusCode, raw
		}
		if code, _ := get(otherToken); code != 404 || arrivals.Load() != 0 {
			t.Fatalf("foreign workload reached reserved video: status=%d arrivals=%d", code, arrivals.Load())
		}
		code, raw := get(tb)
		var public struct{ ID, Status string }
		if code != 200 || json.Unmarshal(raw, &public) != nil || public.ID != job.ID.String() || public.Status != "completed" || arrivals.Load() != 1 {
			t.Fatalf("replacement instance could not retrieve workload job: status=%d arrivals=%d", code, arrivals.Load())
		}
		loaded, err := store.lookup(ctx, job.ID)
		if err != nil || loaded.SubjectKind != "workload" || loaded.Agent != f.workload.Id || loaded.State != "completed" {
			t.Fatalf("retrieval lost workload ownership: %v", err)
		}
	})
}

func TestWorkloadMergedProviderScopes(t *testing.T) {
	in := []EngineProviderScope{
		{Provider: "openrouter", Models: []string{"b", "a"}, KeyIDs: []string{"owned-key-b"}},
		{Provider: "openai", Models: []string{"other"}, KeyIDs: []string{"owned-key-openai"}},
		{Provider: "openrouter", Models: []string{"c", "b"}, KeyIDs: []string{"owned-key-a", "owned-key-b"}},
		{Provider: "openrouter", Models: []string{"a"}, KeyIDs: []string{"owned-key-a"}},
	}
	merged := mergeWorkloadScopes(in)
	want := []EngineProviderScope{
		{Provider: "openai", Models: []string{"other"}, KeyIDs: []string{"owned-key-openai"}},
		{Provider: "openrouter", Models: []string{"a", "b", "c"}, KeyIDs: []string{"owned-key-a", "owned-key-b"}},
	}
	if !validEngineScopes(merged) || !reflect.DeepEqual(merged, want) {
		t.Fatalf("multi-model scopes did not merge/deduplicate owned provider credentials: %#v", merged)
	}
	if !reflect.DeepEqual(mergeWorkloadScopes(merged), want) {
		t.Fatal("scope merging was not idempotent")
	}
	if validEngineScopes(mergeWorkloadScopes([]EngineProviderScope{
		{Provider: "openrouter", Models: []string{"a"}, KeyIDs: []string{"shared-key"}},
		{Provider: "openai", Models: []string{"a"}, KeyIDs: []string{"shared-key"}},
	})) {
		t.Fatal("same key identity was accepted across different providers")
	}
}
