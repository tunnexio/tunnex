package aigateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

const workloadLifecycleBase = "https://gateway.example"

type workloadLifecycleFixture struct {
	*policyFixture
	workloads *Workloads
	provider  *providerFixtureEngine
	workload  api.AIWorkload
}

type workloadLifecycleReplica struct {
	private ed25519.PrivateKey
	input   api.AIWorkloadEnrollInput
	receipt api.AIWorkloadReceipt
}

func newWorkloadLifecycleFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, models []string, threshold *float64) *workloadLifecycleFixture {
	t.Helper()
	f := &workloadLifecycleFixture{policyFixture: newPolicyFixture(t, ctx, pool), provider: newProviderFixtureEngine()}
	f.policies.engine = f.provider
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	provider, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{
		Provider: "openrouter", Name: "Workload provider", Models: []string{"openrouter/a", "openrouter/b"}, Secret: &secret, Enabled: true,
	})
	if err != nil || provider.Status != "applied" {
		t.Fatalf("create provider: status=%s err=%v", provider.Status, err)
	}
	f.workloads, err = NewWorkloads(f.policies, workloadLifecycleBase)
	if err != nil {
		t.Fatal(err)
	}
	grants := make([]api.AIWorkloadModel, len(models))
	for i, model := range models {
		grants[i] = api.AIWorkloadModel{ConnectionId: provider.ID, Model: model, Mode: "chat"}
	}
	before := f.nativeKeys()
	f.workload, err = f.workloads.Put(ctx, f.org, f.owner, uuid.Nil, api.AIWorkloadInput{
		Name: "production/support-bot", Enabled: true, Models: grants, DailyUsdThreshold: threshold,
	})
	if err != nil || f.workload.Status != "applied" || f.workload.AppliedRevision != f.workload.Revision {
		t.Fatalf("create workload: status=%s err=%v", f.workload.Status, err)
	}
	if f.nativeKeys() != before+1 {
		t.Fatal("workload creation did not allocate exactly one native accounting key")
	}
	return f
}

func (f *workloadLifecycleFixture) nativeKeys() int {
	f.provider.policyEngineFixture.mu.Lock()
	defer f.provider.policyEngineFixture.mu.Unlock()
	return len(f.provider.keys)
}

func (f *workloadLifecycleFixture) key(reusable bool, maxUses int64) api.AIWorkloadKeySecret {
	f.t.Helper()
	key, err := f.workloads.CreateKey(f.ctx, f.org, f.owner, f.workload.Id, api.AIWorkloadKeyInput{
		Name: "deployment-key", Reusable: reusable, MaxUses: maxUses, Ephemeral: true, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return key
}

func workloadLifecycleAssertion(t *testing.T, private ed25519.PrivateKey, audience, subject, id string, extras map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": subject, "sub": subject, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": id}
	for name, value := range extras {
		claims[name] = value
	}
	return signWorkloadTestProof(t, private, `{"alg":"EdDSA","typ":"JWT"}`, marshalWorkloadTestClaims(t, claims))
}

func workloadLifecycleJoin(t *testing.T, secret string, request uuid.UUID) workloadLifecycleReplica {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(secret))
	input := api.AIWorkloadEnrollInput{EnrollmentKey: secret, PublicKey: base64.RawURLEncoding.EncodeToString(public), RequestId: request}
	input.Proof = workloadLifecycleAssertion(t, private, workloadLifecycleBase+"/api/v1/workload/enroll", "enrollment", uuid.NewString(), map[string]any{
		"request_id": request.String(), "enrollment_hash": hex.EncodeToString(hash[:]),
	})
	return workloadLifecycleReplica{private: private, input: input}
}

func (f *workloadLifecycleFixture) enroll(key api.AIWorkloadKeySecret) workloadLifecycleReplica {
	f.t.Helper()
	r := workloadLifecycleJoin(f.t, key.Secret, uuid.New())
	var err error
	r.receipt, err = f.workloads.Enroll(f.ctx, r.input)
	if err != nil || r.receipt.OrganizationId != f.org || r.receipt.WorkloadId != f.workload.Id ||
		r.receipt.InstanceId == uuid.Nil || r.receipt.KeyGeneration != 1 || r.receipt.TokenEndpoint != workloadLifecycleBase+"/api/v1/workload/token" ||
		r.receipt.GatewayBase != workloadLifecycleBase+"/ai/v1" {
		f.t.Fatalf("enrollment receipt invalid: %v", err)
	}
	return r
}

func workloadLifecycleTokenInput(t *testing.T, r workloadLifecycleReplica) api.AIWorkloadTokenInput {
	t.Helper()
	return api.AIWorkloadTokenInput{
		ClientId: r.receipt.InstanceId, GrantType: "client_credentials", ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientAssertion: workloadLifecycleAssertion(t, r.private, workloadLifecycleBase+"/api/v1/workload/token", r.receipt.InstanceId.String(), uuid.NewString(), nil),
	}
}

func (f *workloadLifecycleFixture) token(r workloadLifecycleReplica) string {
	f.t.Helper()
	token, err := f.workloads.Token(f.ctx, workloadLifecycleTokenInput(f.t, r))
	if err != nil || token.AccessToken == "" || token.TokenType != "Bearer" || token.ExpiresIn != 300 || token.Scope != "tunnex-ai" {
		f.t.Fatalf("token exchange invalid: %v", err)
	}
	return token.AccessToken
}

func (f *workloadLifecycleFixture) admitted(token, model string, r workloadLifecycleReplica) Grant {
	f.t.Helper()
	grant, err := f.workloads.Authorize(f.ctx, token, model)
	if err != nil || grant.Tenant != f.org.String() || grant.Agent != f.workload.Id.String() || grant.Instance != r.receipt.InstanceId.String() ||
		grant.SubjectKind != "workload" || grant.VirtualKey == "" {
		f.t.Fatalf("workload admission invalid: %v", err)
	}
	return grant
}

func (f *workloadLifecycleFixture) rejected(token, model string, status int) {
	f.t.Helper()
	if _, err := f.workloads.Authorize(f.ctx, token, model); usageStatus(err) != status {
		f.t.Fatalf("admission status=%d, want %d: %v", usageStatus(err), status, err)
	}
}

func (f *workloadLifecycleFixture) update(enabled bool, models []api.AIWorkloadModel, status string) {
	f.t.Helper()
	w, err := f.workloads.Put(f.ctx, f.org, f.owner, f.workload.Id, api.AIWorkloadInput{
		Name: f.workload.Name, ExpectedRevision: f.workload.Revision, Enabled: enabled, Models: models, DailyUsdThreshold: f.workload.DailyUsdThreshold,
	})
	if err != nil || string(w.Status) != status || w.Revision != f.workload.Revision+1 {
		f.t.Fatalf("update status=%s, want %s: %v", w.Status, status, err)
	}
	f.workload = w
}

type workloadLifecycleUsage struct {
	*providerFixtureEngine
	mu       sync.Mutex
	native   string
	cost     float64
	observed int
	badScope bool
}

func (e *workloadLifecycleUsage) Usage(_ context.Context, ids []string, from, to time.Time) (Usage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observed++
	day := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	if len(ids) != 1 || ids[0] != e.native || !from.Equal(day) || to.Location() != time.UTC {
		e.badScope = true
	}
	return Usage{TotalCost: e.cost}, nil
}

func TestWorkloadLifecyclePostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	t.Run("twenty_replicas_share_one_policy_and_native_binding", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(true, 20)
		before := f.nativeKeys()
		instances, keys := map[uuid.UUID]bool{}, map[string]bool{}
		var first workloadLifecycleReplica
		var virtual string
		for i := 0; i < 20; i++ {
			r := f.enroll(key)
			if instances[r.receipt.InstanceId] || keys[r.input.PublicKey] {
				t.Fatal("replicas shared instance identity or public key")
			}
			instances[r.receipt.InstanceId], keys[r.input.PublicKey] = true, true
			token := f.token(r)
			grant := f.admitted(token, "openrouter/a", r)
			if i == 0 {
				first, virtual = r, grant.VirtualKey
			} else if grant.VirtualKey != virtual {
				t.Fatal("replica created a separate native billing identity")
			}
			models, err := f.workloads.Models(ctx, token)
			if err != nil || len(models) != 1 || models[0].Model != "openrouter/a" || models[0].Mode != ModeChat {
				t.Fatalf("model list exceeded current policy: %v", err)
			}
			f.rejected(token, "openrouter/b", 403)
		}
		if f.nativeKeys() != before {
			t.Fatal("enrollment multiplied native keys")
		}
		retry, err := f.workloads.Enroll(ctx, first.input)
		if err != nil || retry != first.receipt {
			t.Fatalf("lost enrollment response was not idempotent after use exhaustion: %v", err)
		}
		changed := workloadLifecycleJoin(t, key.Secret, first.input.RequestId)
		if _, err := f.workloads.Enroll(ctx, changed.input); usageStatus(err) != 401 {
			t.Fatalf("request identity rebound to another public key: %v", err)
		}
		if _, err := f.workloads.Enroll(ctx, workloadLifecycleJoin(t, key.Secret, uuid.New()).input); usageStatus(err) != 401 {
			t.Fatalf("total enrollment limit exceeded: %v", err)
		}
		var uses, count, bindings int
		if err := pool.QueryRow(ctx, `SELECT uses FROM ai_workload_enrollment_keys WHERE org_id=$1 AND id=$2`, f.org, key.Key.Id).Scan(&uses); err != nil || uses != 20 {
			t.Fatalf("enrollment uses=%d, want 20: %v", uses, err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2`, f.org, f.workload.Id).Scan(&count); err != nil || count != 20 {
			t.Fatalf("instance count=%d, want 20: %v", count, err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(DISTINCT native_key_id) FROM ai_workloads WHERE org_id=$1 AND native_key_id<>''`, f.org).Scan(&bindings); err != nil || bindings != 1 {
			t.Fatalf("retained native binding count=%d, want 1: %v", bindings, err)
		}
	})

	t.Run("concurrent_single_use_redemption_and_shared_assertion_replay", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(false, 1)
		second, err := NewWorkloads(f.policies, workloadLifecycleBase)
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			r   workloadLifecycleReplica
			err error
		}
		results := make(chan result, 12)
		start := make(chan struct{})
		for i := 0; i < cap(results); i++ {
			r := workloadLifecycleJoin(t, key.Secret, uuid.New())
			service := f.workloads
			if i%2 != 0 {
				service = second
			}
			go func() {
				<-start
				receipt, enrollErr := service.Enroll(ctx, r.input)
				r.receipt = receipt
				results <- result{r, enrollErr}
			}()
		}
		close(start)
		var winner workloadLifecycleReplica
		accepted := 0
		for i := 0; i < cap(results); i++ {
			r := <-results
			if r.err == nil {
				accepted++
				winner = r.r
			} else if usageStatus(r.err) != 401 {
				t.Fatalf("concurrent enrollment failed for unrelated reason: %v", r.err)
			}
		}
		if accepted != 1 {
			t.Fatalf("single-use key accepted %d concurrent instances", accepted)
		}
		var uses int
		if err := pool.QueryRow(ctx, `SELECT uses FROM ai_workload_enrollment_keys WHERE org_id=$1 AND id=$2`, f.org, key.Key.Id).Scan(&uses); err != nil || uses != 1 {
			t.Fatalf("single-use accounting=%d: %v", uses, err)
		}
		input := workloadLifecycleTokenInput(t, winner)
		token, err := f.workloads.Token(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		f.admitted(token.AccessToken, "openrouter/a", winner)
		for _, service := range []*Workloads{f.workloads, second} {
			if _, err := service.Token(ctx, input); usageStatus(err) != 401 {
				t.Fatalf("assertion replay accepted across API instances: %v", err)
			}
		}
		input = workloadLifecycleTokenInput(t, winner)
		issuance := make(chan error, 2)
		for _, service := range []*Workloads{f.workloads, second} {
			go func() { _, err := service.Token(ctx, input); issuance <- err }()
		}
		accepted = 0
		for range 2 {
			err := <-issuance
			if err == nil {
				accepted++
			} else if usageStatus(err) != 401 {
				t.Fatalf("replay race unrelated failure: %v", err)
			}
		}
		if accepted != 1 {
			t.Fatalf("same concurrent assertion accepted %d times", accepted)
		}
	})

	t.Run("bootstrap_expiry_and_credential_boundaries", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(true, 0)
		r := f.enroll(key)
		f.exec(`UPDATE ai_workload_enrollment_keys SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND id=$2`, f.org, key.Key.Id)
		f.admitted(f.token(r), "openrouter/a", r)
		if _, err := f.workloads.Enroll(ctx, workloadLifecycleJoin(t, key.Secret, uuid.New()).input); usageStatus(err) != 401 {
			t.Fatalf("expired introduction permitted new enrollment: %v", err)
		}
		retry, err := f.workloads.Enroll(ctx, r.input)
		if err != nil || retry != r.receipt {
			t.Fatalf("expired bootstrap prevented receipt recovery: %v", err)
		}
		badAudience := workloadLifecycleTokenInput(t, r)
		badAudience.ClientAssertion = workloadLifecycleAssertion(t, r.private, "https://untrusted.example/token", r.receipt.InstanceId.String(), uuid.NewString(), nil)
		if _, err := f.workloads.Token(ctx, badAudience); usageStatus(err) != 401 {
			t.Fatalf("wrong assertion audience accepted: %v", err)
		}
		unregistered := workloadLifecycleJoin(t, key.Secret, uuid.New())
		unregistered.receipt = r.receipt
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, unregistered)); usageStatus(err) != 401 {
			t.Fatalf("unregistered signing key accepted: %v", err)
		}
		human, err := cliauth.NewService(pool, f.policies.sealer).MintForUser(ctx, f.owner)
		if err != nil {
			t.Fatal(err)
		}
		legacy := newAICredentialFixture(t, ctx, pool)
		legacy.enable()
		legacyToken := legacy.mint()
		if _, err := legacy.service.Authorize(ctx, legacyToken.Token, "openrouter/allowed"); err != nil {
			t.Fatalf("legacy control fixture itself is invalid: %v", err)
		}
		for _, credential := range []string{human.Token, legacy.raw, legacyToken.Token, key.Secret} {
			f.rejected(credential, "openrouter/a", 401)
			if _, err := f.workloads.Models(ctx, credential); usageStatus(err) != 401 {
				t.Fatalf("foreign credential read workload models: %v", err)
			}
		}
	})

	t.Run("individual_key_only_and_combined_revocation", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key, otherKey := f.key(true, 0), f.key(true, 0)
		a, b, c := f.enroll(key), f.enroll(key), f.enroll(otherKey)
		ta, tb, tc := f.token(a), f.token(b), f.token(c)
		if err := f.workloads.RevokeInstance(ctx, f.org, f.owner, f.workload.Id, a.receipt.InstanceId); err != nil {
			t.Fatal(err)
		}
		f.rejected(ta, "openrouter/a", 401)
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, a)); usageStatus(err) != 401 {
			t.Fatalf("revoked instance renewed: %v", err)
		}
		f.admitted(tb, "openrouter/a", b)
		if err := f.workloads.RevokeKey(ctx, f.org, f.owner, f.workload.Id, key.Key.Id, false); err != nil {
			t.Fatal(err)
		}
		if _, err := f.workloads.Enroll(ctx, workloadLifecycleJoin(t, key.Secret, uuid.New()).input); usageStatus(err) != 401 {
			t.Fatalf("revoked key admitted new instance: %v", err)
		}
		f.admitted(tb, "openrouter/a", b)
		tb = f.token(b)
		f.admitted(tb, "openrouter/a", b)
		if err := f.workloads.RevokeKey(ctx, f.org, f.owner, f.workload.Id, key.Key.Id, true); err != nil {
			t.Fatal(err)
		}
		f.rejected(tb, "openrouter/a", 401)
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, b)); usageStatus(err) != 401 {
			t.Fatalf("combined revocation retained descendant renewal: %v", err)
		}
		f.admitted(tc, "openrouter/a", c)
		f.admitted(f.token(c), "openrouter/a", c)
		if err := f.workloads.Retire(ctx, tc); err != nil {
			t.Fatal(err)
		}
		f.rejected(tc, "openrouter/a", 401)
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, c)); usageStatus(err) != 401 {
			t.Fatalf("retired instance renewed: %v", err)
		}
	})

	t.Run("disable_reenable_does_not_resurrect_old_authority", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(true, 0)
		a, b := f.enroll(key), f.enroll(key)
		ta, tb := f.token(a), f.token(b)
		models := slices.Clone(f.workload.Models)
		f.update(false, models, "revoked")
		for _, token := range []string{ta, tb} {
			f.rejected(token, "openrouter/a", 401)
		}
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, a)); usageStatus(err) != 401 {
			t.Fatalf("disabled workload issued token: %v", err)
		}
		if _, err := f.workloads.Enroll(ctx, workloadLifecycleJoin(t, key.Secret, uuid.New()).input); usageStatus(err) != 401 {
			t.Fatalf("disabled workload enrolled instance: %v", err)
		}
		f.update(true, models, "applied")
		for _, token := range []string{ta, tb} {
			f.rejected(token, "openrouter/a", 401)
		}
		if _, err := f.workloads.Enroll(ctx, workloadLifecycleJoin(t, key.Secret, uuid.New()).input); usageStatus(err) != 401 {
			t.Fatalf("reenabling resurrected revoked enrollment key: %v", err)
		}
		f.admitted(f.token(a), "openrouter/a", a)
		fresh := f.enroll(f.key(true, 0))
		f.admitted(f.token(fresh), "openrouter/a", fresh)
	})

	t.Run("policy_tightening_fails_closed_during_engine_outage", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a", "openrouter/b"}, nil)
		r := f.enroll(f.key(true, 0))
		token := f.token(r)
		f.admitted(token, "openrouter/b", r)
		models := []api.AIWorkloadModel{f.workload.Models[0]}
		if models[0].Model != "openrouter/a" {
			t.Fatal("fixture model order changed")
		}
		f.provider.policyEngineFixture.mu.Lock()
		f.provider.policyEngineFixture.fail = true
		f.provider.policyEngineFixture.mu.Unlock()
		f.update(true, models, "error")
		f.rejected(token, "openrouter/b", 403)
		f.rejected(token, "openrouter/a", 403)
		if f.workload.AppliedRevision == f.workload.Revision {
			t.Fatal("failed reconciliation marked desired policy applied")
		}
		f.provider.policyEngineFixture.mu.Lock()
		f.provider.policyEngineFixture.fail = false
		f.provider.policyEngineFixture.mu.Unlock()
		var err error
		f.workload, err = f.workloads.Reconcile(ctx, f.org, f.workload.Id)
		if err != nil || f.workload.Status != "applied" {
			t.Fatalf("recovery failed: %v", err)
		}
		f.admitted(token, "openrouter/a", r)
		f.rejected(token, "openrouter/b", 403)
		modelsAfter, err := f.workloads.Models(ctx, token)
		if err != nil || len(modelsAfter) != 1 || modelsAfter[0].Model != "openrouter/a" {
			t.Fatalf("tightened model list incorrect: %v", err)
		}
		if f.nativeKeys() != 1 {
			t.Fatal("policy tightening replaced native accounting identity")
		}
	})

	t.Run("rotation_retries_preserve_receipt_and_revoke_previous_generation", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		key := f.key(true, 0)
		r := f.enroll(key)
		oldToken := f.token(r)
		next := workloadLifecycleJoin(t, key.Secret, uuid.New())
		request := uuid.New()
		extras := map[string]any{"request_id": request.String(), "next_key": next.input.PublicKey}
		input := api.AIWorkloadRotationInput{
			InstanceId: r.receipt.InstanceId, RequestId: request, PublicKey: next.input.PublicKey,
			OldProof: workloadLifecycleAssertion(t, r.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras),
			NewProof: workloadLifecycleAssertion(t, next.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras),
		}
		receipt, err := f.workloads.Rotate(ctx, input)
		if err != nil || receipt.KeyGeneration != 2 || receipt.InstanceId != r.receipt.InstanceId {
			t.Fatalf("rotation failed: generation=%d err=%v", receipt.KeyGeneration, err)
		}
		retry, err := f.workloads.Rotate(ctx, input)
		if err != nil || retry != receipt {
			t.Fatalf("lost rotation response was not recoverable: %v", err)
		}
		input.OldProof = workloadLifecycleAssertion(t, r.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras)
		input.NewProof = workloadLifecycleAssertion(t, next.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras)
		if refreshed, err := f.workloads.Rotate(ctx, input); err != nil || refreshed != receipt {
			t.Fatalf("fresh proofs could not recover same rotation receipt: %v", err)
		}
		f.rejected(oldToken, "openrouter/a", 401)
		if _, err := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, r)); usageStatus(err) != 401 {
			t.Fatalf("superseded key issued token: %v", err)
		}
		if _, err := f.workloads.Enroll(ctx, r.input); usageStatus(err) != 401 {
			t.Fatalf("old enrollment receipt restored superseded key: %v", err)
		}
		next.receipt = receipt
		f.admitted(f.token(next), "openrouter/a", next)
		changed := workloadLifecycleJoin(t, key.Secret, uuid.New())
		input.PublicKey = changed.input.PublicKey
		if _, err := f.workloads.Rotate(ctx, input); usageStatus(err) != 401 {
			t.Fatalf("rotation request rebound to another candidate: %v", err)
		}
		if f.nativeKeys() != 1 {
			t.Fatal("signing-key rotation multiplied accounting keys")
		}
	})

	t.Run("daily_threshold_aggregates_all_instances_on_workload_binding", func(t *testing.T) {
		threshold := 1.0
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, &threshold)
		var native string
		if err := pool.QueryRow(ctx, `SELECT native_key_id FROM ai_workloads WHERE org_id=$1 AND id=$2`, f.org, f.workload.Id).Scan(&native); err != nil || native == "" {
			t.Fatalf("missing retained billing key: %v", err)
		}
		engine := &workloadLifecycleUsage{providerFixtureEngine: f.provider, native: native}
		f.policies.engine = engine
		key := f.key(true, 0)
		a, b := f.enroll(key), f.enroll(key)
		ta, tb := f.token(a), f.token(b)
		f.admitted(ta, "openrouter/a", a)
		engine.mu.Lock()
		engine.cost = .6
		engine.mu.Unlock()
		f.admitted(tb, "openrouter/a", b)
		engine.mu.Lock()
		engine.cost += .4
		engine.mu.Unlock()
		for _, token := range []string{ta, tb} {
			_, err := f.workloads.Authorize(ctx, token, "openrouter/a")
			requireDailyThreshold(t, err)
		}
		engine.mu.Lock()
		defer engine.mu.Unlock()
		if engine.observed != 4 || engine.badScope {
			t.Fatalf("admission used wrong workload accounting scope: observations=%d badScope=%v", engine.observed, engine.badScope)
		}
	})
}

func TestWorkloadAuthStorageRecoveryPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	// Use real PostgreSQL statement failures after BEGIN succeeds. Closing the
	// pool would exercise only the already-correct connection failure branch.
	config := pool.Config()
	config.ConnConfig.RuntimeParams["statement_timeout"] = "100ms"
	limited, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	if err = limited.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ operation, lock string }{
		{"enroll", "bootstrap_lookup"}, {"enroll", "bootstrap_lock"}, {"enroll", "workload"}, {"enroll", "organization"}, {"receipt_retry", "organization"},
		{"token", "instance_lookup"}, {"token", "instance_lock"}, {"token", "workload"}, {"token", "organization"},
		{"authorize", "bearer_lookup"}, {"authorize", "workload"}, {"authorize", "instance_lock"},
		{"authorize", "organization_lookup"}, {"authorize", "organization"}, {"authorize", "models"}, {"authorize", "provider"},
		{"models", "organization"}, {"models", "models"}, {"models_empty", "organization"},
		{"rotate", "instance_lock"}, {"rotate", "organization"},
		{"retire", "bearer_lookup"}, {"retire", "instance_lock"}, {"retire", "organization_lookup"},
	} {
		t.Run(test.operation+"/"+test.lock, func(t *testing.T) {
			f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
			key := f.key(true, 0)
			r := f.enroll(key)
			bearer := f.token(r)
			policies := *f.policies
			policies.pool = limited
			service, err := NewWorkloads(&policies, workloadLifecycleBase)
			if err != nil {
				t.Fatal(err)
			}
			join := workloadLifecycleJoin(t, key.Secret, uuid.New())
			tokenInput := workloadLifecycleTokenInput(t, r)
			next := workloadLifecycleJoin(t, key.Secret, uuid.New())
			request := uuid.New()
			extras := map[string]any{"request_id": request.String(), "next_key": next.input.PublicKey}
			rotation := api.AIWorkloadRotationInput{
				InstanceId: r.receipt.InstanceId, RequestId: request, PublicKey: next.input.PublicKey,
				OldProof: workloadLifecycleAssertion(t, r.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras),
				NewProof: workloadLifecycleAssertion(t, next.private, workloadLifecycleBase+"/api/v1/workload/rotate", r.receipt.InstanceId.String(), uuid.NewString(), extras),
			}
			invoke := func() error {
				switch test.operation {
				case "enroll":
					_, err := service.Enroll(ctx, join.input)
					return err
				case "receipt_retry":
					_, err := service.Enroll(ctx, r.input)
					return err
				case "token":
					_, err := service.Token(ctx, tokenInput)
					return err
				case "authorize":
					_, err := service.Authorize(ctx, bearer, "openrouter/a")
					return err
				case "models", "models_empty":
					_, err := service.Models(ctx, bearer)
					return err
				case "rotate":
					_, err := service.Rotate(ctx, rotation)
					return err
				default:
					return service.Retire(ctx, bearer)
				}
			}
			locks := map[string]struct {
				query string
				args  []any
			}{
				"bootstrap_lookup":    {`LOCK TABLE ai_workload_enrollment_keys IN ACCESS EXCLUSIVE MODE`, nil},
				"bootstrap_lock":      {`SELECT id FROM ai_workload_enrollment_keys WHERE org_id=$1 AND id=$2 FOR UPDATE`, []any{f.org, key.Key.Id}},
				"workload":            {`SELECT id FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, []any{f.org, f.workload.Id}},
				"instance_lookup":     {`LOCK TABLE ai_workload_instances IN ACCESS EXCLUSIVE MODE`, nil},
				"instance_lock":       {`SELECT id FROM ai_workload_instances WHERE org_id=$1 AND id=$2 FOR UPDATE`, []any{f.org, r.receipt.InstanceId}},
				"bearer_lookup":       {`LOCK TABLE ai_workload_tokens IN ACCESS EXCLUSIVE MODE`, nil},
				"organization_lookup": {`LOCK TABLE organizations IN ACCESS EXCLUSIVE MODE`, nil},
				"organization":        {`SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, []any{f.org}},
				"models":              {`LOCK TABLE ai_workload_models IN ACCESS EXCLUSIVE MODE`, nil},
				"provider":            {`SELECT id FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR UPDATE`, []any{f.org, f.workload.Models[0].ConnectionId}},
			}
			if test.operation == "models_empty" {
				// Exercise Models' final organization check without resolve having
				// acquired that lock on behalf of a nonempty model list.
				f.update(true, nil, "applied")
			}
			blocker, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackAI(blocker)
			lock := locks[test.lock]
			if _, err = blocker.Exec(ctx, lock.query, lock.args...); err != nil {
				t.Fatal(err)
			}
			outage := invoke()
			if err = blocker.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if usageStatus(outage) != 503 {
				t.Fatalf("authorization storage failure status=%d, want retryable 503: %v", usageStatus(outage), outage)
			}
			var state string
			var generation, uses int64
			if err = pool.QueryRow(ctx, `SELECT state,key_generation FROM ai_workload_instances WHERE org_id=$1 AND id=$2`, f.org, r.receipt.InstanceId).Scan(&state, &generation); err != nil || state != "active" || generation != 1 {
				t.Fatalf("outage changed registered authority: state=%s generation=%d err=%v", state, generation, err)
			}
			if err = pool.QueryRow(ctx, `SELECT uses FROM ai_workload_enrollment_keys WHERE org_id=$1 AND id=$2`, f.org, key.Key.Id).Scan(&uses); err != nil || uses != 1 {
				t.Fatalf("outage consumed enrollment use: uses=%d err=%v", uses, err)
			}
			// Retry the exact operation and proofs after storage recovers. In
			// particular, rolled-back assertion inserts must not fence recovery.
			if err = invoke(); err != nil {
				t.Fatalf("same credentials did not recover after storage became available: %v", err)
			}
		})
	}

	t.Run("absent_credentials_keep_identical_refusal", func(t *testing.T) {
		f := newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil)
		missing := workloadLifecycleJoin(t, workloadEnrollmentPrefix+"absent", uuid.New())
		missing.receipt.InstanceId = uuid.New()
		_, enrollmentErr := f.workloads.Enroll(ctx, missing.input)
		_, tokenErr := f.workloads.Token(ctx, workloadLifecycleTokenInput(t, missing))
		_, authorizeErr := f.workloads.Authorize(ctx, workloadTokenPrefix+"absent", "openrouter/a")
		_, modelsErr := f.workloads.Models(ctx, workloadTokenPrefix+"absent")
		_, rotateErr := f.workloads.Rotate(ctx, api.AIWorkloadRotationInput{InstanceId: missing.receipt.InstanceId, RequestId: uuid.New(), PublicKey: missing.input.PublicKey})
		retireErr := f.workloads.Retire(ctx, workloadTokenPrefix+"absent")
		for _, err := range []error{enrollmentErr, tokenErr, authorizeErr, modelsErr, rotateErr, retireErr} {
			if usageStatus(err) != 401 || err.Error() != aiUnauthorized().Error() {
				t.Fatalf("missing credential disclosed lookup detail: %v", err)
			}
		}
	})
}
