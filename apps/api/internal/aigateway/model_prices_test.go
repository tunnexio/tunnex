package aigateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// priceEngine adds an in-memory pricing-override store and uncosted usage to
// the provider fixture engine.
type priceEngine struct {
	*providerFixtureEngine
	pmu       sync.Mutex
	overrides map[string]EnginePriceOverride
	next      int
	failWrite bool
	uncosted  int64
}

func newPriceEngine() *priceEngine {
	return &priceEngine{providerFixtureEngine: newProviderFixtureEngine(), overrides: map[string]EnginePriceOverride{}}
}
func (e *priceEngine) ListPriceOverrides(_ context.Context, key string) ([]EnginePriceOverride, error) {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	out := []EnginePriceOverride{}
	for _, o := range e.overrides {
		if o.ProviderKeyID == key {
			out = append(out, o)
		}
	}
	return out, nil
}
func (e *priceEngine) CreatePriceOverride(_ context.Context, o EnginePriceOverride) error {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	if e.failWrite || !validEnginePriceOverride(o) {
		return errors.New("engine refused")
	}
	e.next++
	o.ID = fmt.Sprintf("override-%d", e.next)
	e.overrides[o.ID] = o
	return nil
}
func (e *priceEngine) UpdatePriceOverride(_ context.Context, id string, o EnginePriceOverride) error {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	if e.failWrite || !validEnginePriceOverride(o) {
		return errors.New("engine refused")
	}
	o.ID = id
	e.overrides[id] = o
	return nil
}
func (e *priceEngine) DeletePriceOverride(_ context.Context, id string) error {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	if e.failWrite {
		return errors.New("engine refused")
	}
	delete(e.overrides, id)
	return nil
}
func (e *priceEngine) Usage(ctx context.Context, ids []string, from, to time.Time) (Usage, error) {
	u, err := e.providerFixtureEngine.Usage(ctx, ids, from, to)
	u.UncostedRequests = e.uncosted
	u.TotalRequests = e.uncosted
	return u, err
}
func (e *priceEngine) tunnexOverrides() []EnginePriceOverride {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	out := []EnginePriceOverride{}
	for _, o := range e.overrides {
		if strings.HasPrefix(o.Name, priceOverrideNamePrefix) {
			out = append(out, o)
		}
	}
	return out
}

type recordingPublisher struct {
	mu     sync.Mutex
	events []alerts.Event
}

func (p *recordingPublisher) Publish(_ context.Context, e alerts.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
	return nil
}
func (p *recordingPublisher) count(key alerts.EventKey) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.events {
		if e.Key == key {
			n++
		}
	}
	return n
}

type priceFixture struct {
	*policyFixture
	engine *priceEngine
	conn   ProviderConnection
	group  uuid.UUID
	user   uuid.UUID
}

func newPriceFixture(t *testing.T) (context.Context, *priceFixture) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newPriceEngine()
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	conn, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "OpenRouter", Models: []string{"openrouter/gemini-3.5-flash", "openrouter/text-embedding-9"}, ModelModes: map[string]ModelMode{"openrouter/text-embedding-9": ModeEmbedding}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, user := uuid.New(), uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, f.org)
	f.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Engineer',now())`, user, user.String()+"@test.local")
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, user)
	if g, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, conn.ID, "openrouter/gemini-3.5-flash", true, 0); err != nil || g.Status != "applied" {
		t.Fatalf("grant: %+v %v", g, err)
	}
	if _, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), 0); err != nil {
		t.Fatal(err)
	}
	engine.unpriced = true // a model the bundled catalog lacks
	return ctx, &priceFixture{policyFixture: f, engine: engine, conn: conn, group: group, user: user}
}

func TestModelPriceOverrideAdmissionAndEngineReconcile(t *testing.T) {
	ctx, f := newPriceFixture(t)
	const model = "openrouter/gemini-3.5-flash"
	_, err := f.policies.ResolveUserModel(ctx, f.org, f.user, model)
	requireAIError(t, err, 403, "ai_price_unavailable")

	// Validation and permissions of shape.
	for _, bad := range []struct {
		model         string
		input, output *float64
	}{
		{"no-provider-model", floatPtr(1e-7), floatPtr(1e-6)},
		{model, floatPtr(-1e-7), floatPtr(1e-6)},
		{model, floatPtr(0.02), floatPtr(1e-6)},
		{model, nil, floatPtr(1e-6)},
		{model, floatPtr(1e-7), nil}, // chat needs an output price
	} {
		_, err := f.policies.PutModelPrice(ctx, f.org, f.owner, bad.model, bad.input, bad.output, 0)
		requireAIError(t, err, 400, "invalid_model_price")
	}
	// An embedding model needs only an input price.
	if p, err := f.policies.PutModelPrice(ctx, f.org, f.owner, "openrouter/text-embedding-9", floatPtr(1e-8), nil, 0); err != nil || p.Status != "applied" {
		t.Fatalf("embedding price: %+v %v", p, err)
	}

	// The engine refuses: the price stays pending and admission ignores it.
	f.engine.failWrite = true
	p, err := f.policies.PutModelPrice(ctx, f.org, f.owner, model, floatPtr(3e-7), floatPtr(2.5e-6), 0)
	if err != nil || p.Status != "error" || p.AppliedRevision == p.Revision {
		t.Fatalf("unapplied price reported applied: %+v %v", p, err)
	}
	_, err = f.policies.ResolveUserModel(ctx, f.org, f.user, model)
	requireAIError(t, err, 403, "ai_price_unavailable")

	// The leader's pass applies it; admission now uses the operator price.
	f.engine.failWrite = false
	if n, err := f.policies.ReconcileAllModelPrices(ctx, 10); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, f.user, model); err != nil {
		t.Fatalf("priced model refused: %v", err)
	}
	overrides := f.engine.tunnexOverrides()
	if len(overrides) != 2 {
		t.Fatalf("want 2 engine overrides, got %+v", overrides)
	}
	var chat EnginePriceOverride
	for _, o := range overrides {
		if o.Pattern == "gemini-3.5-flash" {
			chat = o
		}
	}
	if chat.ProviderKeyID != f.conn.KeyID || chat.Input == nil || *chat.Input != 3e-7 || chat.Output == nil || *chat.Output != 2.5e-6 || chat.RequestTypes[0] != "chat_completion" {
		t.Fatalf("engine override not scoped to the connection key: %+v", chat)
	}

	// A stale editor conflicts; an edit converges the engine.
	_, err = f.policies.PutModelPrice(ctx, f.org, f.owner, model, floatPtr(4e-7), floatPtr(3e-6), 0)
	requireAIError(t, err, 409, "ai_model_price_revision_conflict")
	p, err = f.policies.PutModelPrice(ctx, f.org, f.owner, model, floatPtr(4e-7), floatPtr(3e-6), p.Revision)
	if err != nil || p.Status != "applied" {
		t.Fatalf("edit: %+v %v", p, err)
	}
	if got := f.engine.tunnexOverrides(); len(got) != 2 {
		t.Fatalf("edit duplicated an engine override: %+v", got)
	}

	// Effective prices name their source.
	prices, effective, err := f.policies.ListModelPrices(ctx, f.org, []string{model, "openrouter/unknown-model"})
	if err != nil || len(prices) != 2 || effective[0].Source != ModelPriceSourceCustom || *effective[0].InputCostPerToken != 4e-7 || effective[1].Source != ModelPriceSourceNone {
		t.Fatalf("effective prices: %+v %+v %v", prices, effective, err)
	}

	// Another tool's override on the same key is never touched.
	f.engine.pmu.Lock()
	f.engine.overrides["foreign"] = EnginePriceOverride{ID: "foreign", Name: "operator-own", ProviderKeyID: f.conn.KeyID, Pattern: "x"}
	f.engine.pmu.Unlock()

	// Removing the price deletes Tunnex's override and blocks again.
	_, err = f.policies.RemoveModelPrice(ctx, f.org, f.owner, model, p.Revision)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.policies.ResolveUserModel(ctx, f.org, f.user, model)
	requireAIError(t, err, 403, "ai_price_unavailable")
	// A removed price can be set again from "no live price" (expected 0).
	again, err := f.policies.PutModelPrice(ctx, f.org, f.owner, model, floatPtr(1e-7), floatPtr(1e-6), 0)
	if err != nil || again.Status != "applied" || again.Revision != p.Revision+2 {
		t.Fatalf("set again: %+v %v", again, err)
	}
	if _, err = f.policies.RemoveModelPrice(ctx, f.org, f.owner, model, again.Revision); err != nil {
		t.Fatal(err)
	}
	if got := f.engine.tunnexOverrides(); len(got) != 1 || got[0].Pattern != "text-embedding-9" {
		t.Fatalf("removed price left on the engine: %+v", got)
	}
	f.engine.pmu.Lock()
	_, foreign := f.engine.overrides["foreign"]
	f.engine.pmu.Unlock()
	if !foreign {
		t.Fatal("a non-Tunnex override was deleted")
	}

	var audits int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action IN ('ai_model_price.changed','ai_model_price.removed')`, f.org).Scan(&audits); err != nil || audits != 6 {
		t.Fatalf("want 6 price audit entries, got %d %v", audits, err)
	}
}

func TestUnknownPricePolicy(t *testing.T) {
	ctx, f := newPriceFixture(t)
	const model = "openrouter/gemini-3.5-flash"
	publisher := &recordingPublisher{}
	f.policies.SetAlertPublisher(publisher)

	// Block (default) fails closed on uncosted usage even for a priced model.
	f.engine.unpriced = false
	f.engine.uncosted = 1
	_, err := f.policies.ResolveUserModel(ctx, f.org, f.user, model)
	requireAIError(t, err, 503, "ai_gateway_unavailable")
	f.engine.unpriced = true

	_, err = f.policies.PutCostSettings(ctx, f.org, f.owner, "warn", 30, 0)
	requireAIError(t, err, 400, "invalid_ai_cost_settings")
	settings, err := f.policies.PutCostSettings(ctx, f.org, f.owner, UnknownPriceAllowAndAlert, 30, 0)
	if err != nil || settings.Revision != 1 {
		t.Fatalf("settings: %+v %v", settings, err)
	}
	_, err = f.policies.PutCostSettings(ctx, f.org, f.owner, UnknownPriceBlock, 30, 0)
	requireAIError(t, err, 409, "ai_cost_settings_revision_conflict")

	// Allow and alert: admitted despite unknown price and uncosted usage; one alert a day.
	for i := 0; i < 3; i++ {
		if _, err := f.policies.ResolveUserModel(ctx, f.org, f.user, model); err != nil {
			t.Fatalf("allowed unknown price refused: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for publisher.count(alerts.EventAIPriceUnknown) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := publisher.count(alerts.EventAIPriceUnknown); n != 1 {
		t.Fatalf("want one unknown-price alert, got %d", n)
	}
	publisher.mu.Lock()
	event := publisher.events[0]
	publisher.mu.Unlock()
	if event.Fields["subject_kind"] != "user_group" || event.Fields["subject_name"] != "Engineering" || event.Fields["model"] != model {
		t.Fatalf("alert fields: %+v", event.Fields)
	}

	// The limit still applies to the costed spend.
	f.engine.usage = 5
	_, err = f.policies.ResolveUserModel(ctx, f.org, f.user, model)
	requireDailyThreshold(t, err)

	got, err := f.policies.CostSettings(ctx, f.org)
	if err != nil || got.UnknownPricePolicy != UnknownPriceAllowAndAlert || got.RequestLogRetentionDays != 30 {
		t.Fatalf("read settings: %+v %v", got, err)
	}
}

// The engine wire: provider-key scope only, exact match, read-back parsing.
func TestEnginePriceOverrideWire(t *testing.T) {
	key := "tnx-managed-" + uuid.NewString()
	var created enginePricingOverrideBody
	engine, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/governance/pricing-overrides":
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &created) != nil {
				t.Error("invalid create body")
			}
			w.WriteHeader(http.StatusCreated)
			writeEngineJSON(w, map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/governance/pricing-overrides":
			if r.URL.Query().Get("provider_key_id") != key {
				t.Error("list not filtered by provider key")
			}
			writeEngineJSON(w, map[string]any{"pricing_overrides": []any{
				map[string]any{"id": "abc-1", "name": "tnx-price-0123456789abcdef01234567", "scope_kind": "provider_key", "provider_key_id": key, "match_type": "exact", "pattern": "gemini-3.5-flash", "request_types": []string{"chat_completion"}, "pricing_patch": `{"input_cost_per_token":3e-7,"output_cost_per_token":2.5e-6}`},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	desired := EnginePriceOverride{Name: "tnx-price-0123456789abcdef01234567", ProviderKeyID: key, Pattern: "gemini-3.5-flash", RequestTypes: []string{"chat_completion"}, Input: floatPtr(3e-7), Output: floatPtr(2.5e-6)}
	if err := engine.CreatePriceOverride(ctx, desired); err != nil {
		t.Fatal(err)
	}
	if created.ScopeKind != "provider_key" || created.MatchType != "exact" || created.ProviderKeyID != key || *created.Patch.InputCostPerToken != 3e-7 {
		t.Fatalf("create body: %+v", created)
	}
	list, err := engine.ListPriceOverrides(ctx, key)
	if err != nil || len(list) != 1 || *list[0].Output != 2.5e-6 || list[0].ID != "abc-1" {
		t.Fatalf("list: %+v %v", list, err)
	}
	// Never a global or foreign-key scope, never a wildcard, never above the bound.
	for _, bad := range []EnginePriceOverride{
		{Name: desired.Name, ProviderKeyID: "", Pattern: desired.Pattern, RequestTypes: desired.RequestTypes, Input: desired.Input},
		{Name: desired.Name, ProviderKeyID: "configured-provider-key", Pattern: desired.Pattern, RequestTypes: desired.RequestTypes, Input: desired.Input},
		{Name: desired.Name, ProviderKeyID: key, Pattern: "gemini-*", RequestTypes: desired.RequestTypes, Input: desired.Input},
		{Name: desired.Name, ProviderKeyID: key, Pattern: desired.Pattern, RequestTypes: desired.RequestTypes, Input: floatPtr(1)},
		{Name: "someone-else", ProviderKeyID: key, Pattern: desired.Pattern, RequestTypes: desired.RequestTypes, Input: desired.Input},
	} {
		if engine.CreatePriceOverride(ctx, bad) == nil {
			t.Fatalf("unsafe override accepted: %+v", bad)
		}
	}
	if _, err := engine.ListPriceOverrides(ctx, "configured-provider-key"); err == nil {
		t.Fatal("listed a key that is not Tunnex-managed")
	}
}
