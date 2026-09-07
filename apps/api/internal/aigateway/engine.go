package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Engine is the private, pinned Bifrost administration boundary. Its credentials
// and returned EngineKey.Value must never be serialized to a customer response.
type Engine struct {
	base           *url.URL
	user, password string
	client         *http.Client
}
type EngineKey struct {
	ID    string
	Value string `json:"-"`
}
type Price struct {
	Known                                 bool
	InputCostPerToken, OutputCostPerToken *float64
}
type Usage struct {
	TotalRequests    int64   `json:"total_requests"`
	TotalTokens      int64   `json:"total_tokens"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalCost        float64 `json:"total_cost"`
	UncostedRequests int64   `json:"uncosted_requests"`
}

var errEngine = errors.New("AI engine operation failed")
var errEngineScope = errors.New("AI engine policy readback mismatch")
var engineIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$`)
var engineModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$`)

// NewEngine accepts plaintext only on a numeric loopback address or the explicit
// private installer service name bifrost. All other destinations require TLS.
// Environment proxy variables and redirects are intentionally not used.
func NewEngine(baseURL, user, password string) (*Engine, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || user == "" || password == "" || strings.ContainsAny(user, ":\r\n") || strings.ContainsAny(password, "\r\n") {
		return nil, errEngine
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "bifrost" || (ip != nil && ip.IsLoopback()))) {
		return nil, errEngine
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errEngine
		}
	}
	u.Path = ""
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.MaxIdleConnsPerHost = 8
	return &Engine{base: u, user: user, password: password, client: &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (e *Engine) request(ctx context.Context, method, path string, query url.Values, input, output any) (int, error) {
	if e == nil || e.base == nil || e.client == nil {
		return 0, errEngine
	}
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return 0, errEngine
		}
		body = bytes.NewReader(raw)
	}
	u := *e.base
	u.Path = path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, errEngine
	}
	req.SetBasicAuth(e.user, e.password)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := e.client.Do(req)
	if err != nil {
		return 0, errEngine
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res.StatusCode, errEngine
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return res.StatusCode, errEngine
	}
	if output != nil && json.Unmarshal(raw, output) != nil {
		return res.StatusCode, errEngine
	}
	return res.StatusCode, nil
}

type engineProvider struct {
	ID                uint     `json:"id,omitempty"`
	Provider          string   `json:"provider"`
	AllowedModels     []string `json:"allowed_models"`
	BlacklistedModels []string `json:"blacklisted_models"`
	AllowAllKeys      bool     `json:"allow_all_keys"`
	Keys              []struct {
		KeyID string `json:"key_id"`
	} `json:"keys"`
}
type engineVK struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Value           string            `json:"value"`
	IsActive        *bool             `json:"is_active"`
	ProviderConfigs []engineProvider  `json:"provider_configs"`
	MCPConfigs      []json.RawMessage `json:"mcp_configs"`
	TeamID          *string           `json:"team_id"`
	CustomerID      *string           `json:"customer_id"`
	ExpiresAt       *time.Time        `json:"expires_at"`
}

func validEngineList(values []string, models bool) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		valid := engineIdentifier.MatchString(v)
		if models {
			valid = engineModel.MatchString(v)
		}
		if !valid || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func sameEngineSet(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
func (e *Engine) readKey(ctx context.Context, id string, memory bool) (engineVK, int, error) {
	if !engineIdentifier.MatchString(id) {
		return engineVK{}, 0, errEngineScope
	}
	q := url.Values{}
	if memory {
		q.Set("from_memory", "true")
	}
	var result struct {
		VirtualKey engineVK `json:"virtual_key"`
	}
	status, err := e.request(ctx, http.MethodGet, "/api/governance/virtual-keys/"+id, q, nil, &result)
	if err == nil && result.VirtualKey.ID != id {
		return engineVK{}, status, errEngineScope
	}
	return result.VirtualKey, status, err
}
func (e *Engine) findKey(ctx context.Context, name string) (engineVK, bool, error) {
	// Upstream search is substring-based. Page the
	// bounded result and compare exact names, refusing ambiguity or truncation.
	var found engineVK
	seen := false
	for offset := 0; offset < 1000; offset += 100 {
		var result struct {
			VirtualKeys []engineVK `json:"virtual_keys"`
			TotalCount  *int       `json:"total_count"`
		}
		_, err := e.request(ctx, http.MethodGet, "/api/governance/virtual-keys", url.Values{"search": {name}, "limit": {"100"}, "offset": {strconv.Itoa(offset)}}, nil, &result)
		if err != nil || result.TotalCount == nil || *result.TotalCount < 0 || *result.TotalCount > 1000 || len(result.VirtualKeys) > 100 {
			return engineVK{}, false, errEngine
		}
		for _, vk := range result.VirtualKeys {
			if vk.Name == name {
				if seen {
					return engineVK{}, false, errEngineScope
				}
				found = vk
				seen = true
			}
		}
		if offset+len(result.VirtualKeys) >= *result.TotalCount {
			return found, seen, nil
		}
		if len(result.VirtualKeys) != 100 {
			return engineVK{}, false, errEngine
		}
	}
	return engineVK{}, false, errEngine
}
func engineScope(vk engineVK, name, provider string) bool {
	return engineIdentifier.MatchString(vk.ID) && vk.Name == name && vk.Value != "" && vk.IsActive != nil && len(vk.MCPConfigs) == 0 && vk.TeamID == nil && vk.CustomerID == nil && vk.ExpiresAt == nil && len(vk.ProviderConfigs) == 1 && vk.ProviderConfigs[0].Provider == provider
}
func engineExact(vk engineVK, name, provider string, models, keyIDs []string) bool {
	if !engineScope(vk, name, provider) || !*vk.IsActive {
		return false
	}
	pc := vk.ProviderConfigs[0]
	ids := make([]string, len(pc.Keys))
	for i, k := range pc.Keys {
		ids[i] = k.KeyID
	}
	return !pc.AllowAllKeys && len(pc.BlacklistedModels) == 0 && validEngineList(pc.AllowedModels, true) && validEngineList(ids, false) && sameEngineSet(pc.AllowedModels, models) && sameEngineSet(ids, keyIDs)
}

// EnsureKey uses a stable caller-chosen per-agent name; never include a policy
// revision in that name. Callers must serialize policy reconciliation of that name across replicas
// so an older desired policy cannot overwrite a newer one. The pinned engine
// has a unique name index; a concurrent create can recover after HTTP 409.
// Updates retain the provider-config ID and omit budget/rate/reset fields.
func (e *Engine) EnsureKey(ctx context.Context, name, provider string, models, keyIDs []string) (EngineKey, error) {
	if !engineIdentifier.MatchString(name) || !engineIdentifier.MatchString(provider) || !validEngineList(models, true) || !validEngineList(keyIDs, false) {
		return EngineKey{}, errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	vk, exists, err := e.findKey(ctx, name)
	if err != nil {
		return EngineKey{}, err
	}
	if !exists {
		var result struct {
			VirtualKey engineVK `json:"virtual_key"`
		}
		payload := map[string]any{"name": name, "is_active": true, "mcp_configs": []any{}, "provider_configs": []any{map[string]any{"provider": provider, "allowed_models": models, "key_ids": keyIDs, "weight": 1}}}
		status, createErr := e.request(ctx, http.MethodPost, "/api/governance/virtual-keys", nil, payload, &result)
		if createErr != nil {
			if status != 0 && status != http.StatusConflict {
				return EngineKey{}, errEngine
			}
			// A timeout may occur after the create committed. Recover once by exact
			// name; never issue another create after an uncertain response.
			vk, exists, err = e.findKey(ctx, name)
			if err != nil || !exists {
				return EngineKey{}, errEngine
			}
		} else {
			vk = result.VirtualKey
		}
	}
	if !engineScope(vk, name, provider) {
		return EngineKey{}, errEngineScope
	}
	persisted, _, err := e.readKey(ctx, vk.ID, false)
	if err != nil || !engineScope(persisted, name, provider) || persisted.Value != vk.Value {
		return EngineKey{}, errEngineScope
	}
	if !engineExact(persisted, name, provider, models, keyIDs) {
		pc := persisted.ProviderConfigs[0]
		if pc.ID == 0 {
			return EngineKey{}, errEngineScope
		}
		payload := map[string]any{"is_active": true, "provider_configs": []any{map[string]any{"id": pc.ID, "provider": provider, "allowed_models": models, "blacklisted_models": []string{}, "key_ids": keyIDs, "weight": 1}}}
		if _, err = e.request(ctx, http.MethodPut, "/api/governance/virtual-keys/"+vk.ID, nil, payload, nil); err != nil {
			return EngineKey{}, errEngine
		}
	}
	persisted, _, err = e.readKey(ctx, vk.ID, false)
	if err != nil || persisted.Value != vk.Value || !engineExact(persisted, name, provider, models, keyIDs) {
		return EngineKey{}, errEngineScope
	}
	memory, _, err := e.readKey(ctx, vk.ID, true)
	if err != nil || memory.Value != vk.Value || !engineExact(memory, name, provider, models, keyIDs) {
		return EngineKey{}, errEngineScope
	}
	return EngineKey{ID: vk.ID, Value: vk.Value}, nil
}
func (e *Engine) DisableKey(ctx context.Context, id string) error {
	if !engineIdentifier.MatchString(id) {
		return errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	status, err := e.request(ctx, http.MethodPut, "/api/governance/virtual-keys/"+id, nil, map[string]any{"is_active": false}, nil)
	if err != nil && status != 404 {
		return errEngine
	}
	for _, memory := range []bool{false, true} {
		vk, status, err := e.readKey(ctx, id, memory)
		if status == 404 {
			continue
		}
		if err != nil || vk.IsActive == nil || *vk.IsActive {
			return errEngineScope
		}
	}
	return nil
}

// Price is exact-model catalog pricing. Any scoped override makes this
// scope-free query unqualified; return Known=false instead of implying a cost.
func (e *Engine) Price(ctx context.Context, provider, model string) (Price, error) {
	if !engineIdentifier.MatchString(provider) || !engineModel.MatchString(model) {
		return Price{}, errEngineScope
	}
	var result struct {
		Models []struct {
			Name        string          `json:"name"`
			Provider    string          `json:"provider"`
			Input       *float64        `json:"input_cost_per_token"`
			Output      *float64        `json:"output_cost_per_token"`
			OverrideIDs []string        `json:"pricing_override_ids"`
			Overridden  json.RawMessage `json:"overridden_pricing"`
		} `json:"models"`
	}
	_, err := e.request(ctx, http.MethodGet, "/api/models/details", url.Values{"provider": {provider}, "query": {model}, "limit": {"100"}, "offset": {"0"}}, nil, &result)
	if err != nil {
		return Price{}, errEngine
	}
	var p Price
	found := false
	for _, row := range result.Models {
		if row.Name != model || row.Provider != provider {
			continue
		}
		if found {
			return Price{}, errEngineScope
		}
		found = true
		if len(row.OverrideIDs) > 0 || (len(row.Overridden) > 0 && string(row.Overridden) != "null") {
			continue
		}
		p.InputCostPerToken = row.Input
		p.OutputCostPerToken = row.Output
		p.Known = row.Input != nil && row.Output != nil && validEngineCost(*row.Input) && validEngineCost(*row.Output)
	}
	return p, nil
}
func validEngineCost(n float64) bool { return n >= 0 && !math.IsNaN(n) && !math.IsInf(n, 0) }

// Usage reads aggregate native logs only. Missing-cost requests are explicit;
// TotalCost is observed estimated cost, never a provider invoice or strict cap.
func (e *Engine) Usage(ctx context.Context, ids []string, from, to time.Time) (Usage, error) {
	if !validEngineList(ids, false) || from.IsZero() || to.IsZero() || !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return Usage{}, errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{"virtual_key_ids": {strings.Join(ids, ",")}, "start_time": {from.UTC().Format(time.RFC3339Nano)}, "end_time": {to.UTC().Format(time.RFC3339Nano)}}
	var raw struct {
		TotalRequests    *int64   `json:"total_requests"`
		TotalTokens      *int64   `json:"total_tokens"`
		PromptTokens     *int64   `json:"prompt_tokens"`
		CompletionTokens *int64   `json:"completion_tokens"`
		TotalCost        *float64 `json:"total_cost"`
	}
	if _, err := e.request(ctx, http.MethodGet, "/api/logs/stats", q, nil, &raw); err != nil {
		return Usage{}, errEngine
	}
	if raw.TotalRequests == nil || raw.TotalTokens == nil || raw.PromptTokens == nil || raw.CompletionTokens == nil || raw.TotalCost == nil || *raw.TotalRequests < 0 || *raw.TotalTokens < 0 || *raw.PromptTokens < 0 || *raw.CompletionTokens < 0 || !validEngineCost(*raw.TotalCost) {
		return Usage{}, errEngine
	}
	q.Set("missing_cost_only", "true")
	var missing struct {
		TotalRequests *int64 `json:"total_requests"`
	}
	if _, err := e.request(ctx, http.MethodGet, "/api/logs/stats", q, nil, &missing); err != nil || missing.TotalRequests == nil || *missing.TotalRequests < 0 || *missing.TotalRequests > *raw.TotalRequests {
		return Usage{}, errEngine
	}
	return Usage{TotalRequests: *raw.TotalRequests, TotalTokens: *raw.TotalTokens, PromptTokens: *raw.PromptTokens, CompletionTokens: *raw.CompletionTokens, TotalCost: *raw.TotalCost, UncostedRequests: *missing.TotalRequests}, nil
}
