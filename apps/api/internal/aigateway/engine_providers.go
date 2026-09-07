package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// ProviderEngine contains no secret-bearing result types. Secrets are transient
// write-only arguments; errors must never include native payloads or messages.
type ProviderEngine interface {
	EnsureProvider(context.Context) error
	PutProviderKey(context.Context, ProviderKeySpec, *string) error
	VerifyProviderKey(context.Context, ProviderKeySpec) error
	TestProviderKey(context.Context, ProviderKeySpec) (bool, error)
	DeleteProviderKey(context.Context, ProviderKeySpec) error
	ProviderModels(context.Context, string, int, int) (ProviderModelPage, error)
}
type ProviderKeySpec struct {
	ID       string
	Revision int64
	Models   []string
	Enabled  bool
}
type ProviderModel struct {
	ID   string
	Name string
}
type ProviderModelPage struct {
	Models []ProviderModel
	Total  int
}
type providerReadback struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Models      []string        `json:"models"`
	Enabled     *bool           `json:"enabled"`
	Weight      *float64        `json:"weight"`
	Blacklisted []string        `json:"blacklisted_models"`
	Aliases     json.RawMessage `json:"aliases"`
	Batch       *bool           `json:"use_for_batch_api"`
	Anthropic   *bool           `json:"use_anthropic_endpoints"`
	Value       json.RawMessage `json:"value"`
	Status      string          `json:"status"`
}

func nativeProviderSpec(s ProviderKeySpec) (string, []string, error) {
	id, err := uuid.Parse(strings.TrimPrefix(s.ID, "tnx-managed-"))
	if err != nil || id == uuid.Nil || s.ID != "tnx-managed-"+id.String() || s.Revision < 1 {
		return "", nil, errEngineScope
	}
	models, ok := canonicalModels(s.Models, false)
	if !ok {
		return "", nil, errEngineScope
	}
	for i := range models {
		models[i] = strings.TrimPrefix(models[i], "openrouter/")
	}
	return s.ID + "-r" + strconv.FormatInt(s.Revision, 10), models, nil
}
func providerSecretOK(v string) bool {
	if len(v) == 0 || len(v) > 4096 || strings.HasPrefix(v, "env.") || strings.HasPrefix(v, "vault.") || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
		return false
	}
	return !providerMask(v)
}
func providerMask(v string) bool {
	return strings.EqualFold(v, "<redacted>") || (len(v) > 0 && len(v) <= 8 && strings.Trim(v, "*") == "") || (len(v) == 32 && v[4:28] == strings.Repeat("*", 24))
}
func providerValueOK(raw json.RawMessage) bool {
	var v struct {
		Value string `json:"value"`
		Type  string `json:"type"`
		Ref   string `json:"ref"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Type == "plain_text" && v.Ref == "" && providerMask(v.Value)
}
func providerExact(k providerReadback, s ProviderKeySpec) bool {
	name, models, err := nativeProviderSpec(s)
	return err == nil && k.ID == s.ID && k.Name == name && k.Enabled != nil && *k.Enabled == s.Enabled && k.Weight != nil && *k.Weight == 1 && validEngineList(k.Models, true) && sameEngineSet(k.Models, models) && len(k.Blacklisted) == 0 && (len(k.Aliases) == 0 || string(k.Aliases) == "null" || string(k.Aliases) == "{}") && (k.Batch == nil || !*k.Batch) && (k.Anthropic == nil || !*k.Anthropic) && providerValueOK(k.Value)
}
func (e *Engine) providerKey(ctx context.Context, id string) (providerReadback, int, error) {
	var k providerReadback
	status, err := e.request(ctx, http.MethodGet, "/api/providers/openrouter/keys/"+id, nil, nil, &k)
	return k, status, err
}

// EnsureProvider must be called under the CP's shared provider-init lock. Existing
// provider configuration is never replaced, so unrelated keys remain untouched.
func (e *Engine) EnsureProvider(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var read struct {
		Name    string `json:"name"`
		Network struct {
			Retries *int `json:"max_retries"`
		} `json:"network_config"`
	}
	status, err := e.request(ctx, http.MethodGet, "/api/providers/openrouter", nil, nil, &read)
	if err != nil {
		if status != 404 {
			return errEngine
		}
		_, err = e.request(ctx, http.MethodPost, "/api/providers", nil, map[string]any{"provider": "openrouter", "keys": []any{}, "network_config": map[string]any{"max_retries": 0}}, nil)
		if err != nil {
			return errEngine
		}
		if _, err = e.request(ctx, http.MethodGet, "/api/providers/openrouter", nil, nil, &read); err != nil {
			return errEngine
		}
	}
	if read.Name != "openrouter" || read.Network.Retries == nil || *read.Network.Retries != 0 {
		return errEngineScope
	}
	return nil
}
func (e *Engine) PutProviderKey(ctx context.Context, s ProviderKeySpec, secret *string) error {
	name, models, err := nativeProviderSpec(s)
	if err != nil {
		return err
	}
	if secret != nil && !providerSecretOK(*secret) {
		return errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	old, status, readErr := e.providerKey(ctx, s.ID)
	exists := readErr == nil
	if readErr != nil && status != 404 {
		return errEngine
	}
	if exists {
		previous, parseErr := strconv.ParseInt(strings.TrimPrefix(old.Name, s.ID+"-r"), 10, 64)
		if old.ID != s.ID || parseErr != nil || previous < 1 || previous > s.Revision || old.Name != s.ID+"-r"+strconv.FormatInt(previous, 10) {
			return errEngineScope
		}
	}
	var value any
	if secret == nil {
		if !exists || old.ID != s.ID || !strings.HasPrefix(old.Name, s.ID+"-r") || !providerValueOK(old.Value) {
			return errEngineScope
		}
		// Echo only the supported literal placeholder, never arbitrary native fields.
		value = map[string]string{"type": "plain_text", "value": "<REDACTED>"}
	} else {
		value = *secret
	}
	body := map[string]any{"id": s.ID, "name": name, "value": value, "models": models, "blacklisted_models": []string{}, "weight": 1, "enabled": s.Enabled, "use_for_batch_api": false, "use_anthropic_endpoints": false}
	method, path := http.MethodPost, "/api/providers/openrouter/keys"
	if exists {
		method = http.MethodPut
		path += "/" + s.ID
	}
	var result providerReadback
	if _, err = e.request(ctx, method, path, nil, body, &result); err != nil {
		return errEngine
	}
	if !providerExact(result, s) {
		return errEngineScope
	}
	return e.VerifyProviderKey(ctx, s)
}
func (e *Engine) VerifyProviderKey(ctx context.Context, s ProviderKeySpec) error {
	if _, _, err := nativeProviderSpec(s); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	k, _, err := e.providerKey(ctx, s.ID)
	if err != nil {
		return errEngine
	}
	if !providerExact(k, s) {
		return errEngineScope
	}
	return nil
}
func (e *Engine) TestProviderKey(ctx context.Context, s ProviderKeySpec) (bool, error) {
	if !s.Enabled {
		return false, errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := e.VerifyProviderKey(ctx, s); err != nil {
		return false, err
	}
	var k providerReadback
	if _, err := e.request(ctx, http.MethodPost, "/api/providers/openrouter/keys/"+s.ID+"/refresh-models", nil, nil, &k); err != nil {
		return false, errEngine
	}
	if !providerExact(k, s) {
		return false, errEngineScope
	}
	switch k.Status {
	case "success":
		return true, nil
	case "list_models_failed":
		return false, nil
	default:
		return false, errEngine
	}
}

// DeleteProviderKey requires prior CP reference refusal and a verified disabled
// native key. Never delete a provider or cascade another key's configuration.
func (e *Engine) DeleteProviderKey(ctx context.Context, s ProviderKeySpec) error {
	if _, _, err := nativeProviderSpec(s); err != nil || s.Enabled {
		return errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	k, status, err := e.providerKey(ctx, s.ID)
	if status == 404 {
		return nil
	}
	if err != nil {
		return errEngine
	}
	if !providerExact(k, s) {
		return errEngineScope
	}
	if _, err = e.request(ctx, http.MethodDelete, "/api/providers/openrouter/keys/"+s.ID, nil, nil, nil); err != nil {
		return errEngine
	}
	_, status, err = e.providerKey(ctx, s.ID)
	if status != 404 || err == nil {
		return errEngine
	}
	return nil
}
func (e *Engine) ProviderModels(ctx context.Context, query string, limit, offset int) (ProviderModelPage, error) {
	out := ProviderModelPage{Models: []ProviderModel{}}
	if len(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return out, errEngineScope
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{"provider": {"openrouter"}, "unfiltered": {"true"}, "query": {query}, "limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}
	var raw struct {
		Models []struct {
			Name     string `json:"name"`
			Provider string `json:"provider"`
		} `json:"models"`
		Total *int `json:"total"`
	}
	if _, err := e.request(ctx, http.MethodGet, "/api/models", q, nil, &raw); err != nil || raw.Models == nil || raw.Total == nil || *raw.Total < 0 || len(raw.Models) > limit || (len(raw.Models) > 0 && *raw.Total < offset+len(raw.Models)) {
		return out, errEngine
	}
	seen := map[string]bool{}
	for _, m := range raw.Models {
		if m.Provider != "openrouter" || !engineModel.MatchString(m.Name) || seen[m.Name] {
			return ProviderModelPage{}, errEngineScope
		}
		seen[m.Name] = true
		out.Models = append(out.Models, ProviderModel{ID: "openrouter/" + m.Name, Name: m.Name})
	}
	out.Total = *raw.Total
	return out, nil
}
