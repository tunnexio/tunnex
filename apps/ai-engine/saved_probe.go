// Compiled into the pinned Bifrost handlers package. The owned credential never
// leaves the engine, appears in a result, or changes its serving allowlist.
package handlers

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/valyala/fasthttp"
	"strings"
)

func (h *ProviderHandler) tunnexSavedKeyProbe(ctx *fasthttp.RequestCtx) {
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		tunnexFail(ctx, 400)
		return
	}
	id, err := getKeyIDFromCtx(ctx)
	if err != nil || !strings.HasPrefix(id, "tnx-managed-") {
		tunnexFail(ctx, 400)
		return
	}
	var payload struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Mode     string `json:"mode"`
		KeyName  string `json:"key_name"`
		Endpoint string `json:"endpoint_url,omitempty"`
	}
	if !tunnexDecode(ctx, &payload) || len(payload.KeyName) > 100 {
		tunnexFail(ctx, 400)
		return
	}
	in := tunnexOperation{Provider: payload.Provider, Model: payload.Model, Mode: payload.Mode, KeyName: payload.KeyName, Endpoint: payload.Endpoint}
	config, err := h.inMemoryStore.GetProviderConfigRaw(provider)
	if err != nil {
		tunnexFail(ctx, 404)
		return
	}
	if tunnexEndpointKind(in.Provider) {
		if !strings.HasPrefix(string(provider), "custom-") || config.NetworkConfig == nil || config.NetworkConfig.BaseURL != in.Endpoint || in.Endpoint == "" {
			tunnexFail(ctx, 409)
			return
		}
	} else if string(provider) != in.Provider || in.Endpoint != "" {
		tunnexFail(ctx, 409)
		return
	}
	in.Secret = tunnexSavedSecret(config.Keys, id, in.KeyName)
	if in.Mode == "" {
		in.Mode = "chat"
	}
	if !tunnexValidate(in, false) {
		tunnexFail(ctx, 409)
		return
	}
	SendJSON(ctx, tunnexProbe(in, tunnexNativeConfig(config)))
}

// tunnexSavedSecret returns the stored value only for the exact owned key at
// the requested revision name, under the same enabled rule as serving setup.
func tunnexSavedSecret(keys []schemas.Key, id, name string) string {
	if !strings.HasPrefix(id, "tnx-managed-") || name == "" || len(name) > 100 {
		return ""
	}
	for _, key := range keys {
		if key.ID == id && key.Name == name && key.Enabled != nil && (*key.Enabled || len(key.Models) == 0) {
			return key.Value.GetValue()
		}
	}
	return ""
}

func tunnexNativeConfig(config *configstore.ProviderConfig) *schemas.ProviderConfig {
	native := &schemas.ProviderConfig{ProxyConfig: config.ProxyConfig, CustomProviderConfig: config.CustomProviderConfig, OpenAIConfig: config.OpenAIConfig}
	if config.NetworkConfig != nil {
		native.NetworkConfig = *config.NetworkConfig
	}
	if config.ConcurrencyAndBufferSize != nil {
		native.ConcurrencyAndBufferSize = *config.ConcurrencyAndBufferSize
	}
	return native
}

// tunnexSavedCatalog lists a standard provider's models with an owned stored
// key. The request names the key; it never carries one. The stored allowlist
// is not applied: it holds the models already configured, not the catalog.
func (h *ProviderHandler) tunnexSavedCatalog(ctx *fasthttp.RequestCtx) {
	var payload struct {
		Provider string `json:"provider"`
		KeyID    string `json:"key_id"`
		KeyName  string `json:"key_name"`
		Mode     string `json:"mode"`
		Query    string `json:"query"`
		Limit    int    `json:"limit"`
		Offset   int    `json:"offset"`
	}
	if !tunnexDecode(ctx, &payload) || !tunnexNative(payload.Provider) || !strings.HasPrefix(payload.KeyID, "tnx-managed-") || payload.KeyName == "" || len(payload.KeyName) > 100 {
		tunnexFail(ctx, 400)
		return
	}
	in := tunnexOperation{Provider: payload.Provider, Mode: payload.Mode, Query: payload.Query, Limit: payload.Limit, Offset: payload.Offset}
	if in.Mode == "" {
		in.Mode = "chat"
	}
	config, err := h.inMemoryStore.GetProviderConfigRaw(schemas.ModelProvider(in.Provider))
	if err != nil {
		tunnexFail(ctx, 404)
		return
	}
	in.Secret = tunnexSavedSecret(config.Keys, payload.KeyID, payload.KeyName)
	if !tunnexValidate(in, true) {
		tunnexFail(ctx, 409)
		return
	}
	code, body := tunnexCatalog(in, tunnexNativeConfig(config))
	if code != 200 {
		tunnexFail(ctx, code)
		return
	}
	SendJSON(ctx, body)
}
