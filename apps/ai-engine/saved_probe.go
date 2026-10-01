// Compiled into the pinned Bifrost handlers package. The owned credential never
// leaves the engine, appears in a result, or changes its serving allowlist.
package handlers

import (
	"github.com/maximhq/bifrost/core/schemas"
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
	for _, key := range config.Keys {
		if key.ID == id && key.Name == in.KeyName && key.Enabled != nil && (*key.Enabled || len(key.Models) == 0) {
			in.Secret = key.Value.GetValue()
			break
		}
	}
	if in.Mode == "" {
		in.Mode = "chat"
	}
	if !tunnexValidate(in, false) {
		tunnexFail(ctx, 409)
		return
	}
	native := &schemas.ProviderConfig{ProxyConfig: config.ProxyConfig, CustomProviderConfig: config.CustomProviderConfig, OpenAIConfig: config.OpenAIConfig}
	if config.NetworkConfig != nil {
		native.NetworkConfig = *config.NetworkConfig
	}
	if config.ConcurrencyAndBufferSize != nil {
		native.ConcurrencyAndBufferSize = *config.ConcurrencyAndBufferSize
	}
	SendJSON(ctx, tunnexProbe(in, native))
}
