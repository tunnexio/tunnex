package aigateway

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"net/url"
	"strconv"
	"strings"
)

// ConfigureCustomProxy is startup-only. Proxy credentials never leave private native configuration.
func (e *Engine) ConfigureCustomProxy(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User == nil || u.User.Username() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errEngineScope
	}
	if strings.ContainsAny(raw, "\r\n\t ") || u.ForceQuery || u.Opaque != "" {
		return errEngineScope
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errEngineScope
		}
	}
	password, ok := u.User.Password()
	if !ok || !providerSecretOK(password) || !providerSecretOK(u.User.Username()) {
		return errEngineScope
	}
	e.customProxy = u
	return nil
}
func (e *Engine) providerConfigPayload(provider, base string) (map[string]any, bool) {
	p := map[string]any{"provider": provider, "keys": []any{}, "network_config": map[string]any{"max_retries": 0}}
	if !strings.HasPrefix(provider, "custom-") {
		return p, base == ""
	}
	normalized, err := aiegress.NormalizeEndpoint(base)
	if err != nil || normalized != base || e.customProxy == nil {
		return nil, false
	}
	p["network_config"] = map[string]any{"base_url": base, "max_retries": 0, "allow_private_network": true, "insecure_skip_verify": false}
	p["proxy_config"] = map[string]any{"type": "http", "url": "env.TUNNEX_AI_CUSTOM_PROXY_URL"}
	p["custom_provider_config"] = map[string]any{"base_provider_type": "openai", "is_key_less": false, "allowed_requests": map[string]bool{"list_models": true, "chat_completion": true, "chat_completion_stream": true}}
	return p, true
}
func (e *Engine) customConfigExact(base, actual string, private, insecure bool, headers map[string]string, custom, proxy json.RawMessage) bool {
	if e.customProxy == nil || actual != base || !private || insecure || len(headers) != 0 {
		return false
	}
	var c struct {
		Base    string            `json:"base_provider_type"`
		Keyless bool              `json:"is_key_less"`
		Allowed map[string]bool   `json:"allowed_requests"`
		Paths   map[string]string `json:"request_path_overrides"`
	}
	if json.Unmarshal(custom, &c) != nil || c.Base != "openai" || c.Keyless || len(c.Paths) != 0 {
		return false
	}
	for _, k := range []string{"list_models", "chat_completion", "chat_completion_stream"} {
		if !c.Allowed[k] {
			return false
		}
	}
	for k, v := range c.Allowed {
		if v && k != "list_models" && k != "chat_completion" && k != "chat_completion_stream" {
			return false
		}
	}
	var p struct {
		Type     string          `json:"type"`
		URL      json.RawMessage `json:"url"`
		Username json.RawMessage `json:"username"`
		Password json.RawMessage `json:"password"`
		CA       json.RawMessage `json:"ca_cert_pem"`
	}
	if json.Unmarshal(proxy, &p) != nil || p.Type != "http" {
		return false
	}
	var endpoint struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Ref   string `json:"ref"`
	}
	if json.Unmarshal(p.URL, &endpoint) != nil || endpoint.Ref != "env.TUNNEX_AI_CUSTOM_PROXY_URL" || endpoint.Type != "env" || endpoint.Value != e.customProxy.String()[:4]+strings.Repeat("*", 24)+e.customProxy.String()[len(e.customProxy.String())-4:] {
		return false
	}
	empty := func(v json.RawMessage) bool { return len(v) == 0 || string(v) == "null" }
	return empty(p.Username) && empty(p.Password) && empty(p.CA)
}

func nativeSupportedProvider(provider string) bool {
	if supportedProvider(provider) {
		return true
	}
	id, e := uuid.Parse(strings.TrimPrefix(provider, "custom-"))
	return e == nil && id != uuid.Nil && provider == "custom-"+id.String()
}
