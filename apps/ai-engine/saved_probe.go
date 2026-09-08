// Compiled into the pinned Bifrost handlers package by build.py.
// This private administration operation never returns or persists a secret.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var savedProbeModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$`)

// All routes use the same administrator authentication as key management.
// A new model is tested through LiteLLM without changing the serving allowlist.
func (h *ProviderHandler) tunnexSavedKeyProbe(ctx *fasthttp.RequestCtx) {
	fail := func(code int) {
		ctx.SetStatusCode(code)
		ctx.SetContentType("application/json")
		ctx.SetBodyString(`{"error":"saved credential test unavailable"}`)
	}
	ctx.Response.Header.Set("Cache-Control", "no-store")
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		fail(400)
		return
	}
	id, err := getKeyIDFromCtx(ctx)
	if err != nil || !strings.HasPrefix(id, "tnx-managed-") {
		fail(400)
		return
	}
	var in struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Mode     string `json:"mode"`
		KeyName  string `json:"key_name"`
		Endpoint string `json:"endpoint_url,omitempty"`
	}
	if len(ctx.PostBody()) > 4096 {
		fail(400)
		return
	}
	d := json.NewDecoder(bytes.NewReader(ctx.PostBody()))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || !savedProbeModel.MatchString(in.Model) || len(in.KeyName) > 100 {
		fail(400)
		return
	}
	switch in.Mode {
	case "chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank":
	default:
		fail(400)
		return
	}
	config, err := h.inMemoryStore.GetProviderConfigRaw(provider)
	if err != nil {
		fail(404)
		return
	}
	custom := in.Provider == "custom" || in.Provider == "sagemaker" || in.Provider == "azure_foundry"
	if custom {
		if !strings.HasPrefix(string(provider), "custom-") || config.NetworkConfig == nil || config.NetworkConfig.BaseURL != in.Endpoint || in.Endpoint == "" {
			fail(409)
			return
		}
	} else if string(provider) != in.Provider || in.Endpoint != "" {
		fail(409)
		return
	}
	secret := ""
	for _, key := range config.Keys {
		if key.ID == id && key.Name == in.KeyName && key.Enabled != nil && *key.Enabled {
			secret = key.Value.GetValue()
			break
		}
	}
	if secret == "" {
		fail(409)
		return
	}
	// Destination/authentication come only from installation configuration.
	u, err := url.Parse(os.Getenv("TUNNEX_AI_LITELLM_URL"))
	token := os.Getenv("TUNNEX_AI_LITELLM_ADMIN_TOKEN")
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(token) < 16 || len(token) > 4096 || strings.ContainsAny(token, " \r\n\t") {
		fail(503)
		return
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "litellm-bridge" || ip != nil && ip.IsLoopback())) {
		fail(503)
		return
	}
	payload := map[string]any{"provider": in.Provider, "model": in.Model, "mode": in.Mode, "api_key": secret}
	if custom {
		payload["endpoint_url"] = in.Endpoint
	}
	body, err := json.Marshal(payload)
	if err != nil {
		fail(503)
		return
	}
	defer clear(body)
	deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	u.Path = "/test-connection"
	req, err := http.NewRequestWithContext(deadline, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		fail(503)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		fail(503)
		return
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	var result struct {
		Status     string `json:"status"`
		DurationMS int64  `json:"duration_ms"`
	}
	if err != nil || len(raw) > 4096 || res.StatusCode != 200 || json.Unmarshal(raw, &result) != nil || (result.Status != "success" && result.Status != "error") || result.DurationMS < 0 {
		fail(503)
		return
	}
	SendJSON(ctx, result)
}
