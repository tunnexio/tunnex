// Compiled into the pinned Bifrost HTTP handlers package. These private
// administrator operations use the same native provider implementations as
// serving, with transient credentials and no provider/key/model mutation.
package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/providers/cerebras"
	"github.com/maximhq/bifrost/core/providers/deepseek"
	"github.com/maximhq/bifrost/core/providers/gemini"
	"github.com/maximhq/bifrost/core/providers/groq"
	"github.com/maximhq/bifrost/core/providers/mistral"
	"github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/providers/openrouter"
	"github.com/maximhq/bifrost/core/providers/tunnexsagemaker"
	"github.com/maximhq/bifrost/core/providers/xai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

var savedProbeModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$`)
var errTunnexOperation = errors.New("native provider operation unavailable")

type tunnexOperation struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	Mode     string `json:"mode"`
	Secret   string `json:"api_key,omitempty"`
	Endpoint string `json:"endpoint_url,omitempty"`
	KeyName  string `json:"key_name,omitempty"`
	Query    string `json:"query,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}
type tunnexProbeFailure struct {
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	HTTPStatus *int   `json:"http_status,omitempty"`
}
type tunnexProbeResult struct {
	Status     string              `json:"status"`
	DurationMS int64               `json:"duration_ms"`
	Failure    *tunnexProbeFailure `json:"failure,omitempty"`
}

// No provider or credential-bearing diagnostics are logged in these operations.
type tunnexQuietLogger struct{}

func (tunnexQuietLogger) Debug(string, ...any)                   {}
func (tunnexQuietLogger) Info(string, ...any)                    {}
func (tunnexQuietLogger) Warn(string, ...any)                    {}
func (tunnexQuietLogger) Error(string, ...any)                   {}
func (tunnexQuietLogger) Fatal(string, ...any)                   {}
func (tunnexQuietLogger) SetLevel(schemas.LogLevel)              {}
func (tunnexQuietLogger) SetOutputType(schemas.LoggerOutputType) {}
func (tunnexQuietLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

func tunnexDecode(ctx *fasthttp.RequestCtx, out any) bool {
	ctx.Response.Header.Set("Cache-Control", "no-store")
	if len(ctx.PostBody()) > 8192 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(ctx.PostBody()))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}
func tunnexFail(ctx *fasthttp.RequestCtx, code int) {
	ctx.SetStatusCode(code)
	ctx.SetContentType("application/json")
	ctx.SetBodyString(`{"error":"native provider operation unavailable"}`)
}
func tunnexSecret(v string) bool {
	return len(v) > 0 && len(v) <= 4096 && strings.IndexFunc(v, unicode.IsSpace) < 0 && !strings.HasPrefix(v, "env.") && !strings.HasPrefix(v, "vault.")
}
func tunnexMode(v string) bool {
	return slices.Contains([]string{"chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank"}, v)
}
func tunnexNative(v string) bool {
	return slices.Contains([]string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek"}, v)
}
func tunnexEndpointKind(v string) bool {
	return v == "custom" || v == "azure_foundry" || v == "sagemaker"
}
func tunnexValidate(in tunnexOperation, catalog bool) bool {
	if in.Mode == "" {
		in.Mode = "chat"
	}
	if !tunnexMode(in.Mode) || !tunnexSecret(in.Secret) || (!tunnexNative(in.Provider) && !tunnexEndpointKind(in.Provider)) {
		return false
	}
	if tunnexEndpointKind(in.Provider) {
		if !tunnexEndpointAllowed(in.Provider, in.Endpoint) {
			return false
		}
	} else if in.Endpoint != "" {
		return false
	}
	if in.Provider == "sagemaker" && in.Mode != "chat" {
		return false
	}
	if strings.HasSuffix(in.Endpoint, "/anthropic") && in.Mode != "chat" {
		return false
	}
	if catalog {
		return len([]rune(in.Query)) <= 100 && in.Limit >= 1 && in.Limit <= 100 && in.Offset >= 0 && in.Offset <= 10000
	}
	if !savedProbeModel.MatchString(in.Model) || strings.HasPrefix(in.Model, "custom-") {
		return false
	}
	if tunnexNative(in.Provider) {
		p, m, ok := strings.Cut(in.Model, "/")
		return ok && p == in.Provider && savedProbeModel.MatchString(m)
	}
	return true
}

// The CP and CONNECT egress service independently enforce this installation
// policy. There is no request-controlled proxy, permissive fallback or TLS skip.
func tunnexEndpointAllowed(provider, endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Scheme != "https" && u.Scheme != "http") || strings.ContainsAny(endpoint, " \r\n\t") {
		return false
	}
	if provider == "azure_foundry" {
		host := u.Hostname()
		azure := strings.HasSuffix(host, ".openai.azure.com") || strings.HasSuffix(host, ".services.ai.azure.com") || strings.HasSuffix(host, ".cognitiveservices.azure.com")
		if u.Scheme != "https" || !azure || (u.Path != "/openai" && u.Path != "/anthropic") {
			return false
		}
	} else if u.Path == "/anthropic" {
		return false
	}
	raw, err := os.ReadFile(os.Getenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"))
	if err != nil || len(raw) > 65536 {
		return false
	}
	var policy struct {
		Public    bool `json:"public_https"`
		Endpoints []struct {
			Provider string `json:"provider"`
			URL      string `json:"url"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(raw, &policy) != nil {
		return false
	}
	for _, row := range policy.Endpoints {
		if row.URL == endpoint {
			kind := row.Provider
			if kind == "" {
				kind = "custom"
			}
			return kind == provider
		}
	}
	return provider != "sagemaker" && policy.Public && u.Scheme == "https"
}
func tunnexProvider(in tunnexOperation, native *schemas.ProviderConfig) (schemas.Provider, error) {
	cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{DefaultRequestTimeoutInSeconds: 9, MaxRetries: 0, MaxConnsPerHost: 1}, OpenAIConfig: &schemas.OpenAIConfig{DisableStore: true}}
	if native != nil {
		*cfg = *native
		cfg.SendBackRawRequest = false
		cfg.SendBackRawResponse = false
		cfg.StoreRawRequestResponse = false
		cfg.NetworkConfig.DefaultRequestTimeoutInSeconds = 9
		cfg.NetworkConfig.MaxRetries = 0
	}
	cfg.NetworkConfig.TunnexMaxResponseBodySize = 1 << 20
	if in.Model == "" {
		cfg.NetworkConfig.TunnexMaxResponseBodySize = 4 << 20
	}
	base := in.Provider
	if tunnexEndpointKind(in.Provider) {
		// Always require the authenticated Go CONNECT boundary, even for public URLs.
		proxyRaw := os.Getenv("TUNNEX_AI_CUSTOM_PROXY_URL")
		p, err := url.Parse(proxyRaw)
		if err != nil || p.Scheme != "http" || p.Host == "" || p.User == nil {
			return nil, errTunnexOperation
		}
		cfg.ProxyConfig = &schemas.ProxyConfig{Type: schemas.ProxyType("http"), URL: schemas.NewSecretVar("env.TUNNEX_AI_CUSTOM_PROXY_URL")}
		cfg.NetworkConfig.BaseURL = in.Endpoint
		cfg.NetworkConfig.AllowPrivateNetwork = true
		cfg.NetworkConfig.InsecureSkipVerify = false
		cfg.NetworkConfig.ExtraHeaders = nil
		base = "openai"
		if in.Provider == "sagemaker" {
			base = "tnx-sagemaker"
		}
		if strings.HasSuffix(in.Endpoint, "/anthropic") {
			base = "anthropic"
		}
		cfg.CustomProviderConfig = &schemas.CustomProviderConfig{CustomProviderKey: "tunnex-probe", BaseProviderType: schemas.ModelProvider(base)}
	}
	logger := tunnexQuietLogger{}
	switch base {
	case "tnx-sagemaker":
		return tunnexsagemaker.New(cfg, logger)
	case "openai":
		return openai.NewOpenAIProvider(cfg, logger), nil
	case "anthropic":
		return anthropic.NewAnthropicProvider(cfg, logger), nil
	case "gemini":
		return gemini.NewGeminiProvider(cfg, logger), nil
	case "openrouter":
		return openrouter.NewOpenRouterProvider(cfg, logger), nil
	case "groq":
		return groq.NewGroqProvider(cfg, logger)
	case "mistral":
		return mistral.NewMistralProvider(cfg, logger), nil
	case "cerebras":
		return cerebras.NewCerebrasProvider(cfg, logger)
	case "xai":
		return xai.NewXAIProvider(cfg, logger)
	case "deepseek":
		return deepseek.NewDeepSeekProvider(cfg, logger)
	}
	return nil, errTunnexOperation
}
func tunnexProbe(in tunnexOperation, cfg *schemas.ProviderConfig) (out tunnexProbeResult) {
	start := time.Now()
	out = tunnexProbeResult{Status: "error"}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()
	p, err := tunnexProvider(in, cfg)
	if err != nil {
		out.Failure = &tunnexProbeFailure{Kind: "configuration_error", Source: "gateway"}
		return out
	}
	defer tunnexClose(p)
	ctx, cancel := schemas.NewBifrostContextWithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	key := schemas.Key{ID: "tunnex-transient-probe", Value: *schemas.NewSecretVar(in.Secret), Models: schemas.WhiteList{"*"}}
	model := in.Model
	if tunnexNative(in.Provider) {
		model = strings.TrimPrefix(model, in.Provider+"/")
	}
	provider := schemas.ModelProvider(in.Provider)
	if tunnexEndpointKind(in.Provider) {
		provider = "tunnex-probe"
	}
	var result any
	var upstream *schemas.BifrostError
	text := "Reply with OK."
	limit := 16
	switch in.Mode {
	case "chat":
		result, upstream = p.ChatCompletion(ctx, key, &schemas.BifrostChatRequest{Provider: provider, Model: model, Input: []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: &text}}}, Params: &schemas.ChatParameters{MaxCompletionTokens: &limit}})
	case "completion":
		result, upstream = p.TextCompletion(ctx, key, &schemas.BifrostTextCompletionRequest{Provider: provider, Model: model, Input: &schemas.TextCompletionInput{PromptStr: &text}, Params: &schemas.TextCompletionParameters{MaxTokens: &limit}})
	case "embedding":
		result, upstream = p.Embedding(ctx, key, &schemas.BifrostEmbeddingRequest{Provider: provider, Model: model, Input: &schemas.EmbeddingInput{Text: &text}})
	case "audio_speech":
		voice := "alloy"
		result, upstream = p.Speech(ctx, key, &schemas.BifrostSpeechRequest{Provider: provider, Model: model, Input: &schemas.SpeechInput{Input: "OK"}, Params: &schemas.SpeechParameters{VoiceConfig: &schemas.SpeechVoiceInput{Voice: &voice}, ResponseFormat: "wav"}})
	case "audio_transcription":
		format := "json"
		result, upstream = p.Transcription(ctx, key, &schemas.BifrostTranscriptionRequest{Provider: provider, Model: model, Input: &schemas.TranscriptionInput{File: tunnexWAV(), Filename: "connection-test.wav"}, Params: &schemas.TranscriptionParameters{ResponseFormat: &format}})
	case "image_generation":
		n := 1
		size := "256x256"
		result, upstream = p.ImageGeneration(ctx, key, &schemas.BifrostImageGenerationRequest{Provider: provider, Model: model, Input: &schemas.ImageGenerationInput{Prompt: "A small blue circle."}, Params: &schemas.ImageGenerationParameters{N: &n, Size: &size}})
	case "video_generation":
		seconds := "4"
		size := "1280x720"
		result, upstream = p.VideoGeneration(ctx, key, &schemas.BifrostVideoGenerationRequest{Provider: provider, Model: model, Input: &schemas.VideoGenerationInput{Prompt: "A small blue circle."}, Params: &schemas.VideoGenerationParameters{Seconds: &seconds, Size: size}})
	case "rerank":
		n := 1
		result, upstream = p.Rerank(ctx, key, &schemas.BifrostRerankRequest{Provider: provider, Model: model, Query: "OK", Documents: []schemas.RerankDocument{{Text: "OK"}}, Params: &schemas.RerankParameters{TopN: &n}})
	}
	out.DurationMS = time.Since(start).Milliseconds()
	if upstream != nil {
		out.Failure = tunnexFailure(ctx, upstream)
		return out
	}
	if !tunnexValidResponse(in.Mode, result) {
		out.Failure = &tunnexProbeFailure{Kind: "invalid_response", Source: "provider"}
		return out
	}
	out.Status = "success"
	return out
}
func tunnexFailure(ctx context.Context, e *schemas.BifrostError) *tunnexProbeFailure {
	if ctx.Err() == context.DeadlineExceeded {
		return &tunnexProbeFailure{Kind: "timeout", Source: "gateway"}
	}
	if e.Error != nil && e.Error.Code != nil && *e.Error.Code == "unsupported_operation" {
		return &tunnexProbeFailure{Kind: "configuration_error", Source: "gateway"}
	}
	if e.StatusCode != nil && *e.StatusCode >= 400 && *e.StatusCode <= 599 {
		code := *e.StatusCode
		return &tunnexProbeFailure{Kind: "http_error", Source: "provider", HTTPStatus: &code}
	}
	return &tunnexProbeFailure{Kind: "network_error", Source: "provider"}
}
func tunnexFinish(v *string) bool { return v != nil && (*v == "stop" || *v == "length") }
func tunnexValidResponse(mode string, v any) bool {
	if v == nil {
		return false
	}
	switch mode {
	case "chat":
		r, ok := v.(*schemas.BifrostChatResponse)
		return ok && r != nil && len(r.Choices) == 1 && r.Choices[0].ChatNonStreamResponseChoice != nil && r.Choices[0].Message != nil && tunnexFinish(r.Choices[0].FinishReason)
	case "completion":
		r, ok := v.(*schemas.BifrostTextCompletionResponse)
		return ok && r != nil && len(r.Choices) == 1 && tunnexFinish(r.Choices[0].FinishReason)
	case "embedding":
		r, ok := v.(*schemas.BifrostEmbeddingResponse)
		if !ok || r == nil || len(r.Data) != 1 || len(r.Data[0].Embedding.EmbeddingArray) == 0 {
			return false
		}
		for _, n := range r.Data[0].Embedding.EmbeddingArray {
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return false
			}
		}
		return true
	case "audio_speech":
		r, ok := v.(*schemas.BifrostSpeechResponse)
		return ok && r != nil && len(r.Audio) > 44 && len(r.Audio) <= 1<<20
	case "audio_transcription":
		r, ok := v.(*schemas.BifrostTranscriptionResponse)
		return ok && r != nil
	case "image_generation":
		r, ok := v.(*schemas.BifrostImageGenerationResponse)
		if !ok || r == nil || len(r.Data) != 1 {
			return false
		}
		if r.Data[0].B64JSON != "" {
			decoded, err := base64.StdEncoding.DecodeString(r.Data[0].B64JSON)
			return err == nil && len(decoded) > 0 && len(decoded) <= 1<<20
		}
		u, err := url.Parse(r.Data[0].URL)
		return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
	case "video_generation":
		r, ok := v.(*schemas.BifrostVideoGenerationResponse)
		return ok && r != nil && r.ID != "" && (r.Status == schemas.VideoStatusQueued || r.Status == schemas.VideoStatusInProgress || r.Status == schemas.VideoStatusCompleted)
	case "rerank":
		r, ok := v.(*schemas.BifrostRerankResponse)
		return ok && r != nil && len(r.Results) == 1 && r.Results[0].Index == 0 && !math.IsNaN(r.Results[0].RelevanceScore) && !math.IsInf(r.Results[0].RelevanceScore, 0)
	}
	return false
}
func tunnexWAV() []byte {
	b := make([]byte, 1644)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], 1636)
	copy(b[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(b[16:], 16)
	binary.LittleEndian.PutUint16(b[20:], 1)
	binary.LittleEndian.PutUint16(b[22:], 1)
	binary.LittleEndian.PutUint32(b[24:], 8000)
	binary.LittleEndian.PutUint32(b[28:], 16000)
	binary.LittleEndian.PutUint16(b[32:], 2)
	binary.LittleEndian.PutUint16(b[34:], 16)
	copy(b[36:], "data")
	binary.LittleEndian.PutUint32(b[40:], 1600)
	return b
}

func (h *ProviderHandler) tunnexDraftProbe(ctx *fasthttp.RequestCtx) {
	var payload struct {
		Mode     string `json:"mode"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Secret   string `json:"api_key"`
		Endpoint string `json:"endpoint_url,omitempty"`
	}
	if !tunnexDecode(ctx, &payload) {
		tunnexFail(ctx, 400)
		return
	}
	in := tunnexOperation{Mode: payload.Mode, Provider: payload.Provider, Model: payload.Model, Secret: payload.Secret, Endpoint: payload.Endpoint}
	if in.Mode == "" {
		in.Mode = "chat"
	}
	if in.KeyName != "" || !tunnexValidate(in, false) {
		tunnexFail(ctx, 400)
		return
	}
	SendJSON(ctx, tunnexProbe(in, nil))
}
func (h *ProviderHandler) tunnexDraftCatalog(ctx *fasthttp.RequestCtx) {
	var payload struct {
		Mode     string `json:"mode"`
		Provider string `json:"provider"`
		Secret   string `json:"api_key"`
		Endpoint string `json:"endpoint_url"`
		Query    string `json:"query"`
		Limit    int    `json:"limit"`
		Offset   int    `json:"offset"`
	}
	if !tunnexDecode(ctx, &payload) {
		tunnexFail(ctx, 400)
		return
	}
	in := tunnexOperation{Mode: payload.Mode, Provider: payload.Provider, Secret: payload.Secret, Endpoint: payload.Endpoint, Query: payload.Query, Limit: payload.Limit, Offset: payload.Offset}
	if in.Mode == "" {
		in.Mode = "chat"
	}
	if in.KeyName != "" || in.Model != "" || !tunnexValidate(in, true) {
		tunnexFail(ctx, 400)
		return
	}
	p, err := tunnexProvider(in, nil)
	if err != nil {
		tunnexFail(ctx, 503)
		return
	}
	defer tunnexClose(p)
	deadline, cancel := schemas.NewBifrostContextWithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	key := schemas.Key{ID: "tunnex-transient-catalog", Value: *schemas.NewSecretVar(in.Secret), Models: schemas.WhiteList{"*"}}
	names := map[string]bool{}
	token := ""
	done := false
	for page := 0; page < 20; page++ {
		r, e := p.ListModels(deadline, []schemas.Key{key}, &schemas.BifrostListModelsRequest{Provider: schemas.ModelProvider(in.Provider), PageSize: 1000, PageToken: token, Unfiltered: true})
		if e != nil || r == nil || len(r.Data) > 10000 {
			tunnexFail(ctx, 503)
			return
		}
		for _, m := range r.Data {
			name := m.ID
			if tunnexEndpointKind(in.Provider) {
				name = strings.TrimPrefix(name, string(p.GetProviderKey())+"/")
			}
			if tunnexNative(in.Provider) && !strings.HasPrefix(name, in.Provider+"/") {
				name = in.Provider + "/" + name
			}
			if !savedProbeModel.MatchString(name) || len(name) > 255 || strings.Contains(name, in.Secret) || strings.HasPrefix(name, "custom-") {
				continue
			}
			if strings.Contains(strings.ToLower(name), strings.ToLower(in.Query)) {
				names[name] = true
			}
		}
		if len(names) > 10000 {
			tunnexFail(ctx, 503)
			return
		}
		if r.NextPageToken == "" {
			done = true
			break
		}
		if r.NextPageToken == token {
			tunnexFail(ctx, 503)
			return
		}
		token = r.NextPageToken
	}
	if !done {
		tunnexFail(ctx, 503)
		return
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	slices.Sort(sorted)
	items := []map[string]string{}
	for _, n := range sorted[min(in.Offset, len(sorted)):min(in.Offset+in.Limit, len(sorted))] {
		items = append(items, map[string]string{"id": n, "name": n})
	}
	SendJSON(ctx, map[string]any{"items": items, "total": len(sorted), "limit": in.Limit, "offset": in.Offset})
}

func tunnexClose(p schemas.Provider) {
	if transient, ok := p.(interface{ TunnexCloseProbeConnections() }); ok {
		transient.TunnexCloseProbeConnections()
	}
}
