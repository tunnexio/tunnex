// Compiled into the pinned Bifrost core provider package by build.py.
// IAM credentials come only from explicit installation bindings. They are never
// obtained from profiles, instance metadata, request parameters or SDK defaults.
package tunnexsagemaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/maximhq/bifrost/core/providers/openai"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

const maxBody = 1024 * 1024

var operationSlots = make(chan struct{}, 8)

var (
	modelName        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$`)
	endpointName     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	regionName       = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]$`)
	envName          = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	roleName         = regexp.MustCompile(`^arn:aws(?:-cn|-us-gov)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	errConfiguration = errors.New("SageMaker installation binding is unavailable")
)

type modelBinding struct {
	Alias      string `json:"alias"`
	Endpoint   string `json:"endpoint"`
	Region     string `json:"region"`
	AccessEnv  string `json:"access_key_id_env"`
	SecretEnv  string `json:"secret_access_key_env"`
	SessionEnv string `json:"session_token_env,omitempty"`
	RoleARN    string `json:"role_arn,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}
type clientBinding struct {
	KeyEnv string   `json:"key_env"`
	Models []string `json:"models"`
}
type endpointBinding struct {
	URL     string          `json:"url"`
	Models  []modelBinding  `json:"models"`
	Clients []clientBinding `json:"clients"`
}
type installation struct {
	EndpointURL string            `json:"endpoint_url,omitempty"`
	Models      []modelBinding    `json:"models,omitempty"`
	Clients     []clientBinding   `json:"clients,omitempty"`
	Endpoints   []endpointBinding `json:"endpoints,omitempty"`
}
type scopedClient struct {
	key    string
	models map[string]bool
}
type Provider struct {
	*openai.OpenAIProvider
	name    schemas.ModelProvider
	models  map[string]modelBinding
	clients []scopedClient
	client  *http.Client
	logger  schemas.Logger
}

func secret(name string) (string, error) {
	if !envName.MatchString(name) {
		return "", errConfiguration
	}
	value := os.Getenv(name)
	if len(value) == 0 || len(value) > 4096 || strings.HasPrefix(value, "env.") || strings.HasPrefix(value, "vault.") || strings.HasPrefix(value, "os.environ/") {
		return "", errConfiguration
	}
	for _, c := range value {
		if c <= 32 || c >= 127 {
			return "", errConfiguration
		}
	}
	return value, nil
}

// New retains the normal Bifrost key selection, authorization and accounting
// pipeline. The configured base URL is an installation binding identifier;
// requests go exclusively to the fixed regional AWS service origins.
func New(config *schemas.ProviderConfig, logger schemas.Logger) (schemas.Provider, error) {
	path := os.Getenv("TUNNEX_AI_SAGEMAKER_CONFIG_FILE")
	if path == "" {
		path = os.Getenv("TUNNEX_AI_BRIDGE_CONFIG_FILE")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errConfiguration
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errConfiguration
	}
	var in installation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || len(in.Endpoints) > 64 {
		return nil, errConfiguration
	}
	if len(in.Models) > 0 || len(in.Clients) > 0 {
		if len(in.Endpoints) > 0 {
			return nil, errConfiguration
		}
		endpoint := in.EndpointURL
		if endpoint == "" {
			endpoint = os.Getenv("TUNNEX_AI_SAGEMAKER_ENDPOINT_URL")
		}
		if endpoint == "" {
			return nil, errConfiguration
		}
		in.Endpoints = []endpointBinding{{endpoint, in.Models, in.Clients}}
	}
	var binding *endpointBinding
	seen := map[string]bool{}
	for i := range in.Endpoints {
		b := &in.Endpoints[i]
		if b.URL == "" || seen[b.URL] {
			return nil, errConfiguration
		}
		seen[b.URL] = true
		if b.URL == config.NetworkConfig.BaseURL {
			binding = b
		}
	}
	if binding == nil || len(binding.Models) == 0 || len(binding.Models) > 64 || len(binding.Clients) == 0 || len(binding.Clients) > 128 {
		return nil, errConfiguration
	}
	p := &Provider{name: "tnx-sagemaker", models: map[string]modelBinding{}, logger: logger}
	for _, m := range binding.Models {
		if !modelName.MatchString(m.Alias) || !endpointName.MatchString(m.Endpoint) || !regionName.MatchString(m.Region) {
			return nil, errConfiguration
		}
		if _, duplicate := p.models[m.Alias]; duplicate {
			return nil, errConfiguration
		}
		if _, err = secret(m.AccessEnv); err != nil {
			return nil, err
		}
		if _, err = secret(m.SecretEnv); err != nil {
			return nil, err
		}
		if m.SessionEnv != "" {
			if _, err = secret(m.SessionEnv); err != nil {
				return nil, err
			}
		}
		if m.RoleARN != "" {
			partition := "aws"
			if strings.HasPrefix(m.Region, "cn-") {
				partition = "aws-cn"
			}
			if strings.HasPrefix(m.Region, "us-gov-") {
				partition = "aws-us-gov"
			}
			if !roleName.MatchString(m.RoleARN) || !strings.HasPrefix(m.RoleARN, "arn:"+partition+":") || len(m.ExternalID) > 1224 || strings.ContainsAny(m.ExternalID, "\r\n") {
				return nil, errConfiguration
			}
		} else if m.ExternalID != "" {
			return nil, errConfiguration
		}
		p.models[m.Alias] = m
	}
	seenKeys := map[string]bool{}
	for _, c := range binding.Clients {
		key, err := secret(c.KeyEnv)
		if err != nil || len(key) < 16 || seenKeys[key] || len(c.Models) == 0 || len(c.Models) > 64 {
			return nil, errConfiguration
		}
		seenKeys[key] = true
		scope := scopedClient{key: key, models: map[string]bool{}}
		for _, alias := range c.Models {
			if _, ok := p.models[alias]; !ok || scope.models[alias] {
				return nil, errConfiguration
			}
			scope.models[alias] = true
		}
		p.clients = append(p.clients, scope)
	}
	clone := *config
	custom := schemas.CustomProviderConfig{BaseProviderType: "openai"}
	if config.CustomProviderConfig != nil {
		custom = *config.CustomProviderConfig
		if custom.CustomProviderKey != "" {
			p.name = schemas.ModelProvider(custom.CustomProviderKey)
		}
	}
	custom.AllowedRequests = &schemas.AllowedRequests{ListModels: true, ChatCompletion: true, ChatCompletionStream: true}
	clone.CustomProviderConfig = &custom
	p.OpenAIProvider = openai.NewOpenAIProvider(&clone, logger)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 9 * time.Second, DisableCompression: true}
	p.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p, nil
}

func (p *Provider) GetProviderKey() schemas.ModelProvider { return p.name }
func (p *Provider) TunnexCloseProbeConnections() {
	p.client.CloseIdleConnections()
	if closer, ok := any(p.OpenAIProvider).(interface{ TunnexCloseProbeConnections() }); ok {
		closer.TunnexCloseProbeConnections()
	}
}
func (p *Provider) allowed(key schemas.Key) map[string]bool {
	value := key.Value.GetValue()
	for _, c := range p.clients {
		if subtle.ConstantTimeCompare([]byte(value), []byte(c.key)) == 1 {
			return c.models
		}
	}
	return nil
}
func (p *Provider) ListModels(_ *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostListModelsRequest) (*schemas.BifrostListModelsResponse, *schemas.BifrostError) {
	names := map[string]bool{}
	for _, key := range keys {
		if key.Enabled != nil && !*key.Enabled {
			continue
		}
		for alias := range p.allowed(key) {
			permitted := len(key.Models) == 0
			for _, model := range key.Models {
				if model == alias || model == "*" {
					permitted = true
				}
			}
			for _, model := range key.BlacklistedModels {
				if model == alias {
					permitted = false
				}
			}
			if permitted {
				names[alias] = true
			}
		}
	}
	if len(names) == 0 {
		return nil, failure(401, "configuration_error")
	}
	sorted := make([]string, 0, len(names))
	for alias := range names {
		sorted = append(sorted, alias)
	}
	sort.Strings(sorted)
	out := &schemas.BifrostListModelsResponse{Data: []schemas.Model{}}
	for _, alias := range sorted {
		out.Data = append(out.Data, schemas.Model{ID: string(p.name) + "/" + alias})
	}
	return out.ApplyPagination(request.PageSize, request.PageToken), nil
}

func failure(status int, kind string) *schemas.BifrostError {
	return &schemas.BifrostError{StatusCode: schemas.Ptr(status), AllowFallbacks: schemas.Ptr(false), IsBifrostError: false, Type: schemas.Ptr(kind), Error: &schemas.ErrorField{Message: "SageMaker operation failed"}}
}
func (p *Provider) credentials(ctx context.Context, m modelBinding) (aws.Credentials, error) {
	access, err := secret(m.AccessEnv)
	if err != nil {
		return aws.Credentials{}, err
	}
	private, err := secret(m.SecretEnv)
	if err != nil {
		return aws.Credentials{}, err
	}
	token := ""
	if m.SessionEnv != "" {
		token, err = secret(m.SessionEnv)
		if err != nil {
			return aws.Credentials{}, err
		}
	}
	creds := aws.Credentials{AccessKeyID: access, SecretAccessKey: private, SessionToken: token}
	if m.RoleARN == "" {
		return creds, nil
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(m.Region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	client := sts.NewFromConfig(aws.Config{Region: m.Region, Credentials: credentials.NewStaticCredentialsProvider(access, private, token), HTTPClient: p.client, Retryer: func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 1 }) }}, func(o *sts.Options) { o.BaseEndpoint = aws.String("https://sts." + m.Region + "." + suffix) })
	result, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(m.RoleARN), RoleSessionName: aws.String("tunnex-ai-engine"), ExternalId: func() *string {
		if m.ExternalID == "" {
			return nil
		}
		return aws.String(m.ExternalID)
	}()})
	if err != nil || result == nil || result.Credentials == nil || result.Credentials.AccessKeyId == nil || result.Credentials.SecretAccessKey == nil || result.Credentials.SessionToken == nil {
		return aws.Credentials{}, errConfiguration
	}
	return aws.Credentials{AccessKeyID: *result.Credentials.AccessKeyId, SecretAccessKey: *result.Credentials.SecretAccessKey, SessionToken: *result.Credentials.SessionToken}, nil
}

func (p *Provider) invoke(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostChatRequest, stream bool) (*http.Response, context.CancelFunc, *schemas.BifrostError) {
	if request == nil || !p.allowed(key)[request.Model] {
		return nil, nil, failure(401, "configuration_error")
	}
	m, ok := p.models[request.Model]
	if !ok {
		return nil, nil, failure(401, "configuration_error")
	}
	in := openai.ToOpenAIChatRequest(ctx, request)
	if in == nil || len(in.Messages) == 0 || len(in.Messages) > 64 {
		return nil, nil, failure(400, "configuration_error")
	}
	encoded, err := json.Marshal(in)
	if err != nil || len(in.ExtraParams) > 0 {
		return nil, nil, failure(400, "configuration_error")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return nil, nil, failure(400, "configuration_error")
	}
	for field := range fields {
		switch field {
		case "model", "messages", "max_tokens", "max_completion_tokens", "stream", "temperature", "stream_options":
		default:
			return nil, nil, failure(400, "configuration_error")
		}
	}
	// Retain the original adapter's explicit text-only endpoint contract.
	for _, message := range in.Messages {
		if message.Content == nil || message.Content.ContentStr == nil || (message.Role != "system" && message.Role != "user" && message.Role != "assistant") {
			return nil, nil, failure(400, "configuration_error")
		}
	}
	tokens := 1024
	if in.MaxCompletionTokens != nil {
		tokens = *in.MaxCompletionTokens
	}
	if in.MaxTokens != nil {
		tokens = *in.MaxTokens
	}
	if tokens < 1 || tokens > 4096 {
		return nil, nil, failure(400, "configuration_error")
	}
	body := map[string]any{"messages": in.Messages, "max_tokens": tokens, "stream": stream}
	if in.Temperature != nil {
		if *in.Temperature < 0 || *in.Temperature > 2 {
			return nil, nil, failure(400, "configuration_error")
		}
		body["temperature"] = in.Temperature
	}
	if stream {
		body["stream_options"] = map[string]bool{"include_usage": true}
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 32768 {
		return nil, nil, failure(400, "configuration_error")
	}
	defer clear(raw)
	select {
	case operationSlots <- struct{}{}:
	default:
		return nil, nil, failure(429, "configuration_error")
	}
	deadline, stop := context.WithTimeout(ctx, 30*time.Second)
	var once sync.Once
	cancel := func() { once.Do(func() { stop(); <-operationSlots }) }
	creds, err := p.credentials(deadline, m)
	if err != nil {
		cancel()
		return nil, nil, failure(502, "configuration_error")
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(m.Region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	path := "invocations"
	if stream {
		path = "invocations-response-stream"
	}
	url := "https://runtime.sagemaker." + m.Region + "." + suffix + "/endpoints/" + m.Endpoint + "/" + path
	req, err := http.NewRequestWithContext(deadline, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		cancel()
		return nil, nil, failure(502, "configuration_error")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if stream {
		req.Header.Set("Accept", "application/vnd.amazon.eventstream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	hash := sha256.Sum256(raw)
	if v4.NewSigner().SignHTTP(deadline, creds, req, hex.EncodeToString(hash[:]), "sagemaker", m.Region, time.Now()) != nil {
		cancel()
		return nil, nil, failure(502, "configuration_error")
	}
	res, err := p.client.Do(req)
	if err != nil {
		kind := "network_error"
		var networkErr net.Error
		if deadline.Err() != nil || errors.As(err, &networkErr) && networkErr.Timeout() {
			kind = "timeout"
		}
		cancel()
		return nil, nil, failure(502, kind)
	}
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		res.Body.Close()
		cancel()
		status := res.StatusCode
		kind := "http_error"
		if status < 400 || status > 599 {
			status = 502
			kind = "invalid_response"
		}
		return nil, nil, failure(status, kind)
	}
	return res, cancel, nil
}

func (p *Provider) ChatCompletion(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostChatRequest) (*schemas.BifrostChatResponse, *schemas.BifrostError) {
	start := time.Now()
	res, cancel, failed := p.invoke(ctx, key, request, false)
	if failed != nil {
		return nil, failed
	}
	defer cancel()
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return nil, failure(502, "invalid_response")
	}
	var out schemas.BifrostChatResponse
	if json.Unmarshal(raw, &out) != nil || len(out.Choices) != 1 || out.Choices[0].ChatNonStreamResponseChoice == nil || out.Choices[0].ChatNonStreamResponseChoice.Message == nil || out.Choices[0].FinishReason == nil {
		return nil, failure(502, "invalid_response")
	}
	out.Model = request.Model
	out.ExtraFields.Latency = time.Since(start).Milliseconds()
	return &out, nil
}

// Decode only bounded, CRC-checked AWS frames before interpreting their payload.
func readEvent(reader io.Reader) (eventstream.Message, error) {
	var prelude [12]byte
	if _, err := io.ReadFull(reader, prelude[:]); err != nil {
		return eventstream.Message{}, err
	}
	total := binary.BigEndian.Uint32(prelude[:4])
	headers := binary.BigEndian.Uint32(prelude[4:8])
	if total < 16 || total > 65536+4096 || headers > 4096 || headers > total-16 {
		return eventstream.Message{}, errors.New("invalid frame")
	}
	raw := make([]byte, total)
	copy(raw, prelude[:])
	if _, err := io.ReadFull(reader, raw[12:]); err != nil {
		return eventstream.Message{}, err
	}
	return eventstream.NewDecoder().Decode(bytes.NewReader(raw), nil)
}

func (p *Provider) ChatCompletionStream(ctx *schemas.BifrostContext, hooks schemas.PostHookRunner, finalizer func(context.Context), key schemas.Key, request *schemas.BifrostChatRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	start := time.Now()
	res, cancel, failed := p.invoke(ctx, key, request, true)
	if failed != nil {
		return nil, failed
	}
	out := make(chan *schemas.BifrostStreamChunk, schemas.DefaultStreamBufferSize)
	go func() {
		defer providerUtils.EnsureStreamFinalizerCalled(ctx, finalizer)
		defer close(out)
		defer cancel()
		defer res.Body.Close()
		failed := func() {
			ctx.SetValue(schemas.BifrostContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendBifrostError(ctx, hooks, failure(502, "invalid_response"), out, p.logger, finalizer)
		}
		usage := &schemas.BifrostLLMUsage{}
		ctx.SetValue(schemas.BifrostContextKeyStreamAccumulatedUsage, usage)
		var terminal *schemas.BifrostChatResponse
		pending := []byte{}
		count, index := 0, 0
		parse := func(raw []byte) bool {
			raw = bytes.TrimSpace(raw)
			raw = bytes.TrimPrefix(raw, []byte("data: "))
			if bytes.Equal(raw, []byte("[DONE]")) {
				return terminal != nil
			}
			var chunk schemas.BifrostChatResponse
			if len(raw) > 65536 || json.Unmarshal(raw, &chunk) != nil || chunk.Object != "chat.completion.chunk" || len(chunk.Choices) > 1 || len(chunk.Choices) == 0 && chunk.Usage == nil {
				return false
			}
			if chunk.Usage != nil {
				*usage = *chunk.Usage
			}
			chunk.Model = request.Model
			chunk.ExtraFields.ChunkIndex = index
			index++
			chunk.ExtraFields.Latency = time.Since(start).Milliseconds()
			if len(chunk.Choices) == 1 && chunk.Choices[0].FinishReason != nil {
				terminal = &chunk
				return true
			}
			if len(chunk.Choices) == 0 {
				return true
			}
			if terminal != nil {
				return false
			}
			providerUtils.ProcessAndSendResponse(ctx, hooks, providerUtils.GetBifrostResponseForStreamResponse(nil, &chunk, nil, nil, nil, nil), out, finalizer)
			return true
		}
		reader := io.LimitReader(res.Body, maxBody+1)
		for {
			frame, err := readEvent(reader)
			if err == io.EOF {
				break
			}
			if err != nil {
				failed()
				return
			}
			count += len(frame.Payload)
			if count > maxBody {
				failed()
				return
			}
			kind, event := frame.Headers.Get(":message-type"), frame.Headers.Get(":event-type")
			if kind == nil || kind.String() != "event" || event == nil || event.String() != "PayloadPart" {
				failed()
				return
			}
			pending = append(pending, frame.Payload...)
			if len(pending) > 65536 {
				failed()
				return
			}
			if json.Valid(bytes.TrimSpace(pending)) {
				if !parse(pending) {
					failed()
					return
				}
				pending = nil
				continue
			}
			for {
				line, remaining, ok := bytes.Cut(pending, []byte("\n"))
				if !ok {
					break
				}
				pending = remaining
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if !parse(line) {
					failed()
					return
				}
			}
		}
		if len(bytes.TrimSpace(pending)) > 0 && !parse(pending) || terminal == nil {
			failed()
			return
		}
		terminal.Model = request.Model
		terminal.Usage = usage
		terminal.ExtraFields.Latency = time.Since(start).Milliseconds()
		ctx.SetValue(schemas.BifrostContextKeyStreamEndIndicator, true)
		providerUtils.ProcessAndSendResponse(ctx, hooks, providerUtils.GetBifrostResponseForStreamResponse(nil, terminal, nil, nil, nil, nil), out, finalizer)
	}()
	return out, nil
}
