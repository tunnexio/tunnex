package tunnexsagemaker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixtureLogger struct{}

func (fixtureLogger) SetOutputType(schemas.LoggerOutputType) {}
func (fixtureLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

func (fixtureLogger) Debug(string, ...any)      {}
func (fixtureLogger) Info(string, ...any)       {}
func (fixtureLogger) Warn(string, ...any)       {}
func (fixtureLogger) Error(string, ...any)      {}
func (fixtureLogger) Fatal(string, ...any)      {}
func (fixtureLogger) SetLevel(schemas.LogLevel) {}
func (fixtureLogger) SetOutput(io.Writer)       {}

func newFixture(t *testing.T, role bool) (*Provider, schemas.Key, *schemas.BifrostContext, *schemas.BifrostChatRequest) {
	t.Helper()
	t.Setenv("FIXTURE_AWS_ACCESS", "FIXTUREKEY")
	t.Setenv("FIXTURE_AWS_SECRET", "fixture-private-signing-key")
	t.Setenv("FIXTURE_AWS_TOKEN", "fixture-session-token")
	t.Setenv("FIXTURE_CLIENT_KEY", "fixture-client-key-never-an-iam-key")
	m := modelBinding{Alias: "public-alias", Endpoint: "private-endpoint", Region: "ap-south-1", AccessEnv: "FIXTURE_AWS_ACCESS", SecretEnv: "FIXTURE_AWS_SECRET", SessionEnv: "FIXTURE_AWS_TOKEN"}
	if role {
		m.RoleARN = "arn:aws:iam::123456789012:role/explicit"
		m.ExternalID = "fixture-external"
	}
	in := installation{Endpoints: []endpointBinding{{URL: "http://installation-binding:8200", Models: []modelBinding{m}, Clients: []clientBinding{{KeyEnv: "FIXTURE_CLIENT_KEY", Models: []string{"public-alias"}}}}}}
	raw, _ := json.Marshal(in)
	path := filepath.Join(t.TempDir(), "bindings.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write fixture")
	}
	t.Setenv("TUNNEX_AI_SAGEMAKER_CONFIG_FILE", path)
	provider, err := New(&schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: "http://installation-binding:8200"}, CustomProviderConfig: &schemas.CustomProviderConfig{CustomProviderKey: "custom-fixture", BaseProviderType: "tnx-sagemaker"}}, fixtureLogger{})
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*Provider)
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	var original openai.OpenAIChatRequest
	if json.Unmarshal([]byte(`{"model":"public-alias","messages":[{"role":"user","content":"Reply OK."}],"max_tokens":16}`), &original) != nil {
		t.Fatal("request")
	}
	return p, schemas.Key{ID: "fixture", Value: *schemas.NewSecretVar("fixture-client-key-never-an-iam-key"), Models: schemas.WhiteList{"public-alias"}}, ctx, original.ToBifrostChatRequest(ctx)
}
func response(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestTunnexSageMakerSignsFixedAWSOriginAndPreservesAliasUsage(t *testing.T) {
	p, key, ctx, req := newFixture(t, false)
	p.client.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://runtime.sagemaker.ap-south-1.amazonaws.com/endpoints/private-endpoint/invocations" {
			t.Errorf("wrong origin %s", r.URL)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=FIXTUREKEY/") || !strings.Contains(r.Header.Get("Authorization"), "/ap-south-1/sagemaker/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "fixture-session-token" {
			t.Error("explicit IAM signing missing")
		}
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "fixture-client") || strings.Contains(string(raw), "fixture-private") || strings.Contains(string(raw), "public-alias") {
			t.Error("private/public binding leaked in endpoint body")
		}
		return response(200, []byte(`{"object":"chat.completion","model":"private-endpoint","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)), nil
	})
	out, failed := p.ChatCompletion(ctx, key, req)
	if failed != nil || out.Model != "public-alias" || out.Usage == nil || out.Usage.TotalTokens != 2 {
		t.Fatalf("alias/usage lost: %v %v", out, failed)
	}
}

func TestTunnexSageMakerScopeAndInstallationBindingFailBeforeNetwork(t *testing.T) {
	p, key, ctx, req := newFixture(t, false)
	p.client.Transport = fixtureTransport(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network call"); return nil, nil })
	key.Value = *schemas.NewSecretVar("other-client-key")
	if _, failed := p.ChatCompletion(ctx, key, req); failed == nil {
		t.Fatal("foreign client key accepted")
	}
	if _, err := New(&schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: "http://different-binding:8200"}}, fixtureLogger{}); err == nil {
		t.Fatal("unbound endpoint accepted")
	}
	key.Value = *schemas.NewSecretVar("fixture-client-key-never-an-iam-key")
	key.Models = schemas.WhiteList{"*"}
	catalog, failed := p.ListModels(ctx, []schemas.Key{key}, &schemas.BifrostListModelsRequest{})
	if failed != nil || len(catalog.Data) != 1 || catalog.Data[0].ID != "custom-fixture/public-alias" {
		t.Fatal("scoped live alias catalog failed")
	}
	key.BlacklistedModels = schemas.BlackList{"public-alias"}
	if _, failed = p.ListModels(ctx, []schemas.Key{key}, &schemas.BifrostListModelsRequest{}); failed == nil {
		t.Fatal("blacklist ignored")
	}
}

func TestTunnexSageMakerExplicitRoleFailureNeverFallsBack(t *testing.T) {
	p, key, ctx, req := newFixture(t, true)
	calls := 0
	p.client.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://sts.ap-south-1.amazonaws.com/" {
			t.Errorf("unexpected origin %s", r.URL)
		}
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), "AssumeRole") || !strings.Contains(string(raw), "fixture-external") {
			t.Error("role binding missing")
		}
		return response(403, []byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>fixture-private-signing-key</Message></Error></ErrorResponse>`)), nil
	})
	_, failed := p.ChatCompletion(ctx, key, req)
	if failed == nil || calls != 1 || strings.Contains(failed.String(), "fixture-private") {
		t.Fatalf("role failure fallback/leak: calls=%d err=%v", calls, failed)
	}
}

func eventBytes(t *testing.T, payload string, kind string) []byte {
	t.Helper()
	var out bytes.Buffer
	h := eventstream.Headers{}
	h.Set(":message-type", eventstream.StringValue(kind))
	h.Set(":event-type", eventstream.StringValue("PayloadPart"))
	if eventstream.NewEncoder().Encode(&out, eventstream.Message{Headers: h, Payload: []byte(payload)}) != nil {
		t.Fatal("encode event")
	}
	return out.Bytes()
}

func TestTunnexSageMakerStreamAliasesUsageAndPostHooks(t *testing.T) {
	p, key, ctx, req := newFixture(t, false)
	frames := eventBytes(t, `{"object":"chat.completion.chunk","model":"private-endpoint","choices":[{"index":0,"delta":{"content":"OK"}}]}`, "event")
	frames = append(frames, eventBytes(t, `{"object":"chat.completion.chunk","model":"private-endpoint","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`, "event")...)
	p.client.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/invocations-response-stream") {
			t.Error("wrong stream path")
		}
		return response(200, frames), nil
	})
	hookCalls := 0
	hooks := func(_ *schemas.BifrostContext, r *schemas.BifrostResponse, e *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		hookCalls++
		return r, e
	}
	stream, failed := p.ChatCompletionStream(ctx, hooks, nil, key, req)
	if failed != nil {
		t.Fatal(failed)
	}
	count := 0
	var last *schemas.BifrostChatResponse
	for chunk := range stream {
		if chunk.BifrostError != nil || chunk.BifrostChatResponse == nil || chunk.BifrostChatResponse.Model != "public-alias" {
			t.Fatalf("invalid chunk %v", chunk)
		}
		count++
		last = chunk.BifrostChatResponse
	}
	if count != 2 || hookCalls != 2 || last.Usage == nil || last.Usage.TotalTokens != 3 {
		t.Fatalf("stream accounting/hooks lost: count=%d hooks=%d last=%v", count, hookCalls, last)
	}
}

func TestTunnexSageMakerTruncatedAndExceptionStreamsFailSanitized(t *testing.T) {
	for _, name := range []string{"truncated", "exception", "crc", "oversized", "inband-error"} {
		t.Run(name, func(t *testing.T) {
			p, key, ctx, req := newFixture(t, false)
			frames := eventBytes(t, `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"OK"}}]}`, "event")
			switch name {
			case "exception":
				frames = append(frames, eventBytes(t, `{"message":"fixture-private-signing-key"}`, "exception")...)
			case "crc":
				frames[len(frames)-1] ^= 0xff
			case "oversized":
				frames = append([]byte{0x7f, 0xff, 0xff, 0xff}, make([]byte, 8)...)
			case "inband-error":
				frames = eventBytes(t, `{"error":{"message":"fixture-private-signing-key"}}`, "event")
			}
			p.client.Transport = fixtureTransport(func(*http.Request) (*http.Response, error) { return response(200, frames), nil })
			hooks := func(_ *schemas.BifrostContext, r *schemas.BifrostResponse, e *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
				return r, e
			}
			stream, failed := p.ChatCompletionStream(ctx, hooks, nil, key, req)
			if failed != nil {
				t.Fatal(failed)
			}
			errors := 0
			for chunk := range stream {
				if chunk.BifrostError != nil {
					errors++
					if strings.Contains(chunk.BifrostError.String(), "fixture-private") {
						t.Fatal("upstream secret reflected")
					}
				}
			}
			if errors != 1 {
				t.Fatal("incomplete stream accepted")
			}
		})
	}
}
