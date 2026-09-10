//go:build enterprise

package devices

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
)

// TestAI0EnrolledIdentityAuthorizesAndRevokes exercises actual CP enrollment and
// runtime authentication. The destination is a synthetic local HTTP service,
// not Bifrost or a paid provider; this proves the identity seam only.
func TestAI0EnrolledIdentityAuthorizesAndRevokes(t *testing.T) {
	f := agentBootstrapFixture(t)
	bootstrap, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "ai0-enrolled-agent")
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: bootstrap, PublicKey: testAgentPublicKey(f.deviceSeed)})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.RuntimeCredential == "" || enrolled.PrivateKeyOneTime != "" {
		t.Fatal("enrollment must return runtime credential and preserve client private-key ownership")
	}
	runtime := agentruntime.New(f.pool, nil)
	identity, err := runtime.AuthenticateCurrent(f.ctx, enrolled.RuntimeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if identity.OrgID != f.org || identity.DeviceID != enrolled.Device.ID || identity.CredentialRevision != 1 || identity.CredentialState != "current" {
		t.Fatalf("enrollment returned incorrect identity binding: %+v", identity)
	}
	var arrivals atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("runtime bearer leaked to destination")
		}
		if r.Header.Get("X-Bf-Vk") != "sk-bf-ai0-enrolled-fixture" {
			t.Error("scoped engine key missing")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"result":"OK"}`)
	}))
	defer destination.Close()

	adapter, err := aigateway.NewAdapter(destination.URL, func(ctx context.Context, raw, model string) (aigateway.Grant, error) {
		current, err := runtime.AuthenticateCurrent(ctx, raw)
		if err != nil {
			return aigateway.Grant{}, err
		}
		if current != identity || model != "openrouter/allowed" {
			return aigateway.Grant{}, errors.New("identity or model denied")
		}
		return aigateway.Grant{Tenant: current.OrgID.String(), Agent: current.DeviceID.String(), VirtualKey: "sk-bf-ai0-enrolled-fixture", Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ingress := httptest.NewServer(adapter)
	defer ingress.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	call := func(raw, model string) int {
		t.Helper()
		request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, ingress.URL+"/v1/chat/completions", strings.NewReader(`{"model":"`+model+`","messages":[{"role":"user","content":"OK"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+raw)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode
	}
	if status := call(enrolled.RuntimeCredential, "openrouter/allowed"); status != http.StatusOK {
		t.Fatalf("enrolled runtime rejected: status=%d", status)
	}
	if arrivals.Load() != 1 {
		t.Fatal("enrolled identity did not reach destination")
	}
	for _, raw := range []string{bootstrap, enrolled.RuntimeCredential + "invalid"} {
		if status := call(raw, "openrouter/allowed"); status != http.StatusForbidden {
			t.Fatalf("invalid runtime accepted: status=%d", status)
		}
	}
	if status := call(enrolled.RuntimeCredential, "openrouter/denied"); status != http.StatusForbidden {
		t.Fatalf("denied model accepted: status=%d", status)
	}
	if err := f.svc.Revoke(f.ctx, f.org, f.owner, enrolled.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AuthenticateCurrent(f.ctx, enrolled.RuntimeCredential); !errors.Is(err, agentruntime.ErrUnauthorized) {
		t.Fatalf("revoked enrollment authenticated: %v", err)
	}
	if status := call(enrolled.RuntimeCredential, "openrouter/allowed"); status != http.StatusForbidden {
		t.Fatalf("revoked runtime accepted: status=%d", status)
	}
	if arrivals.Load() != 1 {
		t.Fatalf("refused credential reached destination: arrivals=%d", arrivals.Load())
	}
	t.Log("CP-issued bootstrap redeemed; runtime identity org/device/revision bound; authorized local destination reached; bootstrap, invalid and revoked runtime bearers refused without arrival")
}

// TestAI0EnrolledOpenRouter is an opt-in paid qualification wire, using a parent-
// started pinned Bifrost. The callback is a minimal qualification policy, not
// production AI-token authorization. It performs exactly two provider requests.
func TestAI0EnrolledOpenRouter(t *testing.T) {
	if os.Getenv("AI0_ALLOW_PAID_SMOKE") != "yes" {
		t.Skip("paid enrolled smoke requires explicit opt-in")
	}
	upstream := os.Getenv("AI0_ENROLLED_ENGINE_URL")
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		t.Fatal("enrolled engine must be a numeric loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		t.Fatal("enrolled engine must be a numeric loopback HTTP origin")
	}
	f := agentBootstrapFixture(t)
	bootstrap, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "ai0-enrolled-live")
	if err != nil {
		t.Fatal("bootstrap issuance failed")
	}
	enrolled, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: bootstrap, PublicKey: testAgentPublicKey(f.deviceSeed)})
	if err != nil || enrolled.RuntimeCredential == "" {
		t.Fatal("agent enrollment failed")
	}
	runtime := agentruntime.New(f.pool, nil)
	const model = "openrouter/openai/gpt-4o-mini"
	adapter, err := aigateway.NewAdapter(upstream, func(ctx context.Context, raw, requestedModel string) (aigateway.Grant, error) {
		identity, err := runtime.AuthenticateCurrent(ctx, raw)
		if err != nil {
			return aigateway.Grant{}, err
		}
		if identity.OrgID != f.org || identity.DeviceID != enrolled.Device.ID || identity.CredentialRevision != 1 || identity.CredentialState != "current" || requestedModel != model {
			return aigateway.Grant{}, errors.New("qualification policy denied")
		}
		return aigateway.Grant{Tenant: identity.OrgID.String(), Agent: identity.DeviceID.String(), VirtualKey: "sk-bf-ai0-enrolled-fixture", Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal("adapter configuration failed")
	}
	ingress := httptest.NewServer(adapter)
	defer ingress.Close()
	client := &http.Client{Timeout: 35 * time.Second}
	for _, path := range []string{"/v1/chat/completions", "/anthropic/v1/messages"} {
		payload, err := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "Reply only OK"}}, "stream": true, "max_tokens": 16})
		if err != nil {
			t.Fatal("request serialization failed")
		}
		request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, ingress.URL+path, strings.NewReader(string(payload)))
		if err != nil {
			t.Fatal("request construction failed")
		}
		request.Header.Set("Authorization", "Bearer "+enrolled.RuntimeCredential)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("enrolled streaming request failed")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		response.Body.Close()
		if readErr != nil || len(body) > 1<<20 || response.StatusCode != http.StatusOK {
			t.Fatalf("enrolled streaming failed: path=%s status=%d", path, response.StatusCode)
		}
		assertEnrolledSSE(t, path, response.Header.Get("Content-Type"), string(body))
		t.Logf("CP-enrolled credential -> adapter -> parent Bifrost -> OpenRouter stream passed: path=%s", path)
	}
}

func assertEnrolledSSE(t *testing.T, path, contentType, body string) {
	t.Helper()
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "text/event-stream" {
		t.Fatal("enrolled response is not SSE")
	}
	anthropic := strings.Contains(path, "messages")
	delta, finish, terminal := false, false, false
	for _, frame := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n") {
		var data []string
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "event:") && strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "error" {
				t.Fatal("enrolled stream contains error event")
			}
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		if len(data) == 0 {
			continue
		}
		if terminal {
			t.Fatal("enrolled stream has payload after terminal")
		}
		raw := strings.Join(data, "\n")
		if raw == "[DONE]" {
			if anthropic || !delta || !finish {
				t.Fatal("premature enrolled DONE")
			}
			terminal = true
			continue
		}
		var event struct {
			Type  string          `json:"type"`
			Error json.RawMessage `json:"error"`
			Delta struct {
				Type       string  `json:"type"`
				Text       string  `json:"text"`
				StopReason *string `json:"stop_reason"`
			} `json:"delta"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(raw), &event) != nil {
			t.Fatal("malformed enrolled stream event")
		}
		if event.Type == "error" || (len(event.Error) > 0 && string(event.Error) != "null") {
			t.Fatal("enrolled stream contains error payload")
		}
		if anthropic {
			if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				delta = true
			}
			if event.Type == "message_delta" && event.Delta.StopReason != nil && *event.Delta.StopReason != "" {
				finish = true
			}
			if event.Type == "message_stop" {
				if !delta || !finish {
					t.Fatal("premature enrolled message_stop")
				}
				terminal = true
			}
		} else {
			for _, choice := range event.Choices {
				if choice.Delta.Content != "" {
					delta = true
				}
				if choice.FinishReason != nil && *choice.FinishReason != "" {
					finish = true
				}
			}
		}
	}
	if !delta || !finish || !terminal {
		t.Fatalf("incomplete enrolled stream: delta=%t finish=%t terminal=%t", delta, finish, terminal)
	}
}
