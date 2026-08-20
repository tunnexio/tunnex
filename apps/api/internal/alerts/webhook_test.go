package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts/safedial"
)

type opener string

func (o opener) Open(_ string) ([]byte, error) { return []byte(o), nil }

func TestWebhookSenderUsesSealedEndpointAndJSON(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request=%s content-type=%q", request.Method, request.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"event":"agent.offline"}` {
			t.Errorf("body=%q", body)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	sender := NewWebhookSender(opener(server.URL))
	status, err := sender.Send(context.Background(), sqlc.AlertDestination{ID: uuid.New(), EndpointSealed: []byte("sealed"), AllowPrivate: true}, []byte(`{"event":"agent.offline"}`))
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("send status=%d err=%v", status, err)
	}
}

func TestProviderTransportPayloadsKeepSecretsOutOfPayloadExceptProviderContract(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"key":"agent.offline","severity":"critical","dedup_key":"agent:42","subject":"Agent 42 is offline"}`)
	tests := []struct {
		kind          string
		secret        string
		wantURL       string
		wantHeader    string
		wantBodyField string
	}{
		{kind: "slack", secret: "https://hooks.example/slack", wantURL: "https://hooks.example/slack", wantBodyField: "text"},
		{kind: "discord", secret: "https://hooks.example/discord", wantURL: "https://hooks.example/discord", wantBodyField: "content"},
		{kind: "google_chat", secret: "https://hooks.example/chat", wantURL: "https://hooks.example/chat", wantBodyField: "text"},
		{kind: "teams", secret: "https://hooks.example/teams", wantURL: "https://hooks.example/teams", wantBodyField: "attachments"},
		{kind: "pagerduty", secret: "routing-key", wantURL: "https://events.pagerduty.com/v2/enqueue", wantBodyField: "routing_key"},
		{kind: "opsgenie", secret: "api-key", wantURL: "https://api.opsgenie.com/v2/alerts", wantHeader: "GenieKey api-key", wantBodyField: "alias"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.kind, func(t *testing.T) {
			t.Parallel()
			url, body, headers, err := transportRequest(tt.kind, tt.secret, payload)
			if err != nil || url != tt.wantURL {
				t.Fatalf("url=%q err=%v", url, err)
			}
			if tt.wantHeader != "" && headers["Authorization"] != tt.wantHeader {
				t.Fatalf("authorization=%q", headers["Authorization"])
			}
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if _, ok := decoded[tt.wantBodyField]; !ok {
				t.Fatalf("body=%s missing %q", body, tt.wantBodyField)
			}
		})
	}
}

func TestDestinationHostUsesProviderSpecificWriteOnlyCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   DestinationInput
		want string
	}{
		{name: "webhook", in: DestinationInput{Kind: "webhook", Endpoint: "https://hooks.example/alert"}, want: "hooks.example"},
		{name: "pagerduty", in: DestinationInput{Kind: "pagerduty", Endpoint: "routing-key"}, want: "events.pagerduty.com"},
		{name: "opsgenie", in: DestinationInput{Kind: "opsgenie", Endpoint: "api-key"}, want: "api.opsgenie.com"},
		{name: "email", in: DestinationInput{Kind: "email", Endpoint: "ops@example.test"}, want: "example.test"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := destinationHost(tt.in)
			if err != nil || got != tt.want {
				t.Fatalf("host=%q err=%v", got, err)
			}
		})
	}
	if _, err := destinationHost(DestinationInput{Kind: "email", Endpoint: "ops@example.test", AllowPrivate: true}); !errors.Is(err, ErrInvalidDestination) {
		t.Fatalf("private email target error=%v, want invalid destination", err)
	}
}

func TestWebhookSenderRefusesPlainHTTPWithoutPrivateOptIn(t *testing.T) {
	t.Parallel()
	sender := NewWebhookSender(opener("http://hooks.example/alert"))
	_, err := sender.Send(context.Background(), sqlc.AlertDestination{EndpointSealed: []byte("sealed")}, []byte(`{}`))
	if !errors.Is(err, safedial.ErrUnsafeDestination) {
		t.Fatalf("plain HTTP error=%v, want unsafe destination", err)
	}
}
