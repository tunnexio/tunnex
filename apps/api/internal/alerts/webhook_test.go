package alerts

import (
	"context"
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

func TestWebhookSenderRefusesPlainHTTPWithoutPrivateOptIn(t *testing.T) {
	t.Parallel()
	sender := NewWebhookSender(opener("http://hooks.example/alert"))
	_, err := sender.Send(context.Background(), sqlc.AlertDestination{EndpointSealed: []byte("sealed")}, []byte(`{}`))
	if !errors.Is(err, safedial.ErrUnsafeDestination) {
		t.Fatalf("plain HTTP error=%v, want unsafe destination", err)
	}
}
