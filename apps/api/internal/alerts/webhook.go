package alerts

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts/safedial"
)

// SecretOpener is deliberately the minimum crypto.Sealer capability used by
// outbound alert delivery. A sender opens a URL for one request only and never
// returns, logs, or persists the plaintext value.
type SecretOpener interface {
	Open(string) ([]byte, error)
}

type WebhookSender struct {
	opener  SecretOpener
	timeout time.Duration
}

func NewWebhookSender(opener SecretOpener) *WebhookSender {
	return &WebhookSender{opener: opener, timeout: safedial.DefaultTimeout}
}

func (s *WebhookSender) Send(ctx context.Context, destination sqlc.AlertDestination, payload []byte) (int32, error) {
	if s == nil || s.opener == nil {
		return 0, fmt.Errorf("alert webhook sender is not configured")
	}
	endpoint, err := s.opener.Open(string(destination.EndpointSealed))
	if err != nil {
		return 0, fmt.Errorf("open alert destination: %w", err)
	}
	url := string(endpoint)
	if _, err := safedial.ValidateURL(url, destination.AllowPrivate); err != nil {
		return 0, err
	}
	client := safedial.NewClient(safedial.Options{AllowPrivate: destination.AllowPrivate, Timeout: s.timeout})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("build alert request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Tunnex-Alerting/1")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	if _, err := safedial.ReadBody(response, safedial.DefaultBodyLimit); err != nil {
		return int32(response.StatusCode), fmt.Errorf("read alert response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return int32(response.StatusCode), fmt.Errorf("alert destination returned HTTP %d", response.StatusCode)
	}
	return int32(response.StatusCode), nil
}
