package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts/safedial"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

// SecretOpener is deliberately the minimum crypto.Sealer capability used by
// outbound alert delivery. A sender opens a URL for one request only and never
// returns, logs, or persists the plaintext value.
type SecretOpener interface {
	Open(string) ([]byte, error)
}

type WebhookSender struct {
	opener  SecretOpener
	mailer  mail.Mailer
	timeout time.Duration
}

type deliveryError struct{ code string }

func (e *deliveryError) Error() string { return "alert delivery " + e.code }

func deliveryFailureCode(err error, status int32) string {
	if err == nil {
		return ""
	}
	if status >= 400 {
		return "http_error"
	}
	var coded *deliveryError
	if errors.As(err, &coded) {
		return coded.code
	}
	if errors.Is(err, safedial.ErrUnsafeDestination) {
		return "blocked"
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		return "timeout"
	}
	if errors.Is(err, safedial.ErrDestinationDNS) {
		return "dns"
	}
	return "network"
}

func stableDeliveryError(code string) error { return &deliveryError{code: code} }

func NewWebhookSender(opener SecretOpener, mailers ...mail.Mailer) *WebhookSender {
	var mailer mail.Mailer
	if len(mailers) > 0 {
		mailer = mailers[0]
	}
	return &WebhookSender{opener: opener, mailer: mailer, timeout: safedial.DefaultTimeout}
}

func (s *WebhookSender) Send(ctx context.Context, destination sqlc.AlertDestination, payload []byte) (int32, error) {
	if s == nil || s.opener == nil {
		return 0, stableDeliveryError("configuration")
	}
	endpoint, err := s.opener.Open(string(destination.EndpointSealed))
	if err != nil {
		return 0, stableDeliveryError("credential")
	}
	if destination.Kind == "email" {
		return s.sendEmail(ctx, string(endpoint), payload)
	}
	url, body, headers, err := transportRequest(destination.Kind, string(endpoint), payload)
	if err != nil {
		return 0, stableDeliveryError("configuration")
	}
	if _, err := safedial.ValidateURL(url, destination.AllowPrivate); err != nil {
		return 0, stableDeliveryError(deliveryFailureCode(err, 0))
	}
	client := safedial.NewClient(safedial.Options{AllowPrivate: destination.AllowPrivate, Timeout: s.timeout})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, stableDeliveryError("configuration")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Tunnex-Alerting/1")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, stableDeliveryError(deliveryFailureCode(err, 0))
	}
	if _, err := safedial.ReadBody(response, safedial.DefaultBodyLimit); err != nil {
		return int32(response.StatusCode), stableDeliveryError("response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return int32(response.StatusCode), stableDeliveryError("http_error")
	}
	return int32(response.StatusCode), nil
}

func (s *WebhookSender) sendEmail(ctx context.Context, recipient string, payload []byte) (int32, error) {
	if s.mailer == nil {
		return 0, stableDeliveryError("configuration")
	}
	message := alertText(payload)
	if err := s.mailer.Send(ctx, mail.Message{
		To: recipient, Subject: "Tunnex alert", Text: message,
	}); err != nil {
		return 0, stableDeliveryError(deliveryFailureCode(err, 0))
	}
	return 0, nil
}

// transportRequest keeps every provider's secret in the sealed endpoint field
// until a single outbound request. Webhook-family destinations retain their
// supplied URL; PagerDuty and Opsgenie store only their provider-issued key and
// therefore use their fixed public Events endpoints.
func transportRequest(kind, secret string, payload []byte) (string, []byte, map[string]string, error) {
	text := alertText(payload)
	switch kind {
	case "", "webhook":
		return secret, payload, nil, nil
	case "slack":
		body, headers, err := marshalTransport(map[string]string{"text": text})
		return secret, body, headers, err
	case "discord":
		body, headers, err := marshalTransport(map[string]string{"content": text})
		return secret, body, headers, err
	case "google_chat":
		body, headers, err := marshalTransport(map[string]string{"text": text})
		return secret, body, headers, err
	case "teams":
		body, headers, err := marshalTransport(map[string]any{
			"type": "message",
			"attachments": []map[string]any{{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard", "version": "1.4",
					"body": []map[string]string{{"type": "TextBlock", "wrap": "true", "text": text}},
				},
			}},
		})
		return secret, body, headers, err
	case "pagerduty":
		body, headers, err := marshalTransport(map[string]any{
			"routing_key": secret, "event_action": "trigger", "dedup_key": alertDedupKey(payload),
			"payload": map[string]string{"summary": text, "source": "tunnex", "severity": pagerDutySeverity(payload)},
		})
		return "https://events.pagerduty.com/v2/enqueue", body, headers, err
	case "opsgenie":
		body, headers, err := marshalTransport(map[string]any{
			"message": text, "alias": alertDedupKey(payload), "description": text, "priority": opsgeniePriority(payload),
		}, map[string]string{"Authorization": "GenieKey " + secret})
		return "https://api.opsgenie.com/v2/alerts", body, headers, err
	default:
		return "", nil, nil, fmt.Errorf("unsupported alert destination kind %q", kind)
	}
}

func marshalTransport(value any, headers ...map[string]string) ([]byte, map[string]string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	if len(headers) > 0 {
		return body, headers[0], nil
	}
	return body, nil, nil
}

func alertText(payload []byte) string {
	var event struct {
		Key      string `json:"key"`
		Severity string `json:"severity"`
		Subject  string `json:"subject"`
	}
	if err := json.Unmarshal(payload, &event); err != nil || strings.TrimSpace(event.Subject) == "" {
		return "Tunnex alert"
	}
	return fmt.Sprintf("[%s] %s: %s", event.Severity, event.Key, event.Subject)
}

func alertDedupKey(payload []byte) string {
	var event struct {
		DedupKey string `json:"dedup_key"`
	}
	if err := json.Unmarshal(payload, &event); err != nil || strings.TrimSpace(event.DedupKey) == "" {
		return "tunnex-alert"
	}
	return event.DedupKey
}

func pagerDutySeverity(payload []byte) string {
	var event struct {
		Severity string `json:"severity"`
	}
	_ = json.Unmarshal(payload, &event)
	if event.Severity == "critical" || event.Severity == "warning" || event.Severity == "info" {
		return event.Severity
	}
	return "warning"
}

func opsgeniePriority(payload []byte) string {
	switch pagerDutySeverity(payload) {
	case "critical":
		return "P1"
	case "warning":
		return "P3"
	default:
		return "P5"
	}
}
