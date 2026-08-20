package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdmail "net/mail"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts/safedial"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

var (
	ErrDestinationNotFound = errors.New("alert destination not found")
	ErrInvalidDestination  = errors.New("invalid alert destination")
)

// DestinationInput carries the one write-only endpoint. The service seals it
// before persistence and never returns it in a destination projection.
type DestinationInput struct {
	Kind            string
	Name            string
	Endpoint        string
	AllowPrivate    bool
	SeverityFloor   string
	CooldownSeconds int32
}

// ConfigService owns F11 configuration writes. It intentionally has no HTTP
// client: creating a destination must not make an outbound network request.
// A future explicit test-send uses WebhookSender and records its real result.
type ConfigService struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	sealer *crypto.Sealer
	sender Sender
}

func NewConfigService(pool *pgxpool.Pool, sealer *crypto.Sealer, mailer mail.Mailer) *ConfigService {
	return &ConfigService{pool: pool, q: sqlc.New(pool), sealer: sealer, sender: NewWebhookSender(sealer, mailer)}
}

// TestResult deliberately reports a stable outcome category instead of a raw
// transport error. Raw resolver and dial errors can disclose private topology;
// an operator still needs to distinguish a guard refusal, timeout, DNS failure,
// and a provider HTTP rejection.
type TestResult struct {
	Delivered   bool
	StatusCode  *int32
	FailureCode string
}

func (s *ConfigService) List(ctx context.Context, orgID uuid.UUID) ([]sqlc.AlertDestination, error) {
	return s.q.ListAlertDestinations(ctx, orgID)
}

func (s *ConfigService) ListSubscriptions(ctx context.Context, orgID, destinationID uuid.UUID) ([]sqlc.AlertSubscription, error) {
	if _, err := s.destination(ctx, orgID, destinationID); err != nil {
		return nil, err
	}
	return s.q.ListAlertSubscriptions(ctx, sqlc.ListAlertSubscriptionsParams{OrgID: orgID, DestinationID: destinationID})
}

// ListDeliveries returns the bounded operator-facing outcome history. Callers
// must project the rows: payload and deduplication details never leave this
// package through an HTTP response.
func (s *ConfigService) ListDeliveries(ctx context.Context, orgID uuid.UUID) ([]sqlc.AlertDelivery, error) {
	return s.q.ListAlertDeliveries(ctx, sqlc.ListAlertDeliveriesParams{OrgID: orgID, Limit: 100})
}

func (s *ConfigService) Create(ctx context.Context, orgID, actor uuid.UUID, in DestinationInput) (sqlc.AlertDestination, error) {
	if s == nil || s.pool == nil || s.sealer == nil {
		return sqlc.AlertDestination{}, fmt.Errorf("alert configuration is not configured")
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	if err := validateDestination(in); err != nil {
		return sqlc.AlertDestination{}, err
	}
	host, err := destinationHost(in)
	if err != nil {
		return sqlc.AlertDestination{}, err
	}
	sealed, err := s.sealer.Seal([]byte(in.Endpoint))
	if err != nil {
		return sqlc.AlertDestination{}, fmt.Errorf("seal alert endpoint: %w", err)
	}
	var row sqlc.AlertDestination
	err = withTx(ctx, s.pool, func(q *sqlc.Queries) error {
		var e error
		row, e = q.CreateAlertDestination(ctx, sqlc.CreateAlertDestinationParams{
			OrgID: orgID, Kind: in.Kind, Name: in.Name, EndpointSealed: []byte(sealed),
			EndpointFingerprint: s.sealer.Fingerprint([]byte(in.Endpoint)), EndpointHost: host,
			AllowPrivate: in.AllowPrivate, SeverityFloor: defaultSeverity(in.SeverityFloor),
			CooldownSeconds: defaultCooldown(in.CooldownSeconds), CreatedByUserID: actor,
		})
		if e != nil {
			return e
		}
		return writeAudit(ctx, q, orgID, actor, "alert.destination_created", "alert_destination", row.ID.String(), map[string]any{
			"kind": row.Kind, "name": row.Name, "endpoint_host": row.EndpointHost,
			"endpoint_fingerprint": row.EndpointFingerprint, "allow_private": row.AllowPrivate,
		})
	})
	return row, err
}

func (s *ConfigService) AddSubscription(ctx context.Context, orgID, destinationID, actor uuid.UUID, key EventKey) error {
	if !knownKey(key) {
		return fmt.Errorf("%w: unknown event key", ErrInvalidDestination)
	}
	return withTx(ctx, s.pool, func(q *sqlc.Queries) error {
		if _, err := q.GetAlertDestination(ctx, sqlc.GetAlertDestinationParams{OrgID: orgID, ID: destinationID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrDestinationNotFound
			}
			return err
		}
		_, err := q.AddAlertSubscription(ctx, sqlc.AddAlertSubscriptionParams{OrgID: orgID, DestinationID: destinationID, EventKey: string(key)})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} // idempotently present
		if err != nil {
			return err
		}
		return writeAudit(ctx, q, orgID, actor, "alert.subscription_added", "alert_destination", destinationID.String(), map[string]any{"event_key": key})
	})
}

// RemoveSubscription is intentionally idempotent. Removing an event from a
// destination changes only future delivery selection; queued deliveries stay
// attributable to the configuration that created them.
func (s *ConfigService) RemoveSubscription(ctx context.Context, orgID, destinationID, actor uuid.UUID, key EventKey) error {
	if !knownKey(key) {
		return fmt.Errorf("%w: unknown event key", ErrInvalidDestination)
	}
	return withTx(ctx, s.pool, func(q *sqlc.Queries) error {
		if _, err := q.GetAlertDestination(ctx, sqlc.GetAlertDestinationParams{OrgID: orgID, ID: destinationID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrDestinationNotFound
			}
			return err
		}
		if _, err := q.RemoveAlertSubscription(ctx, sqlc.RemoveAlertSubscriptionParams{OrgID: orgID, DestinationID: destinationID, EventKey: string(key)}); err != nil {
			return err
		}
		return writeAudit(ctx, q, orgID, actor, "alert.subscription_removed", "alert_destination", destinationID.String(), map[string]any{"event_key": key})
	})
}

// Archive stops future selection of the destination without deleting its
// delivery history. This preserves the audit trail while making the action
// safe to repeat after a browser retry.
func (s *ConfigService) Archive(ctx context.Context, orgID, destinationID, actor uuid.UUID) error {
	return withTx(ctx, s.pool, func(q *sqlc.Queries) error {
		rows, err := q.ArchiveAlertDestination(ctx, sqlc.ArchiveAlertDestinationParams{OrgID: orgID, ID: destinationID})
		if err != nil {
			return err
		}
		if rows == 0 {
			if _, err := q.GetAlertDestination(ctx, sqlc.GetAlertDestinationParams{OrgID: orgID, ID: destinationID}); errors.Is(err, pgx.ErrNoRows) {
				return ErrDestinationNotFound
			}
			return nil
		}
		return writeAudit(ctx, q, orgID, actor, "alert.destination_archived", "alert_destination", destinationID.String(), nil)
	})
}

// Test sends a single synthetic provider-shaped payload and does not enqueue a
// durable production event. Its result is normalized before it reaches a UI so
// a failed test cannot disclose resolver, endpoint, or routing-key details.
func (s *ConfigService) Test(ctx context.Context, orgID, destinationID, actor uuid.UUID) (TestResult, error) {
	if s == nil || s.sender == nil {
		return TestResult{}, fmt.Errorf("alert configuration is not configured")
	}
	destination, err := s.destination(ctx, orgID, destinationID)
	if err != nil {
		return TestResult{}, err
	}
	if destination.ArchivedAt.Valid {
		return TestResult{}, ErrDestinationNotFound
	}
	status, sendErr := s.sender.Send(ctx, destination, []byte(`{"key":"agent.offline","severity":"info","dedup_key":"tunnex.alert.test","subject":"Tunnex alert destination test"}`))
	result := TestResult{Delivered: sendErr == nil, FailureCode: testFailureCode(sendErr, status)}
	if status > 0 {
		result.StatusCode = &status
	}
	if err := withTx(ctx, s.pool, func(q *sqlc.Queries) error {
		return writeAudit(ctx, q, orgID, actor, "alert.destination_tested", "alert_destination", destinationID.String(), map[string]any{
			"delivered": result.Delivered, "status_code": result.StatusCode, "failure_code": result.FailureCode,
		})
	}); err != nil {
		return TestResult{}, err
	}
	return result, nil
}

func testFailureCode(err error, status int32) string {
	return deliveryFailureCode(err, status)
}

func (s *ConfigService) destination(ctx context.Context, orgID, destinationID uuid.UUID) (sqlc.AlertDestination, error) {
	row, err := s.q.GetAlertDestination(ctx, sqlc.GetAlertDestinationParams{OrgID: orgID, ID: destinationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AlertDestination{}, ErrDestinationNotFound
	}
	return row, err
}

func validateDestination(in DestinationInput) error {
	if !knownDestinationKind(in.Kind) || strings.TrimSpace(in.Name) == "" || len(strings.TrimSpace(in.Name)) > 100 {
		return ErrInvalidDestination
	}
	if _, err := destinationHost(in); err != nil {
		return err
	}
	if in.SeverityFloor != "" && in.SeverityFloor != string(SeverityInfo) && in.SeverityFloor != string(SeverityWarning) && in.SeverityFloor != string(SeverityCritical) {
		return ErrInvalidDestination
	}
	if in.CooldownSeconds != 0 && (in.CooldownSeconds < 60 || in.CooldownSeconds > 86400) {
		return ErrInvalidDestination
	}
	return nil
}

// destinationHost validates each provider's write-only credential form and
// derives the only safe read-back field. URLs are used where providers issue a
// webhook URL. PagerDuty and Opsgenie instead take a routing/API key, while
// email takes an RFC address; none are ever returned to a caller.
func destinationHost(in DestinationInput) (string, error) {
	value := strings.TrimSpace(in.Endpoint)
	if value == "" {
		return "", ErrInvalidDestination
	}
	switch in.Kind {
	case "pagerduty":
		if in.AllowPrivate || len(value) > 512 {
			return "", ErrInvalidDestination
		}
		return "events.pagerduty.com", nil
	case "opsgenie":
		if in.AllowPrivate || len(value) > 512 {
			return "", ErrInvalidDestination
		}
		return "api.opsgenie.com", nil
	case "email":
		if in.AllowPrivate {
			return "", ErrInvalidDestination
		}
		address, err := stdmail.ParseAddress(value)
		if err != nil || address.Address != value {
			return "", ErrInvalidDestination
		}
		at := strings.LastIndexByte(address.Address, '@')
		if at <= 0 || at == len(address.Address)-1 {
			return "", ErrInvalidDestination
		}
		return address.Address[at+1:], nil
	default:
		u, err := safedial.ValidateURL(value, in.AllowPrivate)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidDestination, err)
		}
		return u.Host, nil
	}
}

func knownDestinationKind(kind string) bool {
	for _, candidate := range []string{"slack", "teams", "pagerduty", "opsgenie", "discord", "google_chat", "webhook", "email"} {
		if kind == candidate {
			return true
		}
	}
	return false
}

func defaultSeverity(value string) string {
	if value == "" {
		return string(SeverityWarning)
	}
	return value
}
func defaultCooldown(value int32) int32 {
	if value == 0 {
		return 900
	}
	return value
}

func withTx(ctx context.Context, pool *pgxpool.Pool, fn func(*sqlc.Queries) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func writeAudit(ctx context.Context, q *sqlc.Queries, orgID, actor uuid.UUID, action, targetType, targetID string, metadata map[string]any) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true},
		Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

// ParseEndpoint is kept local to this package so callers can never accidentally
// persist a display host taken from unvalidated input.
func ParseEndpoint(raw string, allowPrivate bool) (*url.URL, error) {
	return safedial.ValidateURL(raw, allowPrivate)
}
