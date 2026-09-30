// Package mailsettings owns deployment-wide, encrypted SMTP overrides.
package mailsettings

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	delivery "github.com/tunnexio/tunnex/apps/api/internal/mail"
)

type View struct {
	Enabled            bool   `json:"enabled"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	From               string `json:"from"`
	Username           string `json:"username"`
	PasswordConfigured bool   `json:"password_configured"`
	Source             string `json:"source"`
	Revision           int64  `json:"revision"`
}
type Update struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	From           string `json:"from"`
	Username       string `json:"username"`
	Revision       int64  `json:"revision"`
	PasswordAction string `json:"password_action"`
	Password       string `json:"password,omitempty"`
}
type Service struct {
	pool     *pgxpool.Pool
	sealer   *crypto.Sealer
	fallback delivery.Config
	logger   *slog.Logger
	send     func(context.Context, delivery.Config, delivery.Message) error
}

func New(pool *pgxpool.Pool, sealer *crypto.Sealer, fallback delivery.Config, logger *slog.Logger) *Service {
	s := &Service{pool: pool, sealer: sealer, fallback: fallback, logger: logger}
	s.send = func(ctx context.Context, cfg delivery.Config, msg delivery.Message) error {
		return delivery.New(cfg, logger).Send(ctx, msg)
	}
	return s
}

type reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Service) load(ctx context.Context, q reader) (delivery.Config, int64, error) {
	var sealed string
	var revision int64
	err := q.QueryRow(ctx, "SELECT config_ciphertext, revision FROM server_email_settings WHERE singleton").Scan(&sealed, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.fallback, 0, nil
	}
	if err != nil {
		return delivery.Config{}, 0, err
	}
	raw, err := s.sealer.Open(sealed)
	if err != nil {
		return delivery.Config{}, 0, errors.New("email configuration could not be decrypted")
	}
	var cfg delivery.Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return delivery.Config{}, 0, errors.New("email configuration is invalid")
	}
	return cfg, revision, nil
}
func viewOf(cfg delivery.Config, revision int64) View {
	port, _ := strconv.Atoi(cfg.Port)
	if port == 0 {
		port = 587
	}
	source := "installer"
	if revision > 0 {
		source = "server"
	}
	return View{Enabled: delivery.Configured(cfg), Host: cfg.Host, Port: port, From: cfg.From, Username: cfg.Username, PasswordConfigured: cfg.Password != "", Source: source, Revision: revision}
}
func (s *Service) Get(ctx context.Context) (View, error) {
	cfg, rev, err := s.load(ctx, s.pool)
	return viewOf(cfg, rev), err
}
func (s *Service) Configured(ctx context.Context) (bool, error) {
	cfg, _, err := s.load(ctx, s.pool)
	return delivery.Configured(cfg), err
}
func (s *Service) Kind() string { return "managed-smtp" }
func (s *Service) Send(ctx context.Context, msg delivery.Message) error {
	cfg, _, err := s.load(ctx, s.pool)
	if err != nil {
		return errors.New("email configuration unavailable")
	}
	return s.send(ctx, cfg, msg)
}
func invalid(message string) error { return apierr.BadRequest("smtp_settings_invalid", message) }
func prepare(old delivery.Config, in Update) (delivery.Config, error) {
	if in.Revision < 0 {
		return delivery.Config{}, invalid("Reload email settings before saving.")
	}
	cfg := delivery.Config{Host: strings.TrimSpace(in.Host), Port: strconv.Itoa(in.Port), From: strings.TrimSpace(in.From), Username: strings.TrimSpace(in.Username), DevLogging: old.DevLogging}
	switch in.PasswordAction {
	case "keep":
		if in.Password != "" {
			return cfg, invalid("Choose Replace password to enter a new password.")
		}
		if old.Password != "" && (cfg.Host != old.Host || cfg.Username != old.Username) {
			return cfg, invalid("Replace or clear the saved password when changing the SMTP server or username.")
		}
		cfg.Password = old.Password
	case "replace":
		if in.Password == "" || len(in.Password) > 4096 {
			return cfg, invalid("Enter the new SMTP password.")
		}
		cfg.Password = in.Password
	case "clear":
		if in.Password != "" {
			return cfg, invalid("A password cannot be supplied with Clear password.")
		}
	default:
		return cfg, invalid("Choose Keep, Replace or Clear password.")
	}
	if strings.IndexFunc(cfg.Username, unicode.IsControl) >= 0 || len(cfg.Username) > 320 {
		return cfg, invalid("Enter a valid SMTP username.")
	}
	cfg.Disabled = !in.Enabled
	if !in.Enabled {
		return cfg, nil
	}
	host := cfg.Host
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/\\@?# \t\r\n") {
		return cfg, invalid("Enter an SMTP hostname or IP address without a scheme or port.")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return cfg, invalid("Enter a valid SMTP hostname.")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return cfg, invalid("Enter a valid SMTP hostname.")
				}
			}
		}
	}
	if in.Port < 1 || in.Port > 65535 || in.Port == 465 {
		return cfg, invalid("Use a STARTTLS port, usually 587. Implicit TLS on port 465 is not supported.")
	}
	address, err := mail.ParseAddress(cfg.From)
	if err != nil || address.Address != cfg.From || strings.ContainsAny(cfg.From, "\r\n") {
		return cfg, invalid("Enter a sender email address without a display name.")
	}
	return cfg, nil
}
func audit(ctx context.Context, tx pgx.Tx, actor uuid.UUID, action string, metadata map[string]any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	targetType, targetID := "server_email_settings", "deployment"
	_, err = sqlc.New(tx).InsertAuditLog(ctx, sqlc.InsertAuditLogParams{ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: raw})
	return err
}
func (s *Service) Save(ctx context.Context, actor uuid.UUID, in Update) (View, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return View{}, err
	}
	defer tx.Rollback(ctx)
	// Serializes even the initially absent singleton; the revision still rejects stale forms.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(164092901)"); err != nil {
		return View{}, err
	}
	current, rev, err := s.load(ctx, tx)
	if err != nil {
		return View{}, err
	}
	if rev != in.Revision {
		return View{}, apierr.Conflict("smtp_settings_changed", "Email settings changed. Reload them before saving.")
	}
	cfg, err := prepare(current, in)
	if err != nil {
		return View{}, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return View{}, err
	}
	sealed, err := s.sealer.Seal(raw)
	if err != nil {
		return View{}, err
	}
	rev++
	_, err = tx.Exec(ctx, `INSERT INTO server_email_settings(singleton,revision,config_ciphertext) VALUES(true,$1,$2)
 ON CONFLICT(singleton) DO UPDATE SET revision=EXCLUDED.revision,config_ciphertext=EXCLUDED.config_ciphertext,updated_at=clock_timestamp()`, rev, sealed)
	if err != nil {
		return View{}, err
	}
	if err = audit(ctx, tx, actor, "server.email_settings_updated", map[string]any{"revision": rev, "enabled": in.Enabled, "password_action": in.PasswordAction}); err != nil {
		return View{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return View{}, err
	}
	return viewOf(cfg, rev), nil
}
func (s *Service) Test(ctx context.Context, actor uuid.UUID, email string, in Update) error {
	current, rev, err := s.load(ctx, s.pool)
	if err != nil {
		return err
	}
	if rev != in.Revision {
		return apierr.Conflict("smtp_settings_changed", "Email settings changed. Reload them before testing.")
	}
	if !in.Enabled {
		return invalid("Enable email delivery in this form before sending a test.")
	}
	cfg, err := prepare(current, in)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(164092902)"); err != nil {
		return err
	}
	var recent bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE action='server.email_test_requested' AND actor_user_id=$1 AND created_at>clock_timestamp()-interval '30 seconds')`, actor).Scan(&recent); err != nil {
		return err
	}
	if recent {
		return apierr.New(429, "smtp_test_rate_limited", "Wait 30 seconds before sending another test email.")
	}
	if err = audit(ctx, tx, actor, "server.email_test_requested", map[string]any{"revision": rev}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = s.send(testCtx, cfg, delivery.Message{To: email, Subject: "Tunnex email delivery test", Text: "Your SMTP server accepted a test requested from Tunnex Server Settings. This test does not change your saved email settings."}); err != nil {
		return apierr.New(502, "smtp_test_failed", "The SMTP server did not accept the test. Check the host, STARTTLS port, sender and credentials. Saved settings were not changed.")
	}
	return nil
}
