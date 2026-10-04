// Package appdomains owns deployment-wide browser address configuration.
package appdomains

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"golang.org/x/net/publicsuffix"
)

type Config struct{ PortalURL, AppBaseDomain string }
type View struct {
	Config
	Version            int64
	Source             string
	ConfigurationReady bool
}
type Update struct {
	PortalURL, AppBaseDomain string
	ExpectedVersion          int64
}
type Service struct {
	pool     *pgxpool.Pool
	fallback Config
}

func New(pool *pgxpool.Pool, fallback Config) *Service {
	return &Service{pool: pool, fallback: fallback}
}

type reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Service) load(ctx context.Context, q reader) (Config, int64, error) {
	var cfg Config
	var version int64
	err := q.QueryRow(ctx, `SELECT portal_url, app_base_domain, version FROM app_access_domain_settings WHERE singleton`).Scan(&cfg.PortalURL, &cfg.AppBaseDomain, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.fallback, 0, nil
	}
	return cfg, version, err
}
func view(cfg Config, version int64) View {
	source := "environment"
	if version > 0 {
		source = "database"
	}
	_, err := Normalize(cfg)
	return View{Config: cfg, Version: version, Source: source, ConfigurationReady: err == nil}
}
func (s *Service) Get(ctx context.Context) (View, error) {
	cfg, v, e := s.load(ctx, s.pool)
	return view(cfg, v), e
}

// Effective never falls back after a database failure; all replicas read one authority.
func (s *Service) Effective(ctx context.Context) (Config, error) {
	cfg, _, e := s.load(ctx, s.pool)
	return cfg, e
}
func invalid(message string) error { return apierr.BadRequest("app_domains_invalid", message) }

// Host is an exact ASCII DNS hostname, without scheme, wildcard, port or suffix dot.
func Host(host string) bool {
	if len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Boundary accepts independent sites, or the explicitly supported portal-parent
// topology. Arbitrary sibling applications on the console site stay prohibited.
func Boundary(portalHost, base string) bool {
	if !Host(base) {
		return false
	}
	if portalHost == base {
		return true
	}
	if net.ParseIP(portalHost) != nil || portalHost == "localhost" {
		return true
	}
	if !Host(portalHost) {
		return false
	}
	a, e1 := publicsuffix.EffectiveTLDPlusOne(portalHost)
	b, e2 := publicsuffix.EffectiveTLDPlusOne(base)
	return e1 == nil && e2 == nil && a != b
}

// Normalize validates address configuration only. DNS, certificate coverage and
// public/private reachability still require the independent publication probes.
func Normalize(in Config) (Config, error) {
	cfg := Config{PortalURL: strings.TrimSpace(in.PortalURL), AppBaseDomain: strings.ToLower(strings.TrimSpace(in.AppBaseDomain))}
	u, err := url.Parse(cfg.PortalURL)
	if err != nil || len(cfg.PortalURL) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(cfg.PortalURL, "#\\\r\n\t ") {
		return cfg, invalid("Enter an HTTPS portal URL without a path, credentials, query or fragment.")
	}
	host := strings.ToLower(u.Hostname())
	if !Host(host) && net.ParseIP(host) == nil {
		return cfg, invalid("Enter a valid portal hostname or IP address.")
	}
	canonical := host
	if strings.Contains(host, ":") {
		canonical = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return cfg, invalid("Enter a valid HTTPS portal port.")
		}
		canonical += ":" + p
	}
	if strings.ToLower(u.Host) != canonical {
		return cfg, invalid("Enter a canonical portal address.")
	}
	if !Boundary(host, cfg.AppBaseDomain) {
		return cfg, invalid("Use the portal hostname as the app base domain, or an independent app domain.")
	}
	_, icann := publicsuffix.PublicSuffix(cfg.AppBaseDomain)
	if _, e := publicsuffix.EffectiveTLDPlusOne(cfg.AppBaseDomain); e != nil || !icann {
		return cfg, invalid("Enter a public DNS app base domain without a wildcard or port.")
	}
	if net.ParseIP(host) == nil {
		if _, icann = publicsuffix.PublicSuffix(host); !icann {
			return cfg, invalid("Enter a public DNS portal hostname or IP address.")
		}
	}
	cfg.PortalURL = "https://" + canonical
	return cfg, nil
}
func (s *Service) Save(ctx context.Context, actor uuid.UUID, in Update) (View, error) {
	if in.ExpectedVersion < 0 || actor == uuid.Nil {
		return View{}, invalid("Reload domain settings before saving.")
	}
	cfg, err := Normalize(Config{PortalURL: in.PortalURL, AppBaseDomain: in.AppBaseDomain})
	if err != nil {
		return View{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return View{}, err
	}
	defer tx.Rollback(ctx)
	// Serialize the absent initial singleton too; stale form saves still fail.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(175100401)"); err != nil {
		return View{}, err
	}
	_, version, err := s.load(ctx, tx)
	if err != nil {
		return View{}, err
	}
	if version != in.ExpectedVersion {
		return View{}, apierr.Conflict("app_domains_changed", "Domain settings changed. Reload them before saving.")
	}
	// Serialize hostname reservations against changing the portal authority.
	if _, err = tx.Exec(ctx, "LOCK TABLE app_access_hostnames IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return View{}, err
	}
	portal, _ := url.Parse(cfg.PortalURL)
	var reserved bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM app_access_hostnames WHERE hostname=$1)", portal.Hostname()).Scan(&reserved); err != nil {
		return View{}, err
	}
	if reserved {
		return View{}, apierr.Conflict("portal_hostname_reserved", "This portal hostname is already reserved for an application. Choose a different portal hostname.")
	}
	version++
	_, err = tx.Exec(ctx, `INSERT INTO app_access_domain_settings(singleton,version,portal_url,app_base_domain) VALUES(true,$1,$2,$3) ON CONFLICT(singleton) DO UPDATE SET version=EXCLUDED.version,portal_url=EXCLUDED.portal_url,app_base_domain=EXCLUDED.app_base_domain,updated_at=clock_timestamp()`, version, cfg.PortalURL, cfg.AppBaseDomain)
	if err != nil {
		return View{}, err
	}
	targetType, targetID := "app_access_domain_settings", "deployment"
	metadata, _ := json.Marshal(map[string]any{"version": version, "portal_url": cfg.PortalURL, "app_base_domain": cfg.AppBaseDomain})
	_, err = sqlc.New(tx).InsertAuditLog(ctx, sqlc.InsertAuditLogParams{ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: "app_access.domains_updated", TargetType: &targetType, TargetID: &targetID, Metadata: metadata})
	if err != nil {
		return View{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return View{}, err
	}
	return view(cfg, version), nil
}

// EffectiveWithQueries uses the caller's transaction/connection, so authority
// reads inside an app operation never wait for a second pooled connection.
func (s *Service) EffectiveWithQueries(ctx context.Context, q *sqlc.Queries) (Config, error) {
	row, err := q.GetAppAccessDomainSettings(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.fallback, nil
	}
	return Config{PortalURL: row.PortalUrl, AppBaseDomain: row.AppBaseDomain}, err
}
