package beam

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/beamreadiness"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
)

type DomainSettings struct {
	Version              int64  `json:"version"`
	Source               string `json:"source"`
	OperatorEnabled      bool   `json:"operator_enabled"`
	BaseDomain           string `json:"base_domain"`
	ProxyURL             string `json:"proxy_url"`
	PortalURL            string `json:"portal_url"`
	AffectedActiveShares int64  `json:"affected_active_shares"`
	AuthorityReady       bool   `json:"authority_ready"`
}
type DomainSettingsInput struct {
	ExpectedVersion        int64  `json:"expected_version"`
	OperatorEnabled        bool   `json:"operator_enabled"`
	BaseDomain             string `json:"base_domain"`
	ProxyURL               string `json:"proxy_url"`
	ConfirmEndActiveShares bool   `json:"confirm_end_active_shares"`
}
type installation struct {
	version                               int64
	configured, enabled, passed           bool
	base, proxy, portal, readinessVersion string
	checked, expires                      *time.Time
	checks                                []beamreadiness.Check
}

func (s *Service) SetReadinessInspector(inspector *beamreadiness.Inspector) { s.inspector = inspector }

func (s *Service) ReadinessConfigurationError() error { return s.inspectorError }

func (s *Service) installation(ctx context.Context, q reader) (installation, error) {
	var r installation
	var raw []byte
	if s.pool == nil {
		return r, unavailable()
	}
	e := q.QueryRow(ctx, `SELECT version,configured,operator_enabled,base_domain,proxy_url,portal_url,readiness_version,readiness_passed AND COALESCE(readiness_expires_at>clock_timestamp(),false),readiness_checked_at,readiness_expires_at,readiness_checks FROM beam_installation_settings WHERE singleton`).Scan(&r.version, &r.configured, &r.enabled, &r.base, &r.proxy, &r.portal, &r.readinessVersion, &r.passed, &r.checked, &r.expires, &raw)
	if e != nil {
		return r, unavailable()
	}
	if e = json.Unmarshal(raw, &r.checks); e != nil {
		return r, unavailable()
	}
	if !r.configured {
		r.base, r.proxy, r.portal = s.config.BaseDomain, s.config.ProxyURL, s.config.PortalURL
	}
	return r, nil
}
func (s *Service) probeConfig(r installation) beamreadiness.Config {
	valid := filepath.IsAbs(s.config.RestoreMarker) && (&Service{config: Config{BaseDomain: r.base, ProxyURL: r.proxy, PortalURL: s.config.PortalURL, DomainReady: true, RestoreMarker: s.config.RestoreMarker}}).domainReady()
	c := beamreadiness.Config{BaseDomain: r.base, ProxyURL: r.proxy, PortalURL: s.config.PortalURL, Asserted: r.configured && r.enabled && r.portal == s.config.PortalURL && valid}
	if s.signer != nil {
		c.ConnectorCA = s.signer.CertPEM()
	}
	if s.inspector != nil {
		c.ProbeFingerprint = s.inspector.ProbeFingerprint() + ":" + strconv.FormatInt(r.version, 10) + ":" + s.config.RestoreMarker
	}
	return c
}
func (s *Service) installationReady(r installation) bool {
	c := s.probeConfig(r)
	return s.inspector != nil && c.Asserted && r.passed && r.readinessVersion == beamreadiness.Version(c) && r.expires != nil && r.expires.After(time.Now())
}
func (s *Service) GetDomainSettings(ctx context.Context) (DomainSettings, error) {
	r, e := s.installation(ctx, s.pool)
	if e != nil {
		return DomainSettings{}, e
	}
	safe := beamreadiness.Snapshot(s.probeConfig(r))
	v := DomainSettings{Version: r.version, Source: "environment", OperatorEnabled: r.enabled, BaseDomain: safe.BaseDomain, ProxyURL: safe.ProxyURL, PortalURL: safe.PortalURL, AuthorityReady: s.installationReady(r)}
	if r.configured {
		v.Source = "database"
	}
	e = s.pool.QueryRow(ctx, `SELECT count(*) FROM beam_shares WHERE state IN ('starting','active','paused') AND expires_at>now()`).Scan(&v.AffectedActiveShares)
	return v, e
}
func (s *Service) UpdateDomainSettings(ctx context.Context, actor uuid.UUID, in DomainSettingsInput) (DomainSettings, error) {
	if s.pool == nil {
		return DomainSettings{}, unavailable()
	}
	if in.ExpectedVersion < 1 || len(in.BaseDomain) > 218 || len(in.ProxyURL) > 2048 {
		return DomainSettings{}, invalid("Invalid installation settings")
	}
	if in.OperatorEnabled || in.BaseDomain != "" || in.ProxyURL != "" {
		if !(&Service{config: Config{BaseDomain: in.BaseDomain, ProxyURL: in.ProxyURL, PortalURL: s.config.PortalURL, DomainReady: true}}).domainReady() {
			return DomainSettings{}, invalid("Configure a valid dedicated domain and HTTPS connector endpoint")
		}
	}
	if in.OperatorEnabled && (s.inspector == nil || !filepath.IsAbs(s.config.RestoreMarker)) {
		return DomainSettings{}, invalid("Configure the installation restore barrier and trusted readiness inspector before enabling Beam")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return DomainSettings{}, e
	}
	defer tx.Rollback(ctx)
	var allowed bool
	if e = tx.QueryRow(ctx, `SELECT cp_admin AND status='active' AND deleted_at IS NULL AND email_verified_at IS NOT NULL AND NOT must_change_password FROM users WHERE id=$1`, actor).Scan(&allowed); e != nil || !allowed {
		return DomainSettings{}, deny()
	}
	if _, e = tx.Exec(ctx, `SELECT version FROM beam_installation_settings WHERE singleton FOR UPDATE`); e != nil {
		return DomainSettings{}, e
	}
	r, e := s.installation(ctx, tx)
	if e != nil {
		return DomainSettings{}, e
	}
	if r.version != in.ExpectedVersion {
		return DomainSettings{}, apierr.Conflict("beam_settings_version_conflict", "Installation settings changed; reload before saving")
	}
	if r.configured && r.enabled == in.OperatorEnabled && r.base == in.BaseDomain && r.proxy == in.ProxyURL && r.portal == s.config.PortalURL {
		_ = tx.Rollback(ctx)
		return s.GetDomainSettings(ctx)
	}
	var count int64
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_shares WHERE state IN ('starting','active','paused') AND expires_at>now()`).Scan(&count); e != nil {
		return DomainSettings{}, e
	}
	if count > 0 && !in.ConfirmEndActiveShares {
		return DomainSettings{}, apierr.Conflict("beam_settings_drain_confirmation_required", "Confirm ending active Beam shares before changing installation settings")
	}
	if _, e = tx.Exec(ctx, `UPDATE beam_shares SET state='revoked',certificate_serial=NULL,origin_ready=false,generation=uuid_generate_v7(),version=version+1,authority_version=authority_version+1 WHERE state IN ('starting','active','paused')`); e != nil {
		return DomainSettings{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE beam_installation_settings SET version=version+1,configured=true,operator_enabled=$1,base_domain=$2,proxy_url=$3,portal_url=$4,readiness_version='',readiness_passed=false,readiness_checked_at=NULL,readiness_expires_at=NULL,readiness_checks='[]' WHERE singleton`, in.OperatorEnabled, in.BaseDomain, in.ProxyURL, s.config.PortalURL); e != nil {
		return DomainSettings{}, e
	}
	metadata, _ := json.Marshal(map[string]any{"outcome": "success", "configuration_version": r.version + 1, "shares_ended": count})
	if _, e = tx.Exec(ctx, `INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,metadata)VALUES($1,'beam.installation.updated','beam_installation','singleton',$2)`, actor, metadata); e != nil {
		return DomainSettings{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return DomainSettings{}, e
	}
	return s.GetDomainSettings(ctx)
}
func (s *Service) readinessView(r installation) beamreadiness.View {
	c := s.probeConfig(r)
	v := beamreadiness.Snapshot(c)
	v.SettingsVersion = r.version
	if r.readinessVersion == v.ConfigurationVersion {
		v.CheckedAt = r.checked
		v.ExpiresAt = r.expires
		v.Checks = r.checks
		v.Passed = r.passed && r.expires != nil && r.expires.After(time.Now())
	}
	return v
}
func (s *Service) GetDomainReadiness(ctx context.Context) (beamreadiness.View, error) {
	r, e := s.installation(ctx, s.pool)
	if e != nil {
		return beamreadiness.View{}, e
	}
	return s.readinessView(r), nil
}
func (s *Service) CheckDomainReadiness(ctx context.Context, expected string) (beamreadiness.View, error) {
	r, e := s.installation(ctx, s.pool)
	if e != nil {
		return beamreadiness.View{}, e
	}
	c := s.probeConfig(r)
	if expected != beamreadiness.Version(c) {
		return beamreadiness.View{}, apierr.Conflict("beam_readiness_version_conflict", "Serving configuration changed; reload before checking")
	}
	if s.inspector == nil {
		return beamreadiness.View{}, unavailable()
	}
	v, reason := s.inspector.Check(ctx, c, expected)
	if reason == "busy" {
		return v, apierr.New(429, "beam_readiness_busy", "A readiness check is already running")
	}
	if reason != "" {
		return v, apierr.Conflict("beam_readiness_version_conflict", "Serving configuration changed; reload before checking")
	}
	v.SettingsVersion = r.version
	return s.persistReadiness(ctx, r, v)
}
func (s *Service) persistReadiness(ctx context.Context, observed installation, v beamreadiness.View) (beamreadiness.View, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return v, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT version FROM beam_installation_settings WHERE singleton FOR UPDATE`); e != nil {
		return v, e
	}
	current, e := s.installation(ctx, tx)
	if e != nil {
		return v, e
	}
	if current.version != observed.version || beamreadiness.Version(s.probeConfig(current)) != v.ConfigurationVersion {
		return v, apierr.Conflict("beam_readiness_version_conflict", "Serving configuration changed during checking")
	}
	passed := v.Passed && v.CheckedAt != nil && v.ExpiresAt != nil && v.ExpiresAt.After(time.Now()) && s.probeConfig(current).Asserted
	raw, _ := json.Marshal(v.Checks)
	if _, e = tx.Exec(ctx, `UPDATE beam_installation_settings SET readiness_version=$1,readiness_passed=$2,readiness_checked_at=$3,readiness_expires_at=$4,readiness_checks=$5 WHERE singleton`, v.ConfigurationVersion, passed, v.CheckedAt, v.ExpiresAt, raw); e != nil {
		return v, e
	}
	if e = tx.Commit(ctx); e != nil {
		return v, e
	}
	v.Passed = passed
	return v, nil
}
func (s *Service) RefreshDomainReadiness(ctx context.Context) error {
	r, e := s.installation(ctx, s.pool)
	if e != nil {
		return e
	}
	if !r.configured || !r.enabled || restorebarrier.Check(s.config.RestoreMarker) != nil {
		return nil
	}
	_, e = s.CheckDomainReadiness(ctx, beamreadiness.Version(s.probeConfig(r)))
	return e
}
