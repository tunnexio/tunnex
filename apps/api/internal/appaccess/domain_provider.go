package appaccess

import (
	"context"
	"net/url"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

type DomainProvider interface {
	Effective(context.Context) (appdomains.Config, error)
}

// WithDomainProvider wires deployment authority once, before the service is shared.
func (s *Service) WithDomainProvider(provider DomainProvider) *Service {
	s.domains = provider
	return s
}
func (s *Service) effectiveDomains(ctx context.Context) (*Service, error) {
	if s.domains == nil {
		return s, nil
	}
	cfg, err := s.domains.Effective(ctx)
	if err != nil {
		return nil, apierr.New(503, "app_domains_unavailable", "App Access domain settings are unavailable.")
	}
	return domainService(cfg)
}
func domainService(cfg appdomains.Config) (*Service, error) {
	portal, err := url.Parse(cfg.PortalURL)
	if err != nil {
		return nil, apierr.New(503, "app_domains_unavailable", "App Access domain settings are unavailable.")
	}
	effective := NewService(nil, Config{AppBaseDomain: cfg.AppBaseDomain, ConsoleURL: cfg.PortalURL, ConsoleHosts: []string{portal.Hostname()}})
	return effective, nil
}
func (s *Service) domainConfigured(ctx context.Context) bool {
	configured, err := s.effectiveDomains(ctx)
	return err == nil && configured.domainReady
}
func (s *Service) publicationDomainReadyContext(ctx context.Context) bool {
	configured, err := s.effectiveDomains(ctx)
	return err == nil && configured.publicationDomainReady()
}
func directChild(host, base string) bool {
	suffix := "." + base
	return strings.HasSuffix(host, suffix) && !strings.Contains(strings.TrimSuffix(host, suffix), ".") && len(host) > len(suffix)
}
func (s *Service) validateCurrent(ctx context.Context, input DraftInput, existingHost string) (DraftInput, string, error) {
	configured, err := s.effectiveDomains(ctx)
	if err != nil {
		return input, "", err
	}
	return configured.validateWithExistingHost(input, existingHost)
}

// ProxyDomains supplies trusted live redirect/domain configuration only to a
// currently authenticated proxy and an available installation authority.
func (s *Service) ProxyDomains(ctx context.Context, proxy AuthenticatedProxy) (appdomains.Config, error) {
	if err := s.currentProxy(ctx, proxy); err != nil {
		return appdomains.Config{}, err
	}
	if _, err := s.installationGeneration(ctx); err != nil {
		return appdomains.Config{}, err
	}
	if s.domains != nil {
		return s.domains.Effective(ctx)
	}
	return appdomains.Config{PortalURL: s.config.ConsoleURL, AppBaseDomain: s.config.AppBaseDomain}, nil
}

// Transaction-bound operations reuse their checked-out connection. A provider
// without transactional support is intended only for pure validation fixtures.
func (s *Service) effectiveDomainsWithQueries(ctx context.Context, q *sqlc.Queries) (*Service, error) {
	if provider, ok := s.domains.(interface {
		EffectiveWithQueries(context.Context, *sqlc.Queries) (appdomains.Config, error)
	}); ok {
		cfg, err := provider.EffectiveWithQueries(ctx, q)
		if err != nil {
			return nil, apierr.New(503, "app_domains_unavailable", "App Access domain settings are unavailable.")
		}
		return domainService(cfg)
	}
	return s.effectiveDomains(ctx)
}
func (s *Service) domainConfiguredWithQueries(ctx context.Context, q *sqlc.Queries) bool {
	cfg, err := s.effectiveDomainsWithQueries(ctx, q)
	return err == nil && cfg.domainReady
}
func (s *Service) publicationDomainReadyWithQueries(ctx context.Context, q *sqlc.Queries) bool {
	cfg, err := s.effectiveDomainsWithQueries(ctx, q)
	return err == nil && cfg.publicationDomainReady()
}
