package appaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

type domainProviderStub struct {
	config appdomains.Config
	err    error
}

func (d *domainProviderStub) Effective(context.Context) (appdomains.Config, error) {
	return d.config, d.err
}
func TestDynamicDomainValidationPreservesOwnedHostname(t *testing.T) {
	ctx := context.Background()
	provider := &domainProviderStub{config: appdomains.Config{PortalURL: "https://internal.tunnex.app", AppBaseDomain: "internal.tunnex.app"}}
	s := NewService(nil, Config{AppBaseDomain: "old.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"}).WithDomainProvider(provider)
	input := DraftInput{Name: "Payroll", OriginURL: "http://origin", GatewayID: uuid.New(), PublicHostname: "payroll.internal.tunnex.app", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	if _, _, err := s.validateCurrent(ctx, input, ""); err != nil || !s.publicationDomainReadyContext(ctx) {
		t.Fatal("parent portal unavailable", err)
	}
	for _, host := range []string{"nested.payroll.internal.tunnex.app", "internal.tunnex.app", "payroll.old.example.net"} {
		input.PublicHostname = host
		if _, _, err := s.validateCurrent(ctx, input, ""); err == nil {
			t.Fatal("accepted new invalid host", host)
		}
	}
	input.PublicHostname = "payroll.old.example.net"
	if _, _, err := s.validateCurrent(ctx, input, input.PublicHostname); err != nil {
		t.Fatal("existing hostname lost after base change", err)
	}
	input.PublicHostname = "internal.tunnex.app"
	if _, _, err := s.validateCurrent(ctx, input, input.PublicHostname); err == nil {
		t.Fatal("existing host bypassed portal isolation")
	}
	provider.err = errors.New("database unavailable")
	if _, _, err := s.validateCurrent(ctx, input, ""); err == nil || s.publicationDomainReadyContext(ctx) || s.domainConfigured(ctx) {
		t.Fatal("database failure used stale environment")
	}
}
