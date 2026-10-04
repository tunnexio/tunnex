package control

import (
	"context"
	"fmt"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
)

func (a *AppAccessClient) BrowserCapability(ctx context.Context) error {
	return a.rpc(ctx, "POST", "/agent/app-access/browser-capability", struct {
		ProtocolVersion int `json:"protocol_version"`
	}{1}, nil)
}
func (a *AppAccessClient) BrowserDesired(ctx context.Context) (authoritywire.AppProxyBrowserDesired, error) {
	var out authoritywire.AppProxyBrowserDesired
	err := a.rpc(ctx, "GET", "/agent/app-access/browser-desired-state", nil, &out)
	if err != nil {
		return out, err
	}
	if out.ProtocolVersion != 1 || out.Purpose != "browser_proxy" || out.Assignments == nil || len(out.Assignments) > 64 || (out.Withdrawn && len(out.Assignments) != 0) {
		return out, fmt.Errorf("browser desired state refused")
	}
	return out, nil
}

// BrowserWithdrawn retains the narrow withdrawal assertion for callers requiring it.
func (a *AppAccessClient) BrowserWithdrawn(ctx context.Context) error {
	out, err := a.BrowserDesired(ctx)
	if err != nil {
		return err
	}
	if !out.Withdrawn {
		return fmt.Errorf("browser desired state refused")
	}
	return nil
}
