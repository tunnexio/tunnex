package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
)

func TestOptionalAIUnavailablePreservesHealthyNetworkReadiness(t *testing.T) {
	target, _ := url.Parse("https://control.test:8443")
	ai := aivpn.NewRuntime("missing-test-wg", target, http.DefaultTransport, func() bool { return true }, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer ai.Close()
	ai.SetDesired("10.77.0.9/24")
	ai.Reconcile(t.Context())
	if ready, address := ai.Status(); ready || address != "" {
		t.Fatal("missing AI listener published an endpoint")
	}
	if !agentReady(true, true, false, false, false) {
		t.Fatal("optional AI failure withdrew healthy ordinary VPN")
	}
	if !agentReady(true, true, true, true, true) {
		t.Fatal("optional AI failure withdrew healthy Kubernetes VPN")
	}
	if agentReady(false, true, false, false, false) || agentReady(true, false, false, false, false) || agentReady(true, true, true, false, true) {
		t.Fatal("network readiness lost existing reconcile, endpoint or Kubernetes gates")
	}
}

func TestOptionalAIConfigurationErrorsDoNotAbortNetworkSetup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct{ setting, backend string }{{"", "wgctrl"}, {"false", "wgctrl"}, {"invalid", "wgctrl"}, {"true", "mem"}} {
		// None of these cases may construct an authenticated AI transport;
		// the ordinary networking control client remains independent.
		ai := configureAIVPNRuntime(tc.setting, tc.backend, "wg0", nil, func() bool { return true }, nil, logger)
		if ai != nil {
			t.Fatal("unavailable optional AI runtime was started")
		}
		if !agentReady(true, true, false, false, false) {
			t.Fatal("network setup became unready")
		}
	}
}
