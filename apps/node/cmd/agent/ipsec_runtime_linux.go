//go:build linux

package main

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Existing obligations restore refusal synchronously before any WireGuard
// forwarding. New hosts discover opt-in in the background and bind no IKE ports
// until authoritative opt-in is true. There is no local capability override.
func startIPsecRuntime(ctx context.Context, client *control.Client, stateDir string, logger *slog.Logger, dns *ipsec.DNSRuntimeTransport) (func() error, error) {
	dir := filepath.Join(stateDir, "ipsec")
	org, node, err := ipsec.ReadRuntimeJournalIdentity(dir)
	existing := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("IPsec saved refusal unavailable")
	}
	var controller *ipsec.RuntimeController
	diagnostic := ipsecDiagnosticSink(logger, os.Getenv("TUNNEX_IPSEC_DNS_DIAGNOSTICS") == "1")
	construct := func() error {
		environment, e := ipsec.NewRuntimeEnvironmentInspectorWithDiagnostics("/sbin/ip", "/usr/sbin/nft", diagnostic)
		if e != nil {
			return e
		}
		if e = os.Mkdir(dir, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
		controller, e = ipsec.NewRuntimeController(ipsec.RuntimeControllerConfig{OrgID: org, GatewayID: node, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Environment: environment, Diagnostic: diagnostic}, client)
		if e != nil {
			return e
		}
		if e = controller.Start(ctx); e != nil {
			controller.Close()
			controller = nil
			return e
		}
		client.AttachIPsecController(controller)
		dns.Attach(controller)
		return nil
	}
	if existing {
		if err = construct(); err != nil {
			return nil, errors.New("IPsec saved refusal unavailable")
		}
	}
	shutdown := launchIPsecRuntime(ctx, func(ctx context.Context) (result error) {
		var process *ipsec.DaemonProcess
		qualified := false
		bgpQualified := false
		defer func() {
			if process != nil {
				result = errors.Join(result, process.Close())
			}
			if controller != nil {
				result = errors.Join(result, controller.Close())
			}
		}()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			validated := false
			// Read-only observations remain independent of fresh permit maintenance.
			if controller != nil {
				bound := &boundIPsecClient{Client: client, org: org, node: node}
				if control.RefreshIPsecRuntimeStatus(ctx, bound, controller) != nil {
					logger.Warn("ipsec_runtime_observation_refused")
				}
			}
			page, cleanupPending, e := discoverIPsecRuntime(ctx, client)
			if e == nil {
				if controller != nil && (page.OrgID != org || page.NodeID != node) {
					logger.Warn("ipsec_runtime_identity_refused")
					return
				}
				if controller == nil && (page.IPsecEnabled || cleanupPending) {
					org, node = page.OrgID, page.NodeID
					if e = construct(); e != nil {
						logger.Warn("ipsec_runtime_start_refused")
					}
				}
				// Existing cleanup obligations remain serviceable after organization opt-out.
				if controller != nil && (page.IPsecEnabled || cleanupPending) {
					if process == nil {
						process, e = ipsec.StartDaemonProcess(ctx)
						if e == nil {
							if e = controller.AttachDaemon(process.Client, process.Alive); e != nil {
								process.Close()
								process = nil
							}
						}
					}
					if e == nil && process != nil {
						if !qualified && page.IPsecEnabled {
							qualificationStarted := time.Now()
							qualificationStage := "static_probe"
							receipt, probeErr := ipsec.ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", process.Client, process.Alive)
							if probeErr == nil {
								qualificationStage = "static_attach"
								probeErr = controller.AttachQualification(receipt)
							}
							if probeErr == nil {
								qualified = true
							} else {
								logger.Warn("ipsec_runtime_platform_refused", "stage", qualificationStage, "elapsed_ms", time.Since(qualificationStarted).Milliseconds(), "context_done", ctx.Err() != nil)
							}
						}
						if qualified && page.IPsecEnabled && !bgpQualified {
							bgpStarted := time.Now()
							bgpStage, bgpErr := qualifyIPsecRuntimeBGP(ctx, &bgpQualified, func(ctx context.Context) (*bgp.PreflightQualification, error) {
								return bgp.QualifyPreflight(ctx, dir)
							}, controller.AttachBGPQualification)
							if bgpErr != nil {
								logger.Warn("ipsec_runtime_bgp_platform_refused", "stage", bgpStage, "reason", bgp.PreflightRefusalReason(bgpErr), "elapsed_ms", time.Since(bgpStarted).Milliseconds(), "context_done", ctx.Err() != nil)
							}
						}
						// Cleanup remains available without activation qualification; Apply requires
						// the attached current receipt and cannot grant permits without it.
						bound := &boundIPsecClient{Client: client, org: org, node: node}
						if validated, e = control.PollIPsecRuntimeValidated(ctx, bound, controller); e != nil {
							logger.Warn("ipsec_runtime_reconcile_refused")
						}
					} else {
						logger.Warn("ipsec_runtime_daemon_unavailable")
					}
				}
			}
			// Ordinary Apply or unchanged maintenance already proved and committed
			// the complete native guard. Failed, empty and cleanup-only passes still
			// validate independently; CP loss can never extend existing deadlines.
			if controller != nil && !validated {
				if err := controller.Validate(ctx); err != nil {
					logger.Warn("ipsec_runtime_authority_withdrawn")
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	return shutdown, nil
}

type boundIPsecClient struct {
	*control.Client
	org, node uuid.UUID
}

func (c *boundIPsecClient) IPsecPending(ctx context.Context, after *uuid.UUID, limit int) (ipsec.RuntimePendingPage, error) {
	p, e := c.Client.IPsecPending(ctx, after, limit)
	if e != nil || p.OrgID != c.org || p.NodeID != c.node {
		return ipsec.RuntimePendingPage{}, control.ErrIPsecControl
	}
	return p, nil
}
