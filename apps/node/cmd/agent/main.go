// Command agent is the tunnex-node data-plane agent (S3.1).
//
// On boot it enrolls (join token -> mTLS cert) if it has no cert yet, then runs
// the reconcile loop against the control plane's desired state. The WireGuard
// backend is in-memory in S3.1; the real wgctrl device lands in S3.2.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/identity"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/ovpnserver"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

const protocolVersion = 1

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	apiURL := getenv("TUNNEX_API_URL", "http://api:8080")
	agentURL := getenv("TUNNEX_AGENT_URL", "https://api:8443")
	serverName := getenv("TUNNEX_AGENT_SERVERNAME", "tunnex-control")
	joinToken := os.Getenv("TUNNEX_JOIN_TOKEN")
	nodeName := getenv("TUNNEX_NODE_NAME", hostname())
	certDir := getenv("TUNNEX_NODE_STATE_DIR", "/var/lib/tunnex-node")
	healthAddr := getenv("TUNNEX_AGENT_HEALTH_ADDR", ":9091")

	var ready, keyReported atomic.Bool
	go serveHealth(healthAddr, &ready, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	stored := loadStored(certDir)
	certPEM, keyPEM, caPEM := stored.CertPEM, stored.KeyPEM, stored.CAPEM

	// S13.1: the stored-identity-vs-join-token decision is a PURE FUNCTION (internal/identity), not an inline
	// branch. It used to be one, and it was wrong in the case that matters most: an EXPIRED stored certificate
	// was preferred over a valid join token the operator had just supplied, so the agent looped forever on
	// `tls: expired certificate` — /agent/renew requires the certificate that expired (EPIC 11 WF-S11-11). The
	// safe direction is always the stored identity; the function narrows that preference to the cases where the
	// stored identity can still work, and cites the evidence for every determination.
	verdict := identity.Decide(stored, nodeName, joinToken != "", time.Now())

	// WF-S11-11b: report the identity actually IN USE, not the one requested. `nodeName` came from
	// TUNNEX_NODE_NAME and was never reconciled with the certificate, so a wrong-host run printed the requested
	// name while reusing a different gateway's identity — the diagnostic hid the very fact it exists to show.
	nodeName = identity.EffectiveName(verdict, nodeName)

	switch verdict.Action {
	case identity.Recover:
		// S13.1 (review #2): RE-KEY FIRST, token second. Proof of possession recovers this node IN PLACE — same id,
		// same site binding, same devices — where a token enrolment creates a new node and discards all three. The
		// trigger is local: identity.Decide reached this verdict from this agent's own clock against its own stored
		// certificate, with no network call, so a transient outage cannot land here.
		c, k, ca, outcome := attemptRekey(ctx, logger, apiURL, certDir, certPEM, keyPEM, caPEM, nodeName,
			verdict.HaveToken)
		switch outcome {
		case rekeyRecovered:
			certPEM, keyPEM, caPEM = c, k, ca
			nodeName = identity.EffectiveName(identity.Decide(identity.Stored{CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM}, nodeName, false, time.Now()), nodeName)

		case rekeyNotNeeded:
			// The CLOCK was wrong, not the credential. Keep the stored identity and carry on as if this had never
			// been entered — which is what a corrected clock means.

		case rekeyCancelled:
			// SHUTDOWN IS NOT A REFUSAL. This path used to report "re-key was refused and no join token is
			// available" on a SIGTERM, and with a token it started an enrolment on an already-cancelled context. An
			// operator reading the logs of a normal restart was told their gateway was unrecoverable.
			logger.Info("agent_rekey_interrupted", slog.String("reason", "shutting down"))
			return

		default: // rekeyExhausted or rekeyImpossible — the join token is the documented remedy
			if !verdict.HaveToken {
				logger.Error("agent_unrecoverable",
					slog.String("reason", "re-key was refused and no join token is available"),
					slog.String("remedy", "mint a join token in the control plane and restart this agent with "+
						"TUNNEX_JOIN_TOKEN set"))
				<-ctx.Done()
				return
			}
			logger.Warn("agent_falling_back_to_join_token",
				slog.String("note", "re-key did not succeed; enrolling with the join token. This creates a NEW "+
					"node: its site binding must be re-applied and devices homed on the old node need re-issuing"))
			tc, tk, tca, ok := enrollWithToken(ctx, logger, apiURL, certDir, joinToken, nodeName)
			if !ok {
				// DO NOT EXIT. An enrolment refusal (a name still held by this node's own expired row, a consumed
				// token, a CP mid-restart) is a condition a control-plane change can resolve, and exiting forfeits
				// the reconciliation that would have fixed it — turning a recoverable state into CrashLoopBackOff.
				<-ctx.Done()
				return
			}
			certPEM, keyPEM, caPEM = tc, tk, tca
		}

	case identity.Idle:
		// Liveness stays up, readiness stays false. LOUD, and naming the remedy rather than the condition.
		logger.Error("agent_no_usable_identity",
			slog.String("reason", verdict.Reason),
			slog.String("remedy", verdict.Evidence),
			slog.String("state_dir", certDir))
		<-ctx.Done()
		return

	case identity.UseToken:
		logger.Info("agent_enrolling",
			slog.String("node_name", nodeName),
			slog.String("reason", verdict.Reason),
			slog.String("evidence", verdict.Evidence))
		if verdict.StoredCN != "" {
			logger.Warn("agent_replacing_unusable_identity",
				slog.String("stored_cn", verdict.StoredCN),
				slog.String("enrolling_as", nodeName),
				slog.Bool("name_mismatch", verdict.NameMismatch))
		}
		c, k, ca, ok := enrollWithToken(ctx, logger, apiURL, certDir, joinToken, nodeName)
		if !ok {
			// Same reasoning as the Recover fallback: never exit on a condition the control plane can resolve.
			<-ctx.Done()
			return
		}
		certPEM, keyPEM, caPEM = c, k, ca

	case identity.UseStored:
		// WF-2 (S8.2c) protection, intact: a re-used VM keeps its OLD identity and org rather than silently
		// adopting a new one. Still named LOUD at boot, and now it names the identity it KEPT.
		lg := logger.Warn
		if verdict.NameMismatch {
			// A valid certificate for a DIFFERENT node than requested is almost always operator error — a
			// mis-set env var, a cloned image, or a command run on the wrong host. ERROR, because the operator
			// asked for something that is not happening, and the agent will not resolve it for them.
			lg = logger.Error
		}
		lg("agent_reusing_stored_identity",
			slog.String("state_dir", certDir),
			slog.String("stored_cn", verdict.StoredCN),
			slog.String("reason", verdict.Reason),
			slog.Bool("name_mismatch", verdict.NameMismatch),
			slog.String("note", verdict.Evidence))
	}

	client, err := control.NewClient(agentURL, serverName, nodeName, certPEM, keyPEM, caPEM)
	if err != nil {
		logger.Error("agent_client_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// WireGuard key: generated locally and persisted; the private key never
	// leaves the node. Re-key = delete the file -> a new key is generated and its
	// pubkey re-reported.
	wgPriv, wgPub, err := loadOrCreateWGKey(filepath.Join(certDir, "wg.key"))
	if err != nil {
		logger.Error("agent_wg_key_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// Report the WG public key + public endpoint to the control plane, retrying
	// until it lands. A one-shot best-effort call could leave the control plane
	// without our key (transient boot-time error) while the agent still went
	// ready — a silent data-plane hole. Readiness is gated on keyReported below,
	// so we never advertise ready until the control plane actually holds our key.
	// The endpoint (host:port peer configs dial) is operator-provided; it cannot
	// be discovered from inside the container.
	wgEndpoint := os.Getenv("TUNNEX_NODE_ENDPOINT")
	// egressNAT holds whether this gateway can source-NAT full-tunnel egress (S3.7),
	// probed by the egress loop and reported to the control plane so it can refuse
	// full-tunnel devices against a no-egress gateway (gateway_no_egress).
	var egressNAT atomic.Bool
	var egressIPv6 atomic.Bool

	// Backend selection: "wgctrl" drives a real WireGuard device (Linux + NET_ADMIN,
	// used in compose/prod); anything else uses the in-memory backend (dev/CI).
	wgBackend := getenv("TUNNEX_WG_BACKEND", "mem")
	wgIface := getenv("TUNNEX_WG_INTERFACE", "wg0")

	// Egress NAT + forwarding (S3.7): probe+arm ONCE synchronously so the very first
	// capability report is accurate (not a spurious egress_nat=false for one interval —
	// review #6), then reconcile on an interval (heals a flushed table). Torn down on
	// shutdown (full-sweep). No-op / not-capable off Linux.
	egressMgr := egress.New(wgIface)
	defer egressMgr.Teardown(context.Background())
	// S8.4: the in-agent cross-site DNS forwarder. Serve is best-effort — a bind/serve fault must NEVER
	// affect the tunnel (DNS-down ≠ tunnel-down, D2/D5). The table is (re)programmed from every policy.
	dnsFwd := dnsforward.New(logger, nil)
	go func() {
		if err := dnsFwd.Serve(ctx, wgIface); err != nil {
			logger.Warn("dns_forward_serve_failed", slog.String("error", err.Error())) // convenience: log, never fail the agent
		}
	}()
	// S7.5.1 flow logging is OPT-IN per gateway: TUNNEX_FLOWLOG_GROUP>0 arms the forward-chain
	// nflog rules (set BEFORE the first Reconcile so the log clauses render from the start) and
	// the reader+drain below. 0 = OFF (the forward chain is byte-identical to pre-S7.5.1).
	flowGroup := getint("TUNNEX_FLOWLOG_GROUP", 0)
	if flowGroup > 0 {
		egressMgr.SetFlowLogGroup(flowGroup)
	}
	if ok, ok6, err := egressMgr.Reconcile(ctx); err != nil {
		logger.Warn("egress_initial_degraded", slog.String("error", err.Error()))
		egressNAT.Store(ok)
		egressIPv6.Store(ok6)
	} else {
		egressNAT.Store(ok)
		egressIPv6.Store(ok6)
	}
	// policyKick wakes the egress loop IMMEDIATELY when a desired-state fetch carries a
	// changed policy — enforcement rides the push path (<5s revocation spec), not the
	// egress interval. Buffered(1) + non-blocking send: coalesces bursts, never stalls
	// the reconcile loop.
	policyKick := make(chan struct{}, 1)

	// S10.3 WF-K5: a K8s gateway reads READY pod endpoints from a read-only in-cluster EndpointSlice+Service
	// watch and DNATs each exposed VIP straight to a ready pod (VIP->ClusterIP can NOT complete — netfilter
	// applies one dst-NAT per prerouting pass, so kube-proxy's second DNAT is a no-op; the box-walk finding).
	// The watch KICKS the egress reconcile on every endpoint change (watch-driven, not polled), so a pod
	// restart re-renders the DNAT within the watch latency. A non-cluster gateway gets (nil,nil) → no source
	// → no VIP DNAT (fail-closed, and it has no VIP mappings anyway). SetEndpointSource runs BEFORE egressLoop
	// starts (source is set-once-before-use — egressLoop is the only reader, via ResolveK8sVIPs — so no race).
	epw, epwErr := egress.NewInClusterWatcher(logger, func() {
		select {
		case policyKick <- struct{}{}:
		default: // a kick is already pending — the reconcile reads the latest endpoint view anyway
		}
	})
	if epwErr != nil {
		logger.Warn("k8s_endpoint_watch_unavailable", slog.String("error", epwErr.Error())) // in-cluster but mis-wired → fail-closed (no DNAT), surfaced loud
	} else if epw != nil {
		egressMgr.SetEndpointSource(epw)
	}
	go egressLoop(ctx, egressMgr, &egressNAT, &egressIPv6, getdur("TUNNEX_AGENT_EGRESS_INTERVAL", 30*time.Second), policyKick, logger)
	if epw != nil {
		go epw.Run(ctx)
	}

	reportEvery := getdur("TUNNEX_AGENT_REPORT_INTERVAL", 30*time.Second)
	// H5: the reconciler writes site-link staleness here each tick; the report loop reads it. Shared
	// because the report loop starts before the reconciler exists.
	var siteLinkStale, siteSubnetUnreachable atomic.Bool
	// S9.1 4d: the OVPN server's refuse-loudly health kind, written by the OnOVPN handler each tick and
	// read by the report loop — same shared-sink pattern (the report loop predates the OVPN manager).
	var ovpnHealth atomic.Pointer[string]
	go reportKeyLoop(ctx, client, wgPub, wgEndpoint, &egressNAT, &egressIPv6, egressMgr, &siteLinkStale, &siteSubnetUnreachable, &ovpnHealth, &keyReported, reportEvery, logger)

	backend, err := reconcile.SelectBackend(wgBackend, wgIface, logger)
	if err != nil {
		logger.Error("agent_backend_failed", slog.String("backend", wgBackend), slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("agent_backend_selected", slog.String("backend", wgBackend), slog.String("interface", wgIface))
	// WF-C Layer 1: tear the WG interface DOWN on graceful shutdown — the symmetric destroy for the
	// interface Configure creates. Without it, `--network host` wg0 outlives the container on `docker stop`
	// and forwards headless (zombie hub / failover-blind). Idempotent. (A hard SIGKILL skips this defer —
	// that residue is WF-C Layer 2, a separate liveness-model paper.)
	defer func() { _ = backend.Close(context.Background()) }()
	r := reconcile.New(backend, wgPriv, wgPub, logger)
	r.SetSiteLinkStaleSink(&siteLinkStale)
	r.SetSiteSubnetUnreachableSink(&siteSubnetUnreachable) // D3: unreachable-advertised-subnet health signal
	r.SetForwardBlockedFn(egressMgr.ForwardBlocked)        // WF-4: Docker FORWARD DROP swallowing the forward → same signal
	// Every desired-state fetch hands the compiled Zero Trust policy (nil = legacy
	// mesh) to the egress manager and kicks an immediate forward-chain re-apply.
	r.OnPolicy(func(p *nodepolicy.Compiled) {
		egressMgr.SetPolicy(p)
		dnsFwd.SetTable(dnsEntriesFrom(p))      // S8.4: reprogram the forwarding table (nil policy → empty → serves nothing)
		dnsFwd.SetK8sAnswers(k8sAnswersFrom(p)) // S10.3 A1: reprogram the K8s direct-answer set (nil policy → empty → answers nothing)
		select {
		case policyKick <- struct{}{}:
		default: // a kick is already pending — the apply reads the latest policy anyway
		}
	})

	// S9.1 4d: the agent-owned OpenVPN server (opt-in PER GATEWAY, D-S9.5-OPTIN). Structurally safe —
	// the Manager's preconditions (binary + certs present) GUARD the supervisor before any spawn, so it
	// cannot crash-loop; a missing binary/certs refuses LOUDLY on the health surface (reported below).
	ovpnMgr := ovpnserver.New(getenv("TUNNEX_OVPN_CFG_DIR", "/etc/tunnex/ovpn"))
	ovpnSup := ovpnserver.NewSupervisor()
	ovpnMgr.SetEnsureProc(ovpnSup.Ensure)
	defer ovpnSup.Stop()
	r.OnOVPN(func(ds reconcile.DesiredState) {
		// D-S9.6: write the CP-delivered server material to disk (or SWEEP it when off) BEFORE Reconcile,
		// so the certs-present precondition sees the current truth. Re-asserted every tick (self-heal).
		if ds.OVPNServer != nil {
			if err := ovpnMgr.WriteServerMaterial(ds.OVPNServer.CA, ds.OVPNServer.Cert, ds.OVPNServer.Key, ds.OVPNServer.CRL); err != nil {
				logger.Warn("ovpn_server_material_write_failed", slog.String("error", err.Error()))
			}
		} else {
			ovpnMgr.SweepServerMaterial()
		}
		if !ds.OVPNEnabled {
			ovpnMgr.SetDesired(ovpnserver.Desired{}) // not opted in on this gateway → idle: no server, no tun
		} else {
			clients := make([]ovpnserver.Client, 0, len(ds.OVPNClients))
			for _, c := range ds.OVPNClients {
				clients = append(clients, ovpnserver.Client{CommonName: c.CommonName, IP: c.IP, FullTunnel: c.FullTunnel})
			}
			// The ranges + DNS to PUSH ride the compiled Policy the agent already holds (Part-3 fold).
			// Routes ∪ LocalSubnets (WF-OVPN-11) — the SAME set a WG client gets from routed-ranges, via
			// the ONE named union (reconcile.OVPNPushRoutes), so an OVPN client reaches remote sites AND
			// the LAN behind its own gateway.
			routes := reconcile.OVPNPushRoutes(ds.Policy)
			var dns []string
			if ds.Policy != nil {
				for _, d := range ds.Policy.DNSForwards {
					dns = append(dns, d.ResolverIP)
				}
				// S10.3 fork-1: push the cluster's reserved DNS VIP as a resolver too, so an OVPN client resolves
				// exposed-Service names (the routed VIP /32 above makes it reachable). Same push shape as the S8.4
				// site resolvers — WF-OVPN-11's twin for the K8s zone.
				for _, z := range ds.Policy.K8sDNSZones {
					if z.ListenVIP != "" {
						dns = append(dns, z.ListenVIP)
					}
				}
			}
			// InterfaceAddress ("10.99.0.1/24") carries the pool prefix — the CCD ifconfig-push mask.
			ovpnMgr.SetDesired(ovpnserver.Desired{PoolCIDR: ds.InterfaceAddress, Clients: clients, Routes: routes, DNS: dns})
		}
		if err := ovpnMgr.Reconcile(ctx); err != nil {
			logger.Warn("ovpn_reconcile_failed", slog.String("error", err.Error()))
		}
		// STEP-5 ORDERING (ruled): publish the tun to egress ONLY once the server is actually up; when
		// it dies (TunActive→false), CLEAR it so the Slice-3 sweep-on-departed-tun removes its egress rules.
		if ovpnMgr.TunActive() {
			egressMgr.SetOVPNTun(ovpnserver.TunName)
		} else {
			egressMgr.SetOVPNTun("")
		}
		// Publish the OVPN health for the report loop → CP surface (refuse-loudly on the dashboard).
		hk := ovpnMgr.Health()
		ovpnHealth.Store(&hk)
	})

	// S7.5.1 flow-log drive: read the nflog group the forward chain logs to, buffer the
	// flow-start records, and drain them to the CP on an interval (best-effort observability;
	// NEVER on the enforcement path). Enabled only when TUNNEX_FLOWLOG_GROUP>0.
	if flowGroup > 0 {
		startFlowLog(ctx, flowGroup, client, egressMgr, logger)
	}

	// Renew the cert at half-life (default 24h; the cert lives 48h) and hot-swap
	// it. Persist the rotated cert so a restart uses the current one. If renewal
	// fails until expiry, mTLS breaks and re-enrollment requires a fresh join
	// token (no silent re-admission).
	renewEvery := getdur("TUNNEX_AGENT_RENEW_INTERVAL", 24*time.Hour)
	go renewLoop(ctx, client, certDir, renewEvery, logger)
	go identityWatchLoop(ctx, client, apiURL, certDir, nodeName, joinToken != "", identityWatchInterval, logger)

	// Report per-peer live telemetry (handshake/bytes/endpoint) on an interval.
	go statusLoop(ctx, client, backend, getdur("TUNNEX_AGENT_STATUS_INTERVAL", 30*time.Second), logger)

	// Readiness mirrors the reconciler's health (enrolled + control session +
	// backend converged). It flips false if the backend later fails (e.g. device
	// lost) so orchestrators see the true state, not a stale first success.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		var announced bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h := r.Healthy() && keyReported.Load()
				ready.Store(h)
				if h && !announced {
					announced = true
					logger.Info("agent_ready")
				}
			}
		}
	}()

	logger.Info("agent_reconciling", slog.String("node_name", nodeName))
	// Interval is env-overridable so the data-plane e2e can sample device stability
	// across ≥2 reconcile cycles quickly (default 60s in production).
	r.Run(ctx, client, getdur("TUNNEX_AGENT_RECONCILE_INTERVAL", 60*time.Second), 5*time.Second)
	logger.Info("agent_stopped")
}

// serveHealth exposes liveness (process up) and readiness (enrolled + control
// session + backend healthy) — the split S8 multi-gateway views consume.
func serveHealth(addr string, ready *atomic.Bool, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "tunnex-node"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_ready"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("agent_health_failed", slog.String("error", err.Error()))
	}
}

// loadStored reads the credential set WITHOUT collapsing it.
//
// It used to return on the first error, so three files became one error and the caller learned only "something
// failed". An unreadable ca.pem was then reported as "no credentials in the state directory" — false — and the
// agent spent its join token, enrolling as a NEW node and discarding the site binding and devices of a gateway
// whose identity was perfectly provable (pass-3 claims 16, 17, 18, 19, 50). WHICH FILE FAILED CHANGES THE
// VERDICT, so the verdict must be able to see which file failed.
func loadStored(dir string) identity.Stored {
	var st identity.Stored
	st.CertPEM, st.CertErr = os.ReadFile(filepath.Join(dir, "cert.pem"))
	st.KeyPEM, st.KeyErr = os.ReadFile(filepath.Join(dir, "key.pem"))
	st.CAPEM, st.CAErr = os.ReadFile(filepath.Join(dir, "ca.pem"))
	return st
}

// saveCreds writes the credential set so that a crash leaves EITHER the old set or the new set, never a mixture
// (review #3).
//
// The previous version wrote cert.pem, key.pem and ca.pem with three separate os.WriteFile calls, iterating a Go
// map — so the order was randomised per run and a crash between two writes could persist a NEW certificate beside
// an OLD key. That combination authenticates as nothing: the cert does not match the key, so the agent cannot use
// the mTLS channel, and it cannot prove possession of the key the control plane recorded either. A gateway lands
// in a state no recovery path covers, from an interruption that lasted milliseconds.
//
// Every file is written to a temp name and renamed. rename(2) within a directory is atomic, so each file is either
// wholly old or wholly new; and the KEY is renamed LAST, because the key is what proves identity — if the sequence
// is interrupted, the old key still matches the old certificate and the agent remains recoverable.
func saveCreds(dir string, cert, key, ca []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Deterministic order, key last. A map range would randomise it, which is how the interrupted-write hazard
	// became unpredictable rather than merely possible.
	type f struct {
		name string
		data []byte
	}
	for _, w := range []f{{"ca.pem", ca}, {"cert.pem", cert}, {"key.pem", key}} {
		tmp := filepath.Join(dir, w.name+".tmp")
		if err := os.WriteFile(tmp, w.data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, w.name)); err != nil {
			return err
		}
	}
	// A pending re-key key is SUPERSEDED the moment a real identity lands — whether it landed by re-key promotion,
	// by renewal, or by join-token enrolment. Leaving it would make the next recovery attempt spend a challenge
	// proving possession of a key the control plane does not hold. Best-effort: a stale pending key costs one wasted
	// attempt, and failing the save over it would cost the identity that just succeeded.
	_ = os.Remove(filepath.Join(dir, pendingKeyFile))
	return nil
}

// pendingKeyFile holds a keypair minted for a re-key that has been SUBMITTED but not confirmed.
//
// It is a separate filename rather than an early write to key.pem on purpose: key.pem must always be the key that
// matches cert.pem, and a re-key in flight has no certificate yet. loadCreds and identity.Decide never look at this
// file, so a pending key cannot become an identity by accident — only saveCreds can promote it.
const pendingKeyFile = "rekey-pending-key.pem"

// renewRetryInterval is how soon a FAILED renewal is retried. Short relative to the 48h certificate lifetime and
// long enough not to hammer a control plane that is down.
const renewRetryInterval = 15 * time.Minute

// saveCredsFn is the promotion seam. A test needs to make the write fail DETERMINISTICALLY to prove that a local
// write failure after the control plane has already committed is retried rather than fatal — and permission
// tricks do not work (the agent runs as root, which bypasses them) while timing tricks produce a SKIP, which
// reads exactly like a pass.
var saveCredsFn = saveCreds

// loadOrCreatePendingKey returns the pending re-key key, minting and PERSISTING one if none exists.
//
// The second return says whether it was already on disk — which is the only evidence available that an earlier
// attempt got far enough for the control plane to have recorded it. See attemptRekey for why that ordering matters.
func loadOrCreatePendingKey(dir string) (keyPEM []byte, wasOnDisk bool, err error) {
	path := filepath.Join(dir, pendingKeyFile)
	if b, rerr := os.ReadFile(path); rerr == nil && len(b) > 0 {
		if _, perr := control.KeyFingerprintFromPEM(b); perr == nil {
			return b, true, nil
		}
		// Unreadable pending material is worse than none: it would be submitted, refused, and looked like a
		// server-side refusal. Replace it loudly-by-consequence (the caller logs the mint) rather than carrying it.
	}
	k, err := control.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, k, 0o600); err != nil {
		return nil, false, err
	}
	// Rename so a crash mid-write cannot leave a truncated key that would then be submitted as an identity.
	if err := os.Rename(tmp, path); err != nil {
		return nil, false, err
	}
	return k, false, nil
}

// renewLoop keeps the certificate ahead of its own expiry.
//
// ANCHORED TO THE CERTIFICATE, NOT TO PROCESS START (review pass 3 claims 5/12). A fixed ticker from boot means a
// process that restarts when its certificate is already 30 hours old waits another 24 before its first attempt —
// six hours after it expired. The gateway then needs the recovery path for a certificate that was renewable the
// whole time. The first tick is therefore computed from what is LEFT, and a failed renew retries on a short
// interval instead of waiting a full cycle for a second chance.
func renewLoop(ctx context.Context, client *control.Client, certDir string, every time.Duration, logger *slog.Logger) {
	// Half of whatever remains, floored so a nearly-expired certificate is attempted promptly and never hot-loops.
	next := every
	if certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem")); err == nil {
		if left := time.Until(identity.NotAfter(certPEM)); left > 0 && left/2 < next {
			next = left / 2
			if next < time.Minute {
				next = time.Minute
			}
			logger.Info("agent_renew_scheduled_from_cert",
				slog.String("cert_expires_in", left.Truncate(time.Minute).String()),
				slog.String("first_attempt_in", next.Truncate(time.Minute).String()),
				slog.String("note", "anchored to the certificate's remaining life, not to process start"))
		}
	}
	t := time.NewTimer(next)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(every)
			certPEM, keyPEM, err := client.Renew(ctx, version())
			if err != nil {
				// A FAILED RENEW RETRIES SOON, NOT IN A FULL CYCLE. One transient failure used to cost 24 hours,
				// which for a 48h certificate is half its remaining life spent waiting.
				logger.Warn("agent_renew_failed", slog.String("error", err.Error()),
					slog.String("retry_in", renewRetryInterval.String()))
				t.Reset(renewRetryInterval)
				continue
			}
			// THE READ ERROR IS NOT DISCARDED (pass-3 claims 30, 32, 37, 46, 52). It used to be `ca, _ :=`, and
			// the empty result went straight to saveCreds — which atomically REPLACED the trust anchor with a
			// zero-length file. The next boot failed AppendCertsFromPEM and os.Exit(1)'d, forever, from one
			// transient read. A renewal must never be able to destroy the anchor it did not fetch.
			ca, caErr := os.ReadFile(filepath.Join(certDir, "ca.pem"))
			if caErr != nil {
				logger.Warn("agent_renew_anchor_unreadable",
					slog.String("error", caErr.Error()),
					slog.String("consequence", "the renewed certificate was NOT written; the existing credential "+
						"set is untouched and this agent keeps using it"),
					slog.String("remedy", "check "+certDir+" is readable; renewal retries on the next tick"))
				t.Reset(renewRetryInterval)
				continue
			}
			if err := saveCreds(certDir, certPEM, keyPEM, ca); err != nil {
				logger.Warn("agent_renew_persist_failed", slog.String("error", err.Error()))
				continue
			}
			logger.Info("agent_cert_renewed")
		}
	}
}

// identityWatchInterval — how often the identity gate is re-evaluated while the agent runs. A var so a red can
// drive it fast; five minutes in production is far below any certificate lifetime and costs three file reads.
var identityWatchInterval = 5 * time.Minute

// identityWatchLoop — WF-S13-6. THE GATE RUNS MORE THAN ONCE.
//
// THE DEFECT THIS CLOSES. identity.Decide was evaluated exactly once, at boot, against the credentials on disk at
// that instant; attemptRekey had exactly one caller, inside that boot switch. So recovery was reachable only from
// a COLD START. A certificate that expired while the agent was running — the ordinary case, and the actual
// incident that opened EPIC 13 — was detected, logged, and never acted on. Measured on the wire 2026-07-31:
// STUCK 59 MINUTES, RECOVERED IN 1.77 SECONDS once a human typed `docker restart`.
//
// Nothing automatic could bridge that gap, because two individually-correct decisions composed badly: the loop
// never exits on refusal (right — a gateway must not stop carrying traffic over a control-plane opinion), so
// Docker's restart policy never fires, kubelet sees a process that is up (and the shipped chart declares no
// probes at all), and systemd sees no failure code.
//
// WHY A TIMER AND NOT AN ERROR HANDLER. The obvious fix is to escalate when requests start failing with
// `tls: expired certificate`. That would make a NETWORK SIGNAL the trigger, and identity.Decide's guarantee is
// that no network signal can reach it — there is no argument to pass one through. An agent that re-keys because
// it cannot reach the control plane hammers an unauthenticated endpoint during every partition and CP restart,
// hardest when the CP can least cope.
//
// So this is not escalation-from-failure. It is THE EXISTING DECISION, INVOKED MORE THAN ONCE, over exactly the
// inputs it already reads: the files in the state directory and this host's clock. The verdict a boot would have
// reached is the verdict this reaches, which is why nothing about the decision needed to change.
func identityWatchLoop(ctx context.Context, client *control.Client, apiURL, certDir, nodeName string,
	haveToken bool, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Re-read from DISK, not from a variable captured at boot: a renewal or an earlier recovery may have
			// replaced the set since, and a stale copy would re-decide a question that no longer exists.
			st := loadStored(certDir)
			verdict := identity.Decide(st, nodeName, haveToken, time.Now())
			if verdict.Action != identity.Recover {
				continue
			}
			logger.Warn("agent_identity_recovery_at_runtime",
				slog.String("reason", verdict.Reason),
				slog.String("evidence", verdict.Evidence),
				slog.String("note", "the identity gate reached a RECOVER verdict while this agent was already "+
					"running. The trigger is local — this host's files against this host's clock — and no "+
					"network outcome contributed to it"))

			c, k, _, outcome := attemptRekey(ctx, logger, apiURL, certDir, st.CertPEM, st.KeyPEM, st.CAPEM,
				nodeName, haveToken)
			if outcome != rekeyRecovered {
				// Every other outcome already logged its own diagnosis, and none of them is fixable from here.
				// The next tick re-decides from disk, so a control plane repaired in the meantime is picked up
				// without an operator touching this host.
				continue
			}
			if err := client.AdoptCredentials(c, k); err != nil {
				logger.Error("agent_identity_recovered_but_not_adopted",
					slog.String("error", err.Error()),
					slog.String("consequence", "the recovery SUCCEEDED and is on disk; this running process could "+
						"not install it, so it takes effect on the next restart"))
				continue
			}
			logger.Info("agent_identity_recovered_in_place",
				slog.String("note", "recovered by proof of possession WITHOUT a restart — same node, same id, "+
					"same site binding, same devices. The control channel re-handshakes with the new certificate"))
		}
	}
}

// reportKeyLoop reports the node's WG public key to the control plane, retrying
// with backoff until it succeeds (then sets reported and returns). The report is
// idempotent server-side, so retrying is safe. Until it succeeds the agent stays
// not-ready, so no orchestrator routes to a node the control plane can't peer.
func reportKeyLoop(ctx context.Context, client *control.Client, pubKey, endpoint string, egressNAT, egressIPv6 *atomic.Bool, egressMgr *egress.Manager, siteLinkStale, siteSubnetUnreachable *atomic.Bool, ovpnHealth *atomic.Pointer[string], reported *atomic.Bool, every time.Duration, logger *slog.Logger) {
	const maxBackoff = 30 * time.Second
	report := func() bool {
		// Applied-policy status rides the capability report (S7.2 staleness): version +
		// canonical hash of what is IN FORCE, plus the last apply error. The control
		// plane compares against what it pushed — a stale gateway must be visible.
		v, h, failingSince, applyErr := egressMgr.AppliedStatus()
		ovpnH := ""
		if hp := ovpnHealth.Load(); hp != nil {
			ovpnH = *hp
		}
		ps := control.PolicyStatus{Version: v, Hash: h, RefusedVersion: egressMgr.RefusedVersion(), SiteLinkStale: siteLinkStale.Load(), SiteSubnetUnreachable: siteSubnetUnreachable.Load(), ConntrackFlushUnavailable: egressMgr.ConntrackFlushFailing(), K8sEndpointsUnavailable: egressMgr.EndpointsUnavailable(), MaxSupportedVersion: nodepolicy.MaxSupportedVersion, OVPNHealth: ovpnH}
		if applyErr != nil {
			ps.Error = applyErr.Error()
			if len(ps.Error) > 300 { // bound so a verbose nft error can't overflow the report body (finding #4)
				ps.Error = ps.Error[:300]
			}
		}
		if !failingSince.IsZero() {
			ps.FailingSince = failingSince.UTC().Format(time.RFC3339)
		}
		if err := client.ReportInfo(ctx, pubKey, endpoint, egressNAT.Load(), egressIPv6.Load(), ps); err != nil {
			logger.Warn("agent_report_key_failed", slog.String("error", err.Error()))
			return false
		}
		if reported.CompareAndSwap(false, true) {
			logger.Info("agent_wg_key_reported", slog.String("public_key", pubKey))
		}
		return true
	}
	// Retry fast until the FIRST success (readiness is gated on it).
	backoff := time.Second
	for !report() {
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	// Then re-report on an interval so a CHANGED egress_nat capability (host state can
	// shift) propagates to the control plane — the decision was "report every reconcile".
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}

// egressLoop reconciles the gateway egress NAT + the Zero Trust forward chain (the
// tunnex nft tables) every interval — idempotent, so it heals a flushed table — and
// updates the egress_nat capability that reportKeyLoop advertises. It ALSO applies
// immediately on a policy kick (a pushed policy change must land within the <5s
// revocation spec, not wait out the interval). A degraded reconcile (locked-down
// host) sets egress_nat=false and logs, never crashing the agent.
func egressLoop(ctx context.Context, mgr *egress.Manager, egressNAT, egressIPv6 *atomic.Bool, every time.Duration, kick <-chan struct{}, logger *slog.Logger) {
	apply := func() {
		// S10.3: resolve exposed-Service ClusterIPs (bounded per-lookup) BEFORE the reconcile. Resolution
		// stores the resolved VIP->ClusterIP map; Reconcile's render reads it and does NO DNS I/O (pure) —
		// so a slow resolver is bounded, never an unbounded stall of the nft apply.
		mgr.ResolveK8sVIPs(ctx)
		// S10.3 A1: own each cluster's reserved DNS VIP as a /32 on wg0 so the client's DNS query is delivered
		// locally and the forwarder binds :53 on it. Fail-closed (a failed assign → no local addr → no answer);
		// logged, never fatal — DNS-VIP-down is never tunnel-down.
		if err := mgr.ReconcileDNSVIPs(ctx); err != nil {
			logger.Warn("dns_vip_reconcile_degraded", slog.String("error", err.Error()))
		}
		ok, ok6, err := mgr.Reconcile(ctx)
		egressNAT.Store(ok)
		egressIPv6.Store(ok6)
		if err != nil {
			logger.Warn("egress_reconcile_degraded", slog.String("error", err.Error()))
		}
	}
	// The initial probe/arm ran synchronously in main() before the first report — this
	// loop only re-reconciles on the interval (heals a flushed table, tracks capability)
	// and on policy kicks (push-path enforcement).
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			apply()
		case <-t.C:
			apply()
		}
	}
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first.
// maxStatusPeers caps a status report so a gateway with thousands of peers can't
// turn a heartbeat into a huge post. Excess is dropped (and logged) — the status
// view is best-effort telemetry, not the source of truth.
const maxStatusPeers = 1000

// statusLoop periodically reads per-peer telemetry from the backend and reports
// it. Best-effort: a failed report only means a momentarily stale status view.
func statusLoop(ctx context.Context, client *control.Client, backend reconcile.WGBackend, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			stats, err := backend.Stats(ctx)
			if err != nil {
				logger.Warn("agent_stats_read_failed", slog.String("error", err.Error()))
				continue
			}
			if len(stats) == 0 {
				continue
			}
			if len(stats) > maxStatusPeers {
				logger.Warn("agent_status_truncated", slog.Int("peers", len(stats)), slog.Int("cap", maxStatusPeers))
				stats = stats[:maxStatusPeers]
			}
			if err := client.ReportStatus(ctx, stats); err != nil {
				logger.Warn("agent_status_report_failed", slog.String("error", err.Error()))
			}
		}
	}
}

// loadOrCreateWGKey loads (or generates + persists) the node's WireGuard key,
// returning base64 private and public keys. A missing OR unparseable file (e.g.
// a crash mid-write left it empty/truncated) triggers regeneration rather than a
// hard error — otherwise a corrupt key file would wedge the agent in a permanent
// crash-loop with no way to self-heal.
func loadOrCreateWGKey(path string) (privB64, pubB64 string, err error) {
	curve := ecdh.X25519()
	if data, rerr := os.ReadFile(path); rerr == nil {
		trimmed := strings.TrimSpace(string(data))
		if raw, derr := base64.StdEncoding.DecodeString(trimmed); derr == nil {
			if pk, perr := curve.NewPrivateKey(raw); perr == nil {
				return trimmed, base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), nil
			}
		}
		// File exists but is corrupt/empty — fall through and regenerate.
	}
	pk, gerr := curve.GenerateKey(rand.Reader)
	if gerr != nil {
		return "", "", gerr
	}
	priv := base64.StdEncoding.EncodeToString(pk.Bytes())
	if werr := os.WriteFile(path, []byte(priv), 0o600); werr != nil {
		return "", "", werr
	}
	return priv, base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), nil
}

// dnsEntriesFrom maps a compiled artifact's DNS forwarding table to the forwarder's input (S8.4). A nil
// policy (mesh/off/cold-start) yields no entries → the forwarder serves nothing (REFUSED), never stale.
func dnsEntriesFrom(p *nodepolicy.Compiled) []dnsforward.Entry {
	if p == nil {
		return nil
	}
	out := make([]dnsforward.Entry, 0, len(p.DNSForwards))
	for _, d := range p.DNSForwards {
		out = append(out, dnsforward.Entry{Domain: d.Domain, ResolverIP: d.ResolverIP})
	}
	return out
}

// k8sAnswersFrom maps a compiled artifact's K8s VIP map + DNS-listen zones to the forwarder's direct-answer
// input (S10.3 A1). The entries are the exposed FQDN→VIP pairs (from VIPMappings.DNSName); the zones are the
// cluster zones this gateway owns (from K8sDNSZones.Zone) — an in-zone-but-unexposed name answers NXDOMAIN.
// A nil policy (mesh/off/cold-start) yields nothing → the forwarder answers no cluster names (fail-closed).
func k8sAnswersFrom(p *nodepolicy.Compiled) ([]dnsforward.K8sEntry, []string) {
	if p == nil {
		return nil, nil
	}
	entries := make([]dnsforward.K8sEntry, 0, len(p.VIPMappings))
	for _, vm := range p.VIPMappings {
		if vm.DNSName != "" {
			entries = append(entries, dnsforward.K8sEntry{FQDN: vm.DNSName, VIP: vm.VIP})
		}
	}
	zones := make([]string, 0, len(p.K8sDNSZones))
	for _, z := range p.K8sDNSZones {
		zones = append(zones, z.Zone)
	}
	return entries, zones
}

func getdur(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func getint(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// startFlowLog wires the nflog reader → pump → periodic drain → ReportFlows (S7.5.1 7/n).
// Best-effort + isolated: a source-open failure logs and returns (enforcement + the rest of
// the agent are unaffected); the pump/drain run until ctx is cancelled. Each event is stamped
// with the APPLIED policy hash so the CP can detect a ruleset-swap-window skew.
func startFlowLog(ctx context.Context, group int, client *control.Client, egressMgr *egress.Manager, logger *slog.Logger) {
	sockBuf := getint("TUNNEX_FLOWLOG_SOCKBUF", flowlog.DefaultNflogSockBuf)
	src, err := flowlog.NewNflogSource(ctx, group, sockBuf)
	if err != nil {
		logger.Error("flowlog_source_failed", slog.Int("group", group), slog.String("error", err.Error()))
		return
	}
	pump := flowlog.NewPump(src, flowlog.NewBuffer(0), func(srcIP string) flowlog.Attribution {
		// F07: one locked event-time snapshot of the successfully applied
		// policy and its complete subject map. Never mix desired identity with
		// a last-good hash after an apply failure.
		return egressMgr.FlowAttribution(srcIP)
	})
	go pump.Run(ctx)
	go flowlog.RunDrain(ctx, pump, client, getdur("TUNNEX_FLOWLOG_INTERVAL", flowlog.DefaultDrainInterval), logger)
	logger.Info("flowlog_started", slog.Int("group", group), slog.Int("sock_buf_bytes", sockBuf))
}

func hostname() string { h, _ := os.Hostname(); return h }
func version() string  { return getenv("TUNNEX_AGENT_VERSION", "0.1.0") }

// Re-key retry pacing (S13.1). THE CEILING IS THE LOAD-BEARING NUMBER, not the floor.
//
// A gateway whose key the control plane never recorded — every node enrolled before migration 0057 and not since
// renewed — will be refused FOREVER, and it cannot learn that from the response, because the refusal is uniform by
// design (a live node, an unknown serial and a wrong key are indistinguishable, so the endpoint cannot be used as an
// oracle). So the retry loop must assume it may be permanent.
//
// One attempt per hour, sustained, is two requests per hour per bricked gateway against an endpoint whose expensive
// path already requires knowing a real serial for a genuinely expired node. That is negligible load and still
// recovers within an hour of an operator fixing the underlying cause — which is the trade the ceiling exists to make.
// The floor is short because the common case is a gateway rebooting after a weekend, where recovery in seconds is the
// whole point.
// VAR, not const, for ONE reason: a test that proves the loop EXITS on persistent refusal has to sit through the
// backoff to get there, and a test that takes two minutes is a test people stop running. Nothing in the product
// writes these.
var (
	rekeyBackoffFloor   = 30 * time.Second
	rekeyBackoffCeiling = time.Hour
)

// rekeyOutcome is what the retry loop concluded. Before this restructure the function returned "some bytes or
// nil", and nil meant four different things — recovered-but-unsaveable, refused forever, context cancelled, and
// impossible — which is why the join-token fallback was unreachable and a SIGTERM printed a refusal message.
type rekeyOutcome int

const (
	rekeyRecovered  rekeyOutcome = iota // credentials returned and on disk
	rekeyExhausted                      // persistently refused, and a join token exists to fall back to
	rekeyCancelled                      // the context ended; say nothing about the control plane
	rekeyImpossible                     // no local material to attempt with
	rekeyNotNeeded                      // the premise dissolved: the stored certificate is valid after all
)

// rekeyRefusalsBeforeToken bounds how long the loop insists before handing over to the operator's remedy.
//
// It exists because the loop had NO exit: a persistently refused gateway retried toward the hour ceiling forever
// while the join token the operator had already supplied sat unused, and the log told them to do the thing the
// agent was refusing to do. Three consecutive refusals, each behind its own backoff, is minutes of insisting —
// long enough that a transient 403 from a restarting control plane does not spend the identity, short enough that
// an operator who acted on the message sees it work.
//
// With NO token there is no exit, deliberately: retrying forever is strictly better than idling forever, and the
// control plane may still be fixed underneath us.
const rekeyRefusalsBeforeToken = 3

// rekeyThrottlesBeforeEscalation — how many CONSECUTIVE 429s before the agent says loudly that it is being denied
// recovery. Not an exit: a throttle is not a refusal, and no number of them may spend the identity.
const rekeyThrottlesBeforeEscalation = 5

// attemptRekey recovers an expired identity by proof of possession.
//
// WHAT IT LOGS, AND WHY THAT MATTERS. The control plane's refusal carries no reason. So the agent reports what it
// knows LOCALLY — my certificate expired at T, I attempted re-key, it was refused, and the remedy is a join token.
// Without that an operator finds an agent idling silently in exactly the situation they are trying to diagnose.
//
// EVERY INPUT IS RE-EVALUATED INSIDE THE LOOP (review pass 1 ROOT 2). The previous version sampled its premise,
// its identities and its pending-key state ONCE before an infinite loop that revisited none of them, so: a clock
// correction could not end a re-key of a healthy gateway; the fingerprint identity that D10 exists to serve was
// never tried by the process that suffered the lost response; and a join token appearing in the environment was
// never noticed. Three findings, one shape.
func attemptRekey(ctx context.Context, logger *slog.Logger, apiURL, certDir string, certPEM, keyPEM, caPEM []byte,
	nodeName string, haveToken bool) ([]byte, []byte, []byte, rekeyOutcome) {
	serial := identity.StoredSerial(certPEM)

	backoff := rekeyBackoffFloor
	refusals := 0
	throttles := 0
	// identityStart ROTATES on a throttled break, and the reason is an asymmetry that is easy to miss.
	//
	// The identity list is ordered [fingerprint, cert_serial] — fingerprint first because it is the LOST-RESPONSE
	// case: if a previous attempt committed on the control plane without this agent seeing the answer, the CP holds
	// that key and trying it first avoids asking for a second issuance. Correct, and it is the RARE case.
	//
	// cert_serial is the identity the control plane USUALLY holds. So under a partially-exhausted bucket — where
	// some requests in each window succeed and the rest are refused with 429 — the fingerprint consumes each
	// window's surviving request, the throttle breaks the identity loop before cert_serial is ever reached, and the
	// next attempt starts at the fingerprint again. THE ONE IDENTITY THAT CAN SUCCEED IS STARVED BY THE ONE THAT
	// PROVABLY CANNOT (pass-3 #34). Rotating the start index means no identity can be starved by another, so under
	// a throttled fleet the ordering stops deciding whether recovery happens at all.
	identityStart := 0
	for attempt := 1; ; attempt++ {
		// (1) THE PREMISE, RE-READ. A re-key is authorized by this agent's own observation that its certificate has
		// expired, and that observation depends on the CLOCK. A gateway that booted with a fast clock — before NTP
		// settled — decided it was expired and then never asked again, so a corrected clock could not release it.
		//
		// DIRECTION, STATED: this check can only CANCEL a re-key, never start one. Re-reading the clock can only
		// discover that the stored certificate is valid after all. A clock that jumps the OTHER way cannot trigger
		// recovery from in here.
		//
		// CORRECTED with the runtime gate (WF-S13-6): this comment used to say "the loop is entered from
		// identity.Decide at boot and nothing here can enter it." The first clause is no longer true —
		// identityWatchLoop also enters it, on a timer, while the agent runs. THE SAFETY PROPERTY IS UNCHANGED and
		// is worth restating rather than assuming: BOTH entrances are identity.Decide over purely local inputs, so
		// neither can be induced by anything on the network. That old sentence is also the one that described the
		// WF-S13-6 defect as a virtue, which is exactly why it is being rewritten and not merely deleted.
		if len(certPEM) > 0 {
			if v := identity.Decide(identity.Stored{CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM}, nodeName, haveToken, time.Now()); v.Action == identity.UseStored {
				logger.Warn("agent_rekey_no_longer_needed",
					slog.Int("attempt", attempt),
					slog.String("reason", "the stored certificate is valid as of the current clock — the expiry "+
						"this recovery was based on was a clock artifact, not a fact"),
					slog.String("action", "abandoning re-key and using the stored identity"))
				return nil, nil, nil, rekeyNotNeeded
			}
		}

		// (2) THE PENDING KEY AND THE IDENTITIES, REBUILT EACH PASS.
		//
		// pendingWasOnDisk decides whether the fingerprint identity is worth trying, and it was sampled ONCE before
		// the loop — so the very process that suffered a lost response persisted a pending key, then never used the
		// identity that key exists to provide, for the lifetime of the process. Re-reading makes the second
		// iteration know what the first one wrote.
		pending, pendingWasOnDisk, perr := loadOrCreatePendingKey(certDir)
		if perr != nil {
			logger.Error("agent_rekey_impossible",
				slog.String("reason", "could not persist a new keypair before attempting re-key: "+perr.Error()),
				slog.String("remedy", "check the state directory is writable, then restart this agent"))
			return nil, nil, nil, rekeyImpossible
		}
		pendingFP, fperr := control.KeyFingerprintFromPEM(pending)
		if fperr != nil {
			logger.Error("agent_rekey_impossible", slog.String("reason", "pending key unreadable: "+fperr.Error()))
			return nil, nil, nil, rekeyImpossible
		}

		type attemptIdentity struct {
			ident  control.Identifier
			popKey []byte
			note   string
		}
		var identities []attemptIdentity
		if pendingWasOnDisk {
			// The lost-response identity: the control plane may already hold this key. Only meaningful once a
			// pending key has survived an attempt, which is why it is rebuilt rather than fixed at entry.
			identities = append(identities, attemptIdentity{
				ident:  control.Identifier{KeyFingerprint: pendingFP},
				popKey: pending,
				note:   "a previous attempt may have committed on the control plane without this agent seeing the answer",
			})
		}
		if serial != "" && len(keyPEM) > 0 {
			identities = append(identities, attemptIdentity{
				ident:  control.Identifier{CertSerial: serial},
				popKey: keyPEM,
				note:   "the identity this agent's stored certificate names",
			})
		}
		if len(identities) == 0 {
			logger.Error("agent_rekey_impossible",
				slog.String("reason", "no usable local identity material: the stored certificate has no readable "+
					"serial and no pending key survived"),
				slog.String("remedy", "re-enroll this gateway with a join token (TUNNEX_JOIN_TOKEN)"))
			return nil, nil, nil, rekeyImpossible
		}

		var err error
		for n := range identities {
			id := identities[(identityStart+n)%len(identities)]
			var newCert []byte
			// caPEM is the anchor ALREADY ON DISK and is never replaced (review pass 1 #1): this path is
			// unauthenticated plain HTTP, so a CA in the response is attacker-controlled input.
			newCert, err = control.Rekey(ctx, apiURL, id.ident, pending, id.popKey, caPEM, version(), nodeName)
			if err == nil {
				if serr := saveCredsFn(certDir, newCert, pending, caPEM); serr != nil {
					// THE CONTROL PLANE ALREADY COMMITTED, AND THIS IS NO LONGER TERMINAL.
					//
					// It used to be: the CP had spent its one issuance, the agent could not write it, and the loop
					// gave up — falling through to a join token and destroying the identity it had just recovered.
					// Under the UNDELIVERED predicate that certificate was never used, so the node still reads
					// undelivered and a retry is LEGAL. Keep the pending key (saveCreds is what clears it, and it
					// did not get that far) and go round again.
					logger.Error("agent_save_creds_failed",
						slog.String("error", serr.Error()),
						slog.String("consequence", "the control plane issued a certificate this agent could not "+
							"write; because it was never used, the same recovery can be retried"),
						slog.String("remedy", "free space or fix permissions on "+certDir+"; the agent keeps retrying"))
					break
				}
				logger.Info("agent_rekeyed",
					slog.String("old_cert_serial", serial),
					slog.String("identified_by", id.ident.Describe()),
					slog.String("note", "recovered by proof of possession — same node, same identity, new key"))
				return newCert, pending, caPEM, rekeyRecovered
			}
			if errors.Is(err, control.ErrRekeyThrottled) {
				// Do not burn the second identity's request on a rate limit — but ROTATE, so the identity that did
				// not get its turn this time gets it first next time (#34).
				identityStart = (identityStart + 1) % len(identities)
				break
			}
			if len(identities) > 1 && errors.Is(err, control.ErrRekeyRefused) {
				logger.Warn("agent_rekey_identity_refused",
					slog.Int("attempt", attempt),
					slog.String("identified_by", id.ident.Describe()),
					slog.String("why_tried", id.note),
					slog.String("note", "refusals are uniform, so this says nothing about the reason; trying the "+
						"next identity this agent can prove"))
			}
		}

		// CONSECUTIVE throttles only: anything else answering — a refusal, a transient fault, a success — means the
		// path is not saturated, and the escalation below must describe the present, not a historical total.
		if !errors.Is(err, control.ErrRekeyThrottled) {
			throttles = 0
		}

		switch {
		case err == nil:
			// A save failure broke out of the identity loop. Not a refusal — do not count it as one.
			logger.Warn("agent_rekey_retrying_after_local_failure", slog.Int("attempt", attempt))

		case errors.Is(err, control.ErrRekeyThrottled):
			// THROTTLED IS NOT REFUSED, and the server's own number is now honoured rather than printed and
			// discarded. Retry-After was parsed into an error string while the agent retried on its own floor, so
			// the log stated one interval and the code used another.
			wait := control.RetryAfterOf(err)
			if wait <= 0 || wait > rekeyBackoffCeiling {
				wait = rekeyBackoffFloor
			}
			throttles++
			// ESCALATION, because the throttled branch had NO EXIT AND NO ESCALATION (pass-3 claims 9 and 14): it
			// slept and continued forever, at one WARN per attempt, indistinguishable from ordinary backoff. A
			// fleet denied recovery by a rate limit looked exactly like a fleet waiting politely.
			//
			// IT STILL DOES NOT EXIT, AND THAT IS DELIBERATE. A 429 says nothing about whether this gateway can
			// recover — falling back to the join token on a rate limit would destroy the node's id, site binding
			// and devices because an intermediary was busy. The never-exit ruling stands; what was missing was
			// SAYING SO LOUDLY. The remedy is an operator's to apply, and they cannot apply it unseen.
			if throttles >= rekeyThrottlesBeforeEscalation {
				logger.Error("agent_rekey_throttled_persistently",
					slog.Int("consecutive_throttles", throttles),
					slog.String("local_finding", "every re-key attempt has been rate-limited for "+
						(time.Duration(throttles)*wait).String()+"; this gateway cannot recover while that lasts"),
					slog.String("not_a_refusal", "the control plane has NOT refused this node. Its identity is "+
						"intact and no join token has been or will be spent on a rate limit"),
					slog.String("remedy", "the re-key throttle is keyed on the peer address the control plane SEES, "+
						"which behind a reverse proxy is the proxy itself — so one caller can exhaust the budget "+
						"for every gateway behind it. Check the control plane for rekey_throttled log lines and "+
						"which peer is spending them"))
			}
			logger.Warn("agent_rekey_throttled",
				slog.Int("attempt", attempt),
				slog.Int("consecutive_throttles", throttles),
				slog.String("note", "something is rate-limiting re-key attempts; this is NOT a refusal and says "+
					"nothing about whether this gateway can recover. It may be the control plane or an intermediary "+
					"— the agent cannot tell, and does not claim to"),
				slog.String("retry_in", wait.String()),
				slog.String("error", err.Error()))
			if !sleepCtx(ctx, wait) {
				return nil, nil, nil, rekeyCancelled
			}
			continue

		case errors.Is(err, control.ErrIssuedCertUntrusted):
			logger.Error("agent_rekey_response_untrusted",
				slog.Int("attempt", attempt),
				slog.String("local_finding", "a re-key response arrived whose certificate does NOT chain to this "+
					"agent's trusted CA, so it did not come from this control plane"),
				slog.String("consequence", "nothing was written; this agent kept its existing CA, certificate and key"),
				slog.String("remedy", "check what is answering "+apiURL+" — a proxy, a captive portal, or an "+
					"attacker on the path. Do NOT re-enroll on the strength of this message"),
				slog.String("retry_in", backoff.String()),
				slog.String("error", err.Error()))

		case errors.Is(err, control.ErrRekeyTransient):
			// NOTHING ANSWERED, SO NOTHING WAS DECIDED. This must never print the join-token remedy: acting on it
			// during a control-plane restart discards a working identity.
			logger.Warn("agent_rekey_attempt_failed",
				slog.Int("attempt", attempt),
				slog.String("local_finding", "the re-key attempt did not complete — no refusal was received"),
				slog.String("note", "this says NOTHING about whether this gateway can recover; do not re-enroll "+
					"on the strength of it"),
				slog.String("retry_in", backoff.String()),
				slog.String("error", err.Error()))

		default: // a genuine, uniform refusal from the control plane
			refusals++
			logger.Error("agent_rekey_refused",
				slog.Int("attempt", attempt),
				slog.Int("consecutive_refusals", refusals),
				slog.String("cert_serial", serial),
				slog.String("pending_key_fingerprint", pendingFP[:12]),
				slog.Int("identities_tried", len(identities)),
				slog.String("local_finding", "this agent's certificate has expired; it cannot authenticate and cannot renew"),
				slog.String("server_said", "refused, without a reason (the control plane's refusals are uniform by "+
					"design so the endpoint cannot be probed)"),
				slog.String("most_likely_cause", "this gateway was enrolled before the control plane recorded agent "+
					"public keys, so proof-of-possession recovery is unavailable for it — or it was REVOKED, which "+
					"re-key deliberately cannot undo"),
				slog.String("remedy", "mint a join token in the control plane and restart this agent with "+
					"TUNNEX_JOIN_TOKEN set"),
				slog.String("retry_in", backoff.String()),
				slog.String("error", err.Error()))

			if haveToken && refusals >= rekeyRefusalsBeforeToken {
				// THE DOCUMENTED REMEDY, REACHED. The operator already did what the log asked; insisting further
				// would be the agent refusing its own advice.
				logger.Warn("agent_rekey_exhausted",
					slog.Int("consecutive_refusals", refusals),
					slog.String("action", "falling back to the join token this agent was given"))
				return nil, nil, nil, rekeyExhausted
			}
		}

		if !sleepCtx(ctx, backoff) {
			return nil, nil, nil, rekeyCancelled
		}
		if backoff < rekeyBackoffCeiling {
			backoff *= 2
			if backoff > rekeyBackoffCeiling {
				backoff = rekeyBackoffCeiling
			}
		}
	}
}

// sleepCtx waits d, or returns false if the context ends first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// enrollWithToken enrolls with a join token, returning ok=false rather than exiting on failure.
//
// NEVER os.Exit HERE (review finding #2). An enrolment refusal is frequently something a control-plane change
// resolves: the node's name is still held by its own expired-but-not-revoked row (409), the token was already
// consumed, the CP is mid-restart. Exiting forfeits the reconciliation that would have fixed it and converts a
// recoverable condition into CrashLoopBackOff — which is strictly worse than idling with liveness up and readiness
// false, the behaviour this agent had before S13.1 touched the path.
//
// THE GENERAL RULE, recorded in docs/S13.1-decisions.md: an agent must never exit on a condition that a
// control-plane change could resolve.
func enrollWithToken(ctx context.Context, logger *slog.Logger, apiURL, certDir, joinToken, nodeName string) (certPEM, keyPEM, caPEM []byte, ok bool) {
	key, csr, gerr := control.GenerateKeyAndCSR(nodeName)
	if gerr != nil {
		logger.Error("agent_csr_failed", slog.String("error", gerr.Error()))
		return nil, nil, nil, false
	}
	res, eerr := control.Enroll(ctx, apiURL, joinToken, csr, nodeName, version(), protocolVersion)
	if eerr != nil {
		logger.Error("agent_enroll_failed",
			slog.String("error", eerr.Error()),
			slog.String("note", "NOT exiting — this may be resolvable from the control plane (a name still held "+
				"by this node's own expired row, a consumed token, a restarting CP). Liveness stays up, readiness "+
				"stays false."))
		return nil, nil, nil, false
	}
	certPEM, keyPEM, caPEM = []byte(res.CertPEM), key, []byte(res.CAPEM)
	if serr := saveCreds(certDir, certPEM, keyPEM, caPEM); serr != nil {
		logger.Error("agent_save_creds_failed", slog.String("error", serr.Error()))
		return nil, nil, nil, false
	}
	logger.Info("agent_enrolled", slog.String("node_id", res.NodeID))
	return certPEM, keyPEM, caPEM, true
}
