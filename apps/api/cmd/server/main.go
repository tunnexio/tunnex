// Command server is the Tunnex control-plane API.
//
// Boot sequence:
//
//	S0.1 — structured logging, /healthz, graceful shutdown.
//	S0.3 — first-boot secrets bootstrap (fail-loud), crypto self-test, mailer.
//
// Database, Redis, auth, and the node-agent control protocol layer on later.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/bootstrap"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	apphttp "github.com/tunnexio/tunnex/apps/api/internal/http"
	"github.com/tunnexio/tunnex/apps/api/internal/invites"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	applog "github.com/tunnexio/tunnex/apps/api/internal/log"
	"github.com/tunnexio/tunnex/apps/api/internal/machineauth"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
	"github.com/tunnexio/tunnex/apps/api/internal/metrics"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpn"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func main() {
	cfg := config.Load()

	logger := applog.New(cfg.LogLevel)
	slog.SetDefault(logger)

	// --- S0.3: bootstrap roots of trust (fail loudly, never regenerate) ---
	// S10.1: an operator-provided master/session source pre-empts the volume (an
	// ephemeral K8s pod has no writable secrets volume). File-mount is preferred;
	// env is a weaker fallback — warn on it so the posture is visible in the log.
	ext := secrets.ExternalSecrets{
		Master:  secrets.ExternalSource{File: cfg.MasterKeyFile, Value: cfg.MasterKey},
		Session: secrets.ExternalSource{File: cfg.SessionSecretFile, Value: cfg.SessionSecret},
	}
	if cfg.MasterKey != "" && cfg.MasterKeyFile == "" {
		logger.Warn("master_key_from_env",
			slog.String("advice", "prefer TUNNEX_MASTER_KEY_FILE (a mounted secret) — env leaks via process listing, crash dumps, and kubectl describe"),
		)
	}
	sec, err := secrets.LoadOrInitExt(cfg.SecretsDir, ext)
	if err != nil {
		logger.Error("secrets_bootstrap_failed",
			slog.String("secrets_dir", cfg.SecretsDir),
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		logger.Error("sealer_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := crypto.SelfTest(sealer); err != nil {
		logger.Error("crypto_selftest_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ⛔ A DEPLOYMENT WITH NO SMTP SAYS SO AT STARTUP, LOUDLY — not when an invitation is sent and an
	// operator is watching a spinner while a recipient waits for a link that never comes.
	//
	// ⚠ INVITATIONS ARE NOW THE ONLY WAY ANYONE JOINS. Without mail, a fresh deployment cannot admit a
	// second person at all — the CP admin can create invitations and nobody ever receives one. That is a
	// deployment which looks healthy on every screen and is unusable.
	if !mail.Configured(mail.Config{Host: cfg.SMTP.Host}) {
		fmt.Fprint(os.Stdout, "\n"+
			"==========================================================================\n"+
			"  ⛔ EMAIL IS NOT CONFIGURED — invitations cannot be delivered\n"+
			"==========================================================================\n\n"+
			"  Invitations are the only way people join this deployment, and password\n"+
			"  resets and email verification also depend on mail.\n\n"+
			"  Set these in .env and restart:\n"+
			"    SMTP_HOST      your provider's server, e.g. smtp.example.net\n"+
			"    SMTP_PORT      usually 587\n"+
			"    SMTP_FROM      the address mail is sent as\n"+
			"    SMTP_USERNAME  if your provider requires auth\n"+
			"    SMTP_PASSWORD  if your provider requires auth\n\n"+
			"  Until then, invitations are still CREATED and the dashboard shows a\n"+
			"  copyable link you can send yourself. Nothing silently succeeds.\n\n"+
			"==========================================================================\n\n")
	}

	mailCfg := mail.Config{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		From:     cfg.SMTP.From,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		// ⛔ ITS OWN VARIABLE (S12.13 D1). This read `!cfg.IsProduction()` — so TUNNEX_ENV, which says what
		// KIND of deployment this is, silently decided how mail behaved. Setting five SMTP variables
		// correctly still produced a mailer labelled `smtp+log` and a log line that said mail was not sent.
		// It was sending. One flag must not govern two unrelated things.
		DevLogging: cfg.SMTP.DevLog,
	}
	mailer := mail.New(mailCfg, logger)

	// Log fingerprints (never the secrets). Stable fingerprints across restarts
	// prove keys were reused, not regenerated.
	logger.Info("secrets_ready",
		slog.Bool("first_boot", sec.GeneratedAny),
		slog.String("master_key_fp", secrets.Fingerprint(sec.MasterKey)),
		slog.String("session_secret_fp", secrets.Fingerprint(sec.SessionSecret)),
		slog.String("mailer", mailer.Kind()),
	)

	// ⛔ THE BOOT LINE NAMES THE DESTINATION, NOT THE MECHANISM (S12.13 D2). `mailer=smtp+log` was accurate
	// and unreadable: the `+` says "SMTP and also a log copy" to one reader and "logs instead of SMTP" to
	// another, and the second reader has no way to discover they were wrong except by not receiving an
	// email. This says where mail goes, in words, so the question is answered at install rather than at the
	// first missing invitation.
	logger.Info("mail_destination", slog.String("mail_goes_to", mail.Destination(mailCfg)))

	// sealer and mailer are consumed by auth/SSO flows starting in EPIC 2.
	_ = sealer
	_ = mailer

	// --- S0.4: self-provision the schema so `docker compose up` just works ---
	if cfg.AutoMigrate {
		if cfg.DatabaseURL == "" {
			logger.Error("auto_migrate_failed", slog.String("error", "DATABASE_URL is empty"))
			os.Exit(1)
		}
		if err := db.Up(cfg.DatabaseURL); err != nil {
			logger.Error("auto_migrate_failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
		if v, dirty, ok, _ := db.Version(cfg.DatabaseURL); ok {
			logger.Info("schema_migrated", slog.Uint64("version", uint64(v)), slog.Bool("dirty", dirty))
		}
	}

	// Database connection pool (used by the tenancy services).
	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Error("db_pool_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	// S10.1/S6.6 validate-never-generate: pgxpool.New is LAZY, so an unreachable
	// EXTERNAL store would otherwise fail only on first query. Ping at boot so a bad
	// TUNNEX_DATABASE_URL fails LOUD here, not later under a user request.
	{
		pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := pool.Ping(pingCtx); err != nil {
			cancel()
			logger.Error("db_unreachable",
				slog.Bool("external", cfg.ExternalDatabase),
				slog.String("error", err.Error()),
			)
			os.Exit(1)
		}
		cancel()
	}

	// Session store (Redis) + session-backed authentication.
	sessions, err := session.New(cfg.RedisURL, cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL)
	if err != nil {
		logger.Error("session_store_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// redis.NewClient is also lazy — ping so an unreachable external Redis fails loud at boot.
	{
		pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := sessions.Client().Ping(pingCtx).Err(); err != nil {
			cancel()
			logger.Error("redis_unreachable",
				slog.Bool("external", cfg.ExternalRedis),
				slog.String("error", err.Error()),
			)
			os.Exit(1)
		}
		cancel()
	}
	logger.Info("store_ready",
		slog.Bool("db_external", cfg.ExternalDatabase),
		slog.Bool("redis_external", cfg.ExternalRedis),
	)
	if !cfg.CookieSecure {
		logger.Warn("cookie_insecure",
			slog.String("warning", "session cookie Secure flag is OFF — development only; set TUNNEX_COOKIE_SECURE=true in production"))
	}
	// APP_BASE_URL builds every email link (verify, reset, invite). Left at the
	// localhost default on a remote deploy, those links point at localhost and are
	// UNREACHABLE from a user's machine — a silent, confusing failure (POC-surfaced).
	// Warn loudly so it's caught at boot, not by a user who can't verify their email.
	if cfg.AppBaseURLLooksLocal() {
		logger.Warn("app_base_url_local",
			slog.String("app_base_url", cfg.AppBaseURL),
			slog.String("warning", "APP_BASE_URL points at localhost — email verification/reset/invite links will be UNREACHABLE from other machines. Set APP_BASE_URL to this server's public URL for any non-local deployment."))
	}

	// Agent CA (root of trust for tunnex-node mTLS): load-or-create, sealed under
	// the master key, fail-loud on unusable, self-test at boot.
	agentCA, caFirstBoot, err := agentca.LoadOrCreate(context.Background(), sqlc.New(pool), sealer)
	if err != nil {
		logger.Error("agent_ca_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := agentCA.SelfTest(); err != nil {
		logger.Error("agent_ca_selftest_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("agent_ca_ready", slog.Bool("first_boot", caFirstBoot), slog.String("ca_fp", agentCA.Fingerprint()))

	authSvc := auth.NewService(pool, mailer, cfg.AppBaseURL, sessions, logger)
	// ⛔ ONE MANAGER, SHARED. Every gated question — gateway enrolment, org creation, SSO, IdP sync — must
	// read the SAME entitlement. Two managers would be two answers, and the one a capability happened to
	// hold would decide what a customer could do.
	//
	// ⚠ Its zero value is Community, which is the fail-open default: a deployment with no key is complete
	// and supported, not broken.
	// ⛔ READ-THROUGH, NOT LOAD-AT-BOOT. The manager was memory-only and an installed licence evaporated on
	// restart. Persisting alone would only have converted that into "the licence exists on some replicas and
	// not others" — N pods all SERVE (main.go's leadership note), and there is no cross-replica channel, so
	// a boot-cached verdict means a gateway enrolment refused by one pod succeeds on the next.
	//
	// ⚠ The TTL is the bounded window in which two replicas may disagree, and it is floored inside WithStore
	// because a zero — which is what an unset field is — would make this a database query per request.
	// ⛔ THE ONLY WAY INTO A FRESH DEPLOYMENT. There is no public signup, so without this a new install has
	// no account and no way to make one. Idempotent: on any deployment that has ever had a user it does
	// nothing and prints nothing — a restart must not be a security event.
	if e := bootstrap.EnsureAdmin(context.Background(), sqlc.New(pool), logger, os.Stdout, cfg.AdminEmail, mailer); e != nil {
		logger.Error("bootstrap_admin_failed", slog.String("err", e.Error()))
	}
	licenceMgr := (&licence.Manager{}).WithStore(
		apphttp.NewLicenceStore(pool), licence.DefaultRefreshInterval, logger)

	nodeSvc := nodes.NewService(pool, agentCA, sealer).WithLicence(licenceMgr)
	// S7.2: wire the Zero Trust policy source for the desired state (nil in the open
	// build -> no policy field -> agents keep the legacy mesh).
	nodeSvc.SetPolicyProvider(apphttp.NewNodePolicyProvider(pool))
	nodes.LogPolicyHealthTuning(logger) // S7.4b: assumed R + derived T (operator discoverability)
	pushHub := nodepush.New()
	deviceSvc := devices.NewService(pool, pushHub, logger).WithLicence(licenceMgr)
	// WF-OVPN-6: device-approval ENFORCEMENT follows the edition (enterprise only). The open build never
	// enforces approval, so a stored device_approval='on' can't trap new devices when the admin surface is
	// edition-gated away.
	deviceSvc.SetApprovalEnforced(apphttp.NewDeviceApprovalEdition())
	deviceSvc.SetDialResolver(nodeSvc.NodeDial) // WF-A D-WFA-6: a new device's config dials the active hub
	// S12.12 D7: the SAME derivation the dial resolver uses, asked as a set — which gateways a MANAGED device
	// can be transferred onto without re-issuing its config. Wired here rather than inferred at the call site
	// so the transfer's report and the device list's staleness answer the question from one place.
	deviceSvc.SetSelfHomingNodes(nodeSvc.SelfHomingNodes)
	siteSvc := sites.NewService(pool)
	k8sSvc := k8s.NewService(pool)
	k8sSvc.SetNotifier(pushHub) // M5: a K8s sweep (grant-cascading) rides the <5s push path, not the ~25s long-poll
	// S9.1 Part-2: the static-export enrichment source — the org's approved routed ranges (the SAME one
	// truth the Tunnex client polls, sites.ListRoutedRanges) + whether it has cross-site DNS forwarding.
	deviceSvc.SetExportEnrich(func(ctx context.Context, orgID uuid.UUID) ([]string, bool, error) {
		ranges, err := siteSvc.ListRoutedRanges(ctx, orgID)
		if err != nil {
			return nil, false, err
		}
		// hasDNS = "is there a REACHABLE resolver to bake into a static profile?" — derived from the SAME
		// routed-forwards the dynamic client gets (one truth), so it covers BOTH site DNS forwards AND the
		// S10.3 K8s cluster-zone → DNS-VIP resolvers. `ranges` now includes the K8s VIP ranges, so the K8s
		// resolver passes the reachability gate. (This also makes needs_reexport fire on a VIP-range change:
		// staticRanges is baked from `ranges`, which now carries the VIP ranges.)
		fwds, ferr := siteSvc.ListRoutedForwards(ctx, orgID, ranges)
		if ferr != nil {
			return nil, false, ferr
		}
		return ranges, len(fwds) > 0, nil
	})
	// OpenVPN control-plane service (S9.1, D-S9.1-6 open-edition). The client CA loads LAZILY
	// (D-S9.5-OPTIN(a)): generated on the first export in an opted-in org, NEVER at boot — so a
	// deployment that never uses OpenVPN has no OVPN CA row (the zero-config golden at the platform tier).
	ovpnSvc := ovpn.NewService(sqlc.New(pool), func(ctx context.Context) (*ovpnca.CA, error) {
		ca, _, err := ovpnca.LoadOrCreate(ctx, sqlc.New(pool), sealer)
		return ca, err
	}, sealer)
	// D-S9.6: deliver the gateway's OVPN server material as desired state (mint-once via EnsureServerCert).
	nodeSvc.SetOVPNServerCertProvider(func(ctx context.Context, orgID, nodeID uuid.UUID) (string, string, string, error) {
		return ovpnSvc.EnsureServerCert(ctx, orgID, nodeID, "gateway-"+nodeID.String())
	})
	// S9.1 Slice 5: the SHARED CRL rebuild seam wired to BOTH revocation paths (device revoke + node revoke),
	// plus CRL delivery (crl-verify always-on, lazy-inits an empty CRL).
	deviceSvc.SetRebuildCRL(ovpnSvc.RebuildCRL)
	nodeSvc.SetRebuildCRL(ovpnSvc.RebuildCRL)
	// S13.1: the full-sweep reconciliation signal a re-key fires AFTER its transaction commits. A re-key changes
	// the gateway's WireGuard public key, so every peer's AllowedIPs and every site link must reconcile — the same
	// org-wide fan-out devices.PushOrgNodes uses, reached through the same hub.
	nodeSvc.SetPushOrg(deviceSvc.PushOrgNodes)
	// S13.1 D5 (Wall 6): a recovered gateway brings its users back with it. Only cascade-revoked devices —
	// a deliberately revoked laptop is never revived by a gateway rebuild.
	nodeSvc.SetRestoreDevices(func(ctx context.Context, orgID, nodeID uuid.UUID) (int, int, error) {
		// Same node in both positions, and no actor: a re-keyed gateway keeps its devices where they were, and
		// no human was present — the gateway proved possession of its own key.
		res, err := deviceSvc.RestoreCascadeRevokedDevices(ctx, orgID, nodeID, nodeID, nil)
		if err != nil {
			return 0, 0, err
		}
		readdressed := 0
		for _, r := range res {
			if !r.KeptAddress {
				readdressed++
			}
		}
		return len(res), readdressed, nil
	})
	nodeSvc.SetOVPNCRLProvider(ovpnSvc.GetCRL)
	cliAuthSvc := cliauth.NewService(pool, sealer)
	machineAuthSvc := machineauth.NewService(pool, sealer) // S10.2: machine credentials (GitOps operator)
	mfaSvc := mfa.NewService(pool, sealer, mailer, logger)

	// S7.5.1 access-log health is SHARED: the flow-event Ingester (mTLS channel) records
	// JSONL-degraded + retention on it; the enterprise query port surfaces it. One instance.
	flowHealth := accesslog.NewHealth()

	// ⛔ THE CRL REBUILD IS WIRED HERE OR DEACTIVATION'S CERT REVOCATION NEVER REACHES A GATEWAY. The certs
	// are marked revoked in the transaction either way; without this the org's published CRL stays stale
	// until some other path rebuilds it, and the refusal falls back to ccd-exclusive alone.
	membersSvc := tenancy.NewMembershipService(pool, sessions).
		WithDevicePusher(deviceSvc).
		WithCRLRebuilder(ovpnCRLRebuilder{ovpnSvc})
	idpSyncPort := apphttp.NewIdpSyncPort(pool, sealer, membersSvc, deviceSvc, licenceMgr, logger)
	var releaseStatus *release.Status
	var releaseBootstrap *release.BootstrapRelease
	currentRelease := release.Current{Sequence: cfg.ReleaseSequence, Version: cfg.ReleaseVersion, SourceSHA: cfg.ReleaseSourceSHA, Protocol: policyspec.ProtocolVersion}
	if cfg.ReleaseManifestPath != "" {
		signed, loadErr := release.Load(cfg.ReleaseManifestPath, cfg.ReleasePublicKey)
		if loadErr != nil {
			logger.Warn("release_manifest_unavailable", slog.String("error", loadErr.Error()))
			// Keep the failure visible to authenticated operators. A configured but
			// unverifiable release descriptor is evidence that the installation's
			// trusted update metadata is missing or tampered; hiding the upgrade
			// surface makes recovery needlessly opaque. Never mark it available.
			releaseStatus = &release.Status{
				Verified:       false,
				State:          "failed",
				Reason:         "installation verification failed; updates are blocked",
				PreflightState: "unknown",
				BackupState:    "unknown",
				RollbackState:  "available",
				ApprovalMode:   "host_command_only",
			}
		} else {
			if metadata, metadataErr := release.BootstrapReleaseFromSigned(signed, cfg.ReleaseManifestURL); metadataErr == nil {
				releaseBootstrap = &metadata
			} else {
				logger.Warn("bootstrap_release_metadata_unavailable", slog.String("error", metadataErr.Error()))
			}
			// The installed descriptor is itself the authoritative provenance for a
			// fresh install. Do not rely on optional dotenv copies of those fields.
			currentRelease.Sequence = signed.Manifest.Sequence
			currentRelease.Version = signed.Manifest.Version
			currentRelease.SourceSHA = signed.Manifest.SourceSHA
			status := release.Compare(currentRelease, signed.Manifest)
			releaseStatus = &status
		}
	}
	var releaseStatusProvider func() *release.Status
	var stopReleasePoll func()
	if cfg.ReleaseUpdateCheck && cfg.ReleaseCatalogURL != "" && (releaseStatus == nil || releaseStatus.Verified) {
		checker := release.NewChecker(currentRelease, cfg.ReleasePublicKey, cfg.ReleaseCatalogURL, releaseStatus)
		releaseStatusProvider = checker.Status
		releasePollCtx, cancelReleasePoll := context.WithCancel(context.Background())
		stopReleasePoll = cancelReleasePoll
		go func() {
			refresh := func() {
				if err := checker.Refresh(releasePollCtx); err != nil {
					logger.Debug("release_catalog_refresh_failed", slog.String("error", err.Error()))
				}
			}
			refresh()
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-releasePollCtx.Done():
					return
				case <-ticker.C:
					refresh()
				}
			}
		}()
	}

	systemQueries := sqlc.New(pool)
	alertPublisher := alerts.NewOutboxPublisher(alerts.NewPostgresOutbox(pool))
	router, err := apphttp.NewRouter(logger, apphttp.Deps{
		System: systemQueries,
		AgentRuntimeOptIn: agentruntime.OrganizationOptIn(systemQueries, func() bool {
			return licenceMgr.Evaluate(time.Now()).Tier != licence.TierCommunity
		}),
		AgentRuntimeNotify:    pushHub,
		AlertPublisher:        alertPublisher,
		AlertConfig:           alerts.NewConfigService(pool, sealer, mailer),
		Licence:               licenceMgr,
		Orgs:                  tenancy.NewService(pool).WithLicence(licenceMgr),
		CliAuth:               cliAuthSvc,
		Machine:               machineAuthSvc,
		Auth:                  authSvc,
		Members:               membersSvc,
		Invites:               invites.NewService(pool, mailer, cfg.AppBaseURL, logger),
		Nodes:                 nodeSvc,
		Devices:               deviceSvc,
		Ovpn:                  ovpnSvc,
		Sites:                 siteSvc,
		K8s:                   k8sSvc,
		Sessions:              sessions,
		Mfa:                   mfaSvc,
		SSO:                   apphttp.NewSSOPort(pool, sealer, sessions.Client(), cfg.AppBaseURL, licenceMgr, logger),
		Policy:                apphttp.NewPolicyPort(pool, pushHub),
		AgentTemplates:        apphttp.NewAgentTemplatePort(pool, deviceSvc),
		AgentAccess:           apphttp.NewAgentAccessPort(pool, deviceSvc),
		AccessLog:             apphttp.NewAccessLogPort(pool, flowHealth),
		IdpSync:               idpSyncPort,
		DeviceApprovalEnabled: apphttp.NewDeviceApprovalEdition(),
		DeviceHealthEnabled:   apphttp.NewDeviceHealthEdition(),
		MfaEnforceEnabled:     apphttp.NewMfaEnforceEdition(),
		CookieSecure:          cfg.CookieSecure,
		AppBaseURL:            cfg.AppBaseURL,
		GatewayControlURL:     cfg.GatewayControlURL,
		NodeAgentImage:        cfg.NodeAgentImage,
		ReleaseStatus:         releaseStatus,
		ReleaseBootstrap:      releaseBootstrap,
		ReleaseStatusProvider: releaseStatusProvider,
		SMTPConfigured:        mail.Configured(mail.Config{Host: cfg.SMTP.Host}),
		CORSAllowedOrigins:    cfg.CORSAllowedOrigins,
		AuthFn:                apphttp.SessionAuth(sessions, sqlc.New(pool)),
		BearerFn:              apphttp.BearerAuth(sqlc.New(pool)),
		MachineFn:             apphttp.MachineAuth(sqlc.New(pool)), // S10.2: `tnxm_` machine credential (GitOps operator)
	})
	if err != nil {
		logger.Error("router_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if stopReleasePoll != nil {
		defer stopReleasePoll()
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// mTLS agent control channel (separate listener; client certs verified vs CA).
	agentCh := apphttp.NewAgentChannel(nodeSvc, agentCA, pushHub, logger)
	// S7.5.1 flow-event ingest: the PG hot-window (queryable access-event store), wired onto the
	// SAME mTLS channel (node identity = client cert). (S7.5.1b) the JSONL on-disk source-of-truth
	// + verbatim export are DEFERRED — v1 is PG-only.
	retentionStop := make(chan struct{})
	fq := sqlc.New(pool)
	agentCh.SetFlowIngester(accesslog.NewIngester(pool, accesslog.SQLGrantResolver{Q: fq}, accesslog.SQLDeviceResolver{Q: fq}, flowHealth, nil))
	// D3 retention sweep: without this loop access_events grows unbounded and exhausts the DB
	// disk. Run it on an interval: delete by ingest age + trim each org to the row cap. Drop-count
	// + failure land on flowHealth.
	// S11 D4: scheduler leadership. N replicas all SERVE; exactly one TICKS. The election is a Postgres
	// session-scoped advisory lock, so a dead leader's lock is released by the database itself — no TTL, no
	// clock comparison, and two leaders are impossible by construction (the safe failure direction: a gap
	// with nothing ticking, never a double failover promotion or a double CRL rebuild).
	// The elector's context is cancelled at shutdown BEFORE pool.Close() (deferred at startup, so it runs
	// last): leadership holds a dedicated connection for its whole duration, and pgxpool.Close blocks until
	// every acquired connection is released. Cancel-then-close is therefore the required order, and getting
	// it backwards deadlocks shutdown — found by a test that hung on exactly that.
	electorCtx, stopElector := context.WithCancel(context.Background())
	defer stopElector()
	elector := &leader.Elector{}
	go elector.Run(electorCtx, pool, logger)

	go func() {
		t := time.NewTicker(accesslog.RetentionSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-retentionStop:
				return
			case <-t.C:
				// S13.1 review #2/#3: gate cheaply, CONFIRM against Postgres, and derive the work context from
				// electorCtx so losing leadership cancels work in flight. Previously every tick used
				// context.Background(), so an ex-leader kept writing for minutes after the lock had moved.
				if !elector.IsLeader() || !elector.ConfirmLeader(electorCtx, pool) {
					continue
				}
				sctx, scancel := context.WithTimeout(electorCtx, 2*time.Minute)
				orgs, err := fq.DistinctAccessEventOrgs(sctx)
				if err == nil {
					_, err = accesslog.Retain(sctx, fq, flowHealth, time.Now(), 0, 0, orgs)
				}
				if err != nil {
					logger.Error("flowlog_retention_sweep_failed", slog.String("error", err.Error()))
				}
				scancel()
			}
		}
	}()
	// S13.1 (review #5): sweep spent and expired re-key challenges. node_rekey_challenges is written by an
	// UNAUTHENTICATED endpoint — one row per challenge request, for any serial asked about, valid or not — and
	// migration 0058's own comment plus its expires_at index describe pruning that no code performed. Without this
	// loop the table grows until the Postgres volume fills, which is the same failure the flow-log retention sweep
	// above exists to prevent, on a table an attacker can write to directly.
	//
	// Leader-gated like every other tick (D4): pruning twice is harmless, but there is no reason to spend two
	// replicas on it, and gating keeps "exactly one ticks" true of the whole set rather than most of it.
	//
	// Consumed rows are retained for an hour past expiry by the query itself, deliberately: a replayed nonce must
	// keep failing as SPENT rather than becoming unknown, or the log loses the distinction between an attack and a
	// typo.
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-retentionStop:
				return
			case <-t.C:
				// Same as the sweep above — and this tick is one I added in S13.1 by copying the defective
				// context.Background() pattern from its neighbour without checking what it inherited.
				if !elector.IsLeader() || !elector.ConfirmLeader(electorCtx, pool) {
					continue
				}
				sctx, scancel := context.WithTimeout(electorCtx, time.Minute)
				if n, err := fq.DeleteExpiredRekeyChallenges(sctx); err != nil {
					logger.Error("rekey_challenge_sweep_failed", slog.String("error", err.Error()))
				} else if n > 0 {
					logger.Info("rekey_challenge_sweep", slog.Int64("deleted", n))
				}
				scancel()
			}
		}
	}()

	// S8.6 hub-HA failover tick: read member freshness → derive the active hub order → on a change, persist
	// (atomic generation bump) + audit + let the ordinary compile+push carry it. Rides the same
	// ticker-goroutine pattern as the retention sweep; a no-op for orgs without a multi-member hub set.
	go func() {
		t := time.NewTicker(nodes.FailoverTickInterval)
		defer t.Stop()
		for {
			select {
			case <-retentionStop:
				return
			case <-t.C:
				// The FAILOVER tick is where two writers hurt most: its hysteresis counters are PER-PROCESS, so
				// two leaders compute DIFFERENT demoted sets and write contradictory promotion/failback audits
				// for the same org. Confirm against Postgres (IsLeader alone can be up to RetryInterval stale),
				// and run on electorCtx so losing the lock mid-walk cancels the walk instead of letting an
				// ex-leader keep bumping generations for minutes.
				if !elector.IsLeader() || !elector.ConfirmLeader(electorCtx, pool) {
					continue
				}
				sctx, scancel := context.WithTimeout(electorCtx, 2*time.Minute)
				if err := nodeSvc.RunFailoverTick(sctx); err != nil {
					logger.Error("failover_tick_failed", slog.String("error", err.Error()))
				}
				scancel()
			}
		}
	}()
	// S9.1 Slice 5 (D-S9.5-1a): the scheduled CRL refresh — regenerate every OVPN-enabled org's CRL well
	// inside CRLValidity (30d) so no CRL ever EXPIRES (an expired CRL can fail-OPEN, silently un-revoking a
	// fleet). A content no-op when nothing changed — just a fresh nextUpdate + bumped number. 12h << 30d.
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-retentionStop:
				return
			case <-t.C:
				if !elector.IsLeader() || !elector.ConfirmLeader(electorCtx, pool) {
					continue
				}
				sctx, scancel := context.WithTimeout(electorCtx, 5*time.Minute)
				if orgs, err := sqlc.New(pool).ListOVPNEnabledOrgs(sctx); err != nil {
					logger.Error("ovpn_crl_refresh_list_failed", slog.String("error", err.Error()))
				} else {
					for _, org := range orgs {
						if err := ovpnSvc.RebuildCRL(sctx, org); err != nil {
							logger.Error("ovpn_crl_refresh_failed", slog.String("org_id", org.String()), slog.String("error", err.Error()))
						}
					}
				}
				scancel()
			}
		}
	}()
	// S7.5.2 IdP-group sync poller (enterprise; no-op in the open build). Reconciles mapped
	// directory groups every ~10min. Cancelled on shutdown.
	pollCtx, pollCancel := context.WithCancel(context.Background())
	// ONE DEFINITION of "may I tick" (S13.1 review #10). The documented invariant is "N replicas serve, exactly one
	// ticks" — and it was false of the whole set: three periodic WRITERS (IdP group sync, grant expiry, health
	// staleness) ran un-gated on every replica, so a reader reasoning about the invariant reasoned about the wrong
	// deployment. Cheap flag first, then confirm against Postgres, because IsLeader alone can be stale for up to
	// RetryInterval.
	mayTick := func() bool { return elector.IsLeader() && elector.ConfirmLeader(electorCtx, pool) }
	// F11 drains the durable alert outbox only from the elected writer. Delivery
	// rows are claimed before outbound I/O, so serving replicas may all accept
	// configuration while exactly one process sends a subscribed notification.
	alertDispatcher := alerts.NewDispatcher(sqlc.New(pool), alerts.NewWebhookSender(sealer, mailer))
	alertConditions := alerts.NewConditionScanner(alerts.NewPostgresConditionStore(pool), alertPublisher)
	go func() {
		t := time.NewTicker(alerts.DispatchInterval)
		defer t.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-t.C:
				if !mayTick() {
					continue
				}
				ctx, cancel := context.WithTimeout(electorCtx, 2*time.Minute)
				if err := alertDispatcher.RunOnce(ctx); err != nil {
					logger.Error("alert_delivery_tick_failed", slog.String("error", err.Error()))
				}
				cancel()
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-t.C:
				if !mayTick() {
					continue
				}
				ctx, cancel := context.WithTimeout(electorCtx, time.Minute)
				if err := alertConditions.RunOnce(ctx); err != nil {
					logger.Error("alert_condition_tick_failed", slog.String("error", err.Error()))
				}
				cancel()
			}
		}
	}()
	apphttp.StartIdpSyncPoller(pollCtx, idpSyncPort, logger, mayTick)
	// S7.5.4 temporary-grant expiry sweep (enterprise only; no-op in the open build):
	// a lapsed temporary grant's /32 is pushed off every org gateway promptly. Shares
	// pollCtx (cancelled on shutdown).
	apphttp.StartPolicyGrantSweeper(pollCtx, pool, pushHub, mayTick)
	// F10 JIT approvals own their request-bound rule expiry. The generic policy
	// sweeper intentionally excludes those rows; the elected writer advances the
	// workflow, audit and gateway push atomically here.
	apphttp.StartAgentAccessSweeper(pollCtx, pool, deviceSvc, mayTick)
	// S7.5.3 device-health staleness sweep (enterprise only): a stale report is
	// ABSENCE, and absence never blocks — clears health_blocked past the TTL and
	// pushes the affected orgs. Shares pollCtx (cancelled on shutdown).
	if apphttp.NewDeviceHealthEdition() {
		go deviceSvc.StartHealthSweeper(pollCtx, mayTick)
	} else {
		// DOWNGRADE-RELEASE ([1]): device-health is OFF in this build, so no report
		// will arrive and the sweeper never runs — a device left health_blocked by a
		// prior ENTERPRISE deployment would be excluded from every gateway FOREVER
		// (silent permanent network loss). Disabling a feature must RELEASE its
		// enforcement (the downgrade mirror of unlock-then-opt-in). Best-effort at
		// boot; the interval reconcile still converges if the push is missed.
		if n, err := deviceSvc.ReleaseAllHealthBlocks(context.Background()); err != nil {
			logger.Warn("health_downgrade_release_failed", slog.String("error", err.Error()))
		} else if n > 0 {
			logger.Info("health_downgrade_release", slog.Int("released", n))
		}
	}

	agentTLS, err := agentCh.TLSConfig("tunnex-control")
	if err != nil {
		logger.Error("agent_channel_tls_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	agentSrv := &http.Server{
		Addr:              cfg.AgentAddr,
		Handler:           agentCh.Handler(),
		TLSConfig:         agentTLS,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("agent_channel_starting", slog.String("addr", cfg.AgentAddr))
		if err := agentSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("agent_channel_failed", slog.String("error", err.Error()))
		}
	}()

	// S11 D3.1-D3.3: the metrics + readiness listener, on its OWN port (never the public router) and
	// bound to loopback unless explicitly configured otherwise — so operational fleet data cannot become
	// internet-reachable by a default nobody revisited. FleetHealthCounts reads the SAME PolicyHealthForNodes
	// the dashboard reads, so the metric and the console can never disagree about what a kind means.
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()
	go func() {
		reg := metrics.NewRegistry(func() map[nodes.PolicyDegradedKind]int {
			// Bound the scrape's DB work: a slow fleet walk must never hold the scraper open.
			ctx, cancel := context.WithTimeout(metricsCtx, 10*time.Second)
			defer cancel()
			return nodeSvc.FleetHealthCounts(ctx)
		}, elector.IsLeader)
		// readiness = the DB answers. A CP that cannot reach postgres serves nothing useful, and naming the
		// reason beats a bare 503 (diagnosis-from-logs at the readiness tier).
		ready := func() error { return pool.Ping(metricsCtx) }
		if err := metrics.Serve(metricsCtx, cfg.MetricsAddr, reg, ready, logger, elector.IsLeader); err != nil {
			logger.Error("metrics_listener_failed", slog.String("error", err.Error()))
		}
	}()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("api_starting",
			slog.String("addr", cfg.Addr),
			slog.String("env", cfg.Env),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		logger.Error("api_failed", slog.String("error", err.Error()))
		os.Exit(1)
	case sig := <-stop:
		logger.Info("api_shutting_down", slog.String("signal", sig.String()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = agentSrv.Shutdown(ctx)
	pollCancel()         // stop the idp-sync poller
	stopElector()        // release scheduler leadership (and its connection) before the pool closes
	close(retentionStop) // stop the retention sweep loop
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("api_shutdown_error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("api_stopped")
}

// ovpnCRLRebuilder adapts the OVPN service to tenancy.CRLRebuilder — a one-method seam so the tenancy
// package does not import the ovpn package (and cannot grow a dependency on its edition-gated surface).
type ovpnCRLRebuilder struct{ svc *ovpn.Service }

func (r ovpnCRLRebuilder) RebuildCRL(ctx context.Context, orgID uuid.UUID) error {
	return r.svc.RebuildCRL(ctx, orgID)
}
