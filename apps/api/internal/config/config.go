// Package config loads runtime configuration from the environment.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/metrics"
)

// Config holds the process configuration resolved at startup.
type Config struct {
	// Addr is the host:port the HTTP server binds to.
	Addr string
	// AgentAddr is the host:port the mTLS agent control channel binds to (S3.1).
	AgentAddr string
	// MetricsAddr is the host:port the metrics + readiness listener binds to (S11 D3.2). It is a SEPARATE
	// listener from the public API so operational data never rides the public router, and it defaults to
	// LOOPBACK: on a VM, a 0.0.0.0 metrics endpoint is internet-reachable the moment a security group is
	// loose, so remote scraping is opt-in by explicit configuration rather than a default to document
	// against. Set it to a private interface (VM) or 0.0.0.0 (a k8s pod behind an unexposed Service).
	MetricsAddr string
	// Env is the deployment environment name (development, production).
	Env string
	// LogLevel controls the minimum slog level (debug, info, warn, error).
	LogLevel string
	// SecretsDir is the dedicated volume holding the roots of trust (S0.3).
	SecretsDir string
	// External roots of trust (S10.1): an operator-provided master/session key
	// that PRE-EMPTS the volume file — for an ephemeral K8s pod with no writable
	// secrets volume. *File (a mounted secret path) is PREFERRED; * (inline
	// base64 via env) is the documented fallback (env leaks via process listing /
	// crash dump / kubectl describe). Empty = use the volume (self-hosted default).
	MasterKeyFile     string
	MasterKey         string
	SessionSecretFile string
	SessionSecret     string
	// DatabaseURL is the postgres DSN (S0.4).
	DatabaseURL string
	// AutoMigrate runs pending migrations on boot so `docker compose up`
	// self-provisions the schema (S0.4).
	AutoMigrate bool
	// AppBaseURL is the public base URL used to build email links (S2.1).
	AppBaseURL string
	// GatewayControlURL is the optional deployment-wide raw mTLS endpoint used in new gateway commands.
	// Empty keeps the backward-compatible derivation from AppBaseURL:8443.
	GatewayControlURL string
	// AdminEmail receives the one-time first-run administrator credential when SMTP is configured.
	// Empty falls back to bootstrap's local address for non-installer deployments.
	AdminEmail string
	// NodeAgentImage is the gateway agent image the dashboard bakes into the emitted enroll command
	// (S8.2c WF-2). One-truth applied to the artifact version: pin it to a DIGEST
	// (ghcr.io/…/tunnex-node-agent@sha256:…) and the stale-`:latest` drift that mis-convicted D2 becomes
	// structurally impossible. Defaults to the `:latest` ref (matches the compose default).
	NodeAgentImage string
	// K8sHAEnabled is the deployment composition gate for connector ownership
	// HA. It defaults OFF independently of edition and organization settings.
	K8sHAEnabled bool
	// Release metadata is an operator-provided, signed descriptor. Empty path means
	// the upgrade center is unavailable rather than guessing from a mutable tag.
	ReleaseManifestPath string
	ReleaseManifestURL  string
	ReleasePublicKey    string
	ReleaseSequence     int64
	ReleaseVersion      string
	ReleaseSourceSHA    string
	// ReleaseCatalogURL is the signed online discovery pointer. Empty disables
	// network update checks for deliberately air-gapped deployments.
	ReleaseCatalogURL  string
	ReleaseUpdateCheck bool
	// HostUpgrade paths are mounted only by the single-host Docker installer.
	// Empty keeps Kubernetes and development deployments read-only.
	HostUpgradeRequestPath string
	HostUpgradeStatusPath  string
	// RedisURL is the session store DSN (S2.2).
	RedisURL string
	// ExternalDatabase / ExternalRedis are true when TUNNEX_DATABASE_URL /
	// TUNNEX_REDIS_URL were supplied (S10.1 / S6.6 URL-WINS). An external store is
	// validated at boot (fail-loud on unreachable) and never credential-generated;
	// the bundled pg/redis are not started (compose profile). The shared env seam
	// with the Helm chart — compose and K8s must not diverge (docs/S6.6-decisions.md).
	ExternalDatabase bool
	ExternalRedis    bool
	// CookieSecure sets the Secure flag on the session cookie. MUST be true in
	// production; a false value is logged loudly at boot.
	CookieSecure bool
	// SessionIdleTTL is the sliding inactivity timeout (S2.2).
	SessionIdleTTL time.Duration
	// SessionAbsoluteTTL is the hard maximum session lifetime (S2.2).
	SessionAbsoluteTTL time.Duration
	// CORSAllowedOrigins are the EXACT origins allowed to make cross-origin,
	// BEARER-authenticated requests (S6.2 desktop client, whose renderer origin
	// is app://tunnex). Credentials (cookies) are NEVER allowed cross-origin, so
	// this cannot weaken the same-origin cookie/CSRF posture. Comma-separated.
	CORSAllowedOrigins []string
	// SMTP holds mail delivery configuration (S0.3).
	SMTP SMTP
}

// SMTP holds outbound mail settings.
type SMTP struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string
	// DevLog tees safe metadata for every outgoing message to the log IN ADDITION TO SENDING IT
	// (MAIL_DEV_LOG, default off); message bodies are never logged.
	//
	// ⛔ IT IS ITS OWN VARIABLE, AND THAT IS THE RULING (S12.13 D1). This used to be `!IsProduction()` — so
	// TUNNEX_ENV, a variable about what kind of deployment this is, silently governed mail behaviour. The
	// founder set five SMTP variables, got a `smtp+log` mailer and a log line reading "email_not_sent", and
	// spent a session concluding mail was disabled. ONE FLAG MUST NOT GOVERN TWO UNRELATED THINGS.
	//
	// ⚠ IT NEVER SUPPRESSES DELIVERY, and never did — the tee sends and also logs. It remains opt-in so
	// operators do not mistake metadata diagnostics for delivery confirmation.
	DevLog bool
}

// IsProduction reports whether the process runs in a production environment.
func (c Config) IsProduction() bool { return c.Env == "production" }

// AppBaseURLLooksLocal reports whether AppBaseURL points at the local host. On a
// remote deploy this is a misconfiguration: every email link (verify/reset/invite)
// would point at localhost and be unreachable from the user's machine. Boot warns
// loudly on it (POC-surfaced: a remote deploy shipped localhost verify links).
func (c Config) AppBaseURLLooksLocal() bool {
	if c.AppBaseURL == "" {
		return true // unset is not a reachable remote URL either
	}
	for _, local := range []string{"localhost", "127.0.0.1", "0.0.0.0"} {
		if strings.Contains(c.AppBaseURL, local) {
			return true
		}
	}
	return false
}

// Load reads configuration from the environment, applying sane defaults so the
// server runs with zero configuration during development.
func Load() Config {
	return Config{
		Addr:                   getenv("TUNNEX_API_ADDR", ":8080"),
		AgentAddr:              getenv("TUNNEX_AGENT_ADDR", ":8443"),
		MetricsAddr:            getenv("TUNNEX_METRICS_ADDR", metrics.DefaultAddr),
		Env:                    getenv("TUNNEX_ENV", "development"),
		LogLevel:               strings.ToLower(getenv("TUNNEX_LOG_LEVEL", "info")),
		SecretsDir:             getenv("TUNNEX_SECRETS_DIR", "/var/lib/tunnex/secrets"),
		MasterKeyFile:          getenv("TUNNEX_MASTER_KEY_FILE", ""),
		MasterKey:              getenv("TUNNEX_MASTER_KEY", ""),
		SessionSecretFile:      getenv("TUNNEX_SESSION_SECRET_FILE", ""),
		SessionSecret:          getenv("TUNNEX_SESSION_SECRET", ""),
		DatabaseURL:            firstNonEmpty(getenv("TUNNEX_DATABASE_URL", ""), getenv("DATABASE_URL", "")),
		ExternalDatabase:       getenv("TUNNEX_DATABASE_URL", "") != "",
		ExternalRedis:          getenv("TUNNEX_REDIS_URL", "") != "",
		AutoMigrate:            getbool("TUNNEX_AUTO_MIGRATE", true),
		AppBaseURL:             getenv("APP_BASE_URL", "http://localhost"),
		GatewayControlURL:      getenv("TUNNEX_GATEWAY_CONTROL_URL", ""),
		AdminEmail:             getenv("TUNNEX_ADMIN_EMAIL", ""),
		NodeAgentImage:         getenv("TUNNEX_NODE_AGENT_IMAGE", "ghcr.io/tunnexio/tunnex-node-agent:latest"),
		K8sHAEnabled:           getbool("TUNNEX_K8S_HA_ENABLED", false),
		ReleaseManifestPath:    getenv("TUNNEX_RELEASE_MANIFEST_PATH", ""),
		ReleaseManifestURL:     getenv("TUNNEX_RELEASE_MANIFEST_URL", ""),
		ReleasePublicKey:       getenv("TUNNEX_RELEASE_PUBLIC_KEY", ""),
		ReleaseSequence:        getint64("TUNNEX_RELEASE_SEQUENCE", 0),
		ReleaseVersion:         getenv("TUNNEX_RELEASE_VERSION", ""),
		ReleaseSourceSHA:       getenv("TUNNEX_RELEASE_SOURCE_SHA", ""),
		ReleaseCatalogURL:      releaseCatalogURL(getenv("TUNNEX_ENV", "development")),
		ReleaseUpdateCheck:     getbool("TUNNEX_RELEASE_UPDATE_CHECK", true),
		HostUpgradeRequestPath: getenv("TUNNEX_HOST_UPGRADE_REQUEST_PATH", ""),
		HostUpgradeStatusPath:  getenv("TUNNEX_HOST_UPGRADE_STATUS_PATH", ""),
		RedisURL:               firstNonEmpty(getenv("TUNNEX_REDIS_URL", ""), getenv("REDIS_URL", "redis://redis:6379/0")),
		CookieSecure:           getbool("TUNNEX_COOKIE_SECURE", false),
		SessionIdleTTL:         getdur("TUNNEX_SESSION_IDLE_TTL", 24*time.Hour),
		SessionAbsoluteTTL:     getdur("TUNNEX_SESSION_ABSOLUTE_TTL", 720*time.Hour),
		CORSAllowedOrigins:     splitList(getenv("TUNNEX_CORS_ALLOWED_ORIGINS", "app://tunnex")),
		SMTP: SMTP{
			Host:     getenv("SMTP_HOST", ""),
			Port:     getenv("SMTP_PORT", "1025"),
			From:     getenv("SMTP_FROM", "no-reply@tunnex.local"),
			Username: getenv("SMTP_USERNAME", ""),
			Password: getenv("SMTP_PASSWORD", ""),
			// DEFAULT OFF. The previous default was "on unless production", which is the same thing said in a
			// way that hides it: a developer, a founder's rig and a staging box all got the tee without asking.
			DevLog: getbool("MAIL_DEV_LOG", false),
		},
	}
}

func releaseCatalogURL(env string) string {
	if value, set := os.LookupEnv("TUNNEX_RELEASE_CATALOG_URL"); set {
		return strings.TrimSpace(value)
	}
	if env == "production" {
		return "https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json"
	}
	return ""
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstNonEmpty returns a if set, else b (URL-WINS: a TUNNEX_-prefixed external
// URL pre-empts the bundled default).
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getdur(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func getbool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getint64(key string, fallback int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}
