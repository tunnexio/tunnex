package config

import (
	"os"
	"testing"
)

func TestAppAccessRestoreMarkerConfig(t *testing.T) {
	t.Setenv("TUNNEX_APP_ACCESS_RESTORE_MARKER", "")
	if Load().AppAccessRestoreMarker != "" {
		t.Fatal("restore marker must remain opt-in")
	}
	t.Setenv("TUNNEX_APP_ACCESS_RESTORE_MARKER", "/operator/restore.pending")
	if Load().AppAccessRestoreMarker != "/operator/restore.pending" {
		t.Fatal("restore marker environment was not loaded")
	}
}

func TestAppAccessRestoreMarkerRequiredForConfiguredAuthority(t *testing.T) {
	for _, c := range []Config{{AppAccessBaseDomain: "apps.example.net"}, {AppProxyAuthorityAddr: ":18448"}, {AppAccessRestoreMarker: "relative.marker"}, {AppAccessBaseDomain: "apps.example.net", AppAccessRestoreMarker: "relative.marker"}} {
		if c.ValidateAppAccessRestoreMarker() == nil {
			t.Fatal("configured authority admitted missing/relative restore fence")
		}
	}
	for _, c := range []Config{{}, {AppAccessBaseDomain: "apps.example.net", AppAccessRestoreMarker: "/operator/restore.pending"}, {AppProxyAuthorityAddr: ":18448", AppAccessRestoreMarker: "/operator/restore.pending"}} {
		if err := c.ValidateAppAccessRestoreMarker(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAppBaseURLLooksLocal guards the boot-time misconfiguration warning: a remote
// deploy left at the localhost default ships unreachable email links (POC-surfaced).
func TestAppBaseURLLooksLocal(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://localhost", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1", true},
		{"http://0.0.0.0", true}, // bind-any, unreachable as a public link
		{"http://0.0.0.0:8080", true},
		{"", true}, // unset — no reachable URL
		{"https://tunnex.example.com", false},
		{"http://40.65.63.141", false}, // a real remote IP — not local
	}
	for _, c := range cases {
		if got := (Config{AppBaseURL: c.url}).AppBaseURLLooksLocal(); got != c.want {
			t.Errorf("AppBaseURLLooksLocal(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

// TestShippedDefaultTripsLocalWarning is the POC's ACTUAL case: neither .env.example
// nor compose sets APP_BASE_URL, so a remote deploy runs on the code default —
// which MUST trip the warning. Asserts against Load() (the real default source),
// not a hand-written literal, so a future default change can't silently pass.
func TestShippedDefaultTripsLocalWarning(t *testing.T) {
	os.Unsetenv("APP_BASE_URL")
	if !Load().AppBaseURLLooksLocal() {
		t.Fatalf("shipped APP_BASE_URL default (%q) must trip the local-URL warning", Load().AppBaseURL)
	}
}

// S10.1/S6.6 URL-WINS: TUNNEX_DATABASE_URL / TUNNEX_REDIS_URL pre-empt the bundled
// defaults and flag the store external (validated at boot, never credential-generated).
func TestExternalStoreURLWins(t *testing.T) {
	t.Setenv("TUNNEX_DATABASE_URL", "postgres://ext-db/app")
	t.Setenv("DATABASE_URL", "postgres://bundled/app")
	t.Setenv("TUNNEX_REDIS_URL", "redis://ext-redis:6379/0")
	t.Setenv("REDIS_URL", "redis://bundled:6379/0")
	c := Load()
	if c.DatabaseURL != "postgres://ext-db/app" || !c.ExternalDatabase {
		t.Fatalf("external DB URL must win + flag external; got %q external=%v", c.DatabaseURL, c.ExternalDatabase)
	}
	if c.RedisURL != "redis://ext-redis:6379/0" || !c.ExternalRedis {
		t.Fatalf("external Redis URL must win + flag external; got %q external=%v", c.RedisURL, c.ExternalRedis)
	}
}

func TestBundledStoreWhenNoExternal(t *testing.T) {
	t.Setenv("TUNNEX_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "postgres://bundled/app")
	t.Setenv("TUNNEX_REDIS_URL", "")
	t.Setenv("REDIS_URL", "")
	c := Load()
	if c.DatabaseURL != "postgres://bundled/app" || c.ExternalDatabase {
		t.Fatalf("bundled DB URL used, not external; got %q external=%v", c.DatabaseURL, c.ExternalDatabase)
	}
	if c.ExternalRedis {
		t.Fatal("ExternalRedis must be false with no TUNNEX_REDIS_URL")
	}
	if c.RedisURL != "redis://redis:6379/0" {
		t.Fatalf("redis bundled default expected; got %q", c.RedisURL)
	}
}

func TestReleaseCatalogDefaultsOnlyForProductionAndCanBeDisabled(t *testing.T) {
	t.Setenv("TUNNEX_ENV", "production")
	t.Setenv("TUNNEX_RELEASE_CATALOG_URL", "")
	if got := Load().ReleaseCatalogURL; got != "" {
		t.Fatalf("explicit empty catalog must disable online update checks, got %q", got)
	}

	t.Setenv("TUNNEX_ENV", "production")
	os.Unsetenv("TUNNEX_RELEASE_CATALOG_URL")
	if got := Load().ReleaseCatalogURL; got != "https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json" {
		t.Fatalf("production catalog default = %q", got)
	}

	t.Setenv("TUNNEX_ENV", "development")
	if got := Load().ReleaseCatalogURL; got != "" {
		t.Fatalf("development must not make a release network request, got %q", got)
	}
}

func TestKubernetesHADeploymentGateDefaultsOffAndRequiresExplicitOptIn(t *testing.T) {
	os.Unsetenv("TUNNEX_K8S_HA_ENABLED")
	if Load().K8sHAEnabled {
		t.Fatal("Kubernetes HA deployment composition must default OFF")
	}
	t.Setenv("TUNNEX_K8S_HA_ENABLED", "true")
	if !Load().K8sHAEnabled {
		t.Fatal("explicit Kubernetes HA deployment opt-in was ignored")
	}
}

func TestAIProviderManagementRequiresExplicitDeploymentOptIn(t *testing.T) {
	t.Setenv("TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED", "")
	if Load().AIProviderManagementEnabled {
		t.Fatal("provider management must default off")
	}
	t.Setenv("TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED", "true")
	if !Load().AIProviderManagementEnabled {
		t.Fatal("explicit managed-provider opt-in ignored")
	}
	t.Setenv("TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED", "invalid")
	if Load().AIProviderManagementEnabled {
		t.Fatal("invalid deployment setting must not enable management")
	}
}

func TestTrustedProxiesRequireExplicitConfiguration(t *testing.T) {
	t.Setenv("TUNNEX_TRUSTED_PROXIES", "")
	if len(Load().TrustedProxies) != 0 {
		t.Fatal("proxy trust must be explicit")
	}
	t.Setenv("TUNNEX_TRUSTED_PROXIES", "nginx, 192.0.2.1, 2001:db8::/32")
	peers := Load().TrustedProxies
	if len(peers) != 3 || peers[0] != "nginx" || peers[1] != "192.0.2.1" || peers[2] != "2001:db8::/32" {
		t.Fatalf("proxy peers = %q", peers)
	}
}
