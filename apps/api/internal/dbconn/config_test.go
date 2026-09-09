package dbconn_test

import (
	"github.com/jackc/pgx/v5"
	"runtime"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

func TestPoolDefaultHeadroomAndExplicitBudgets(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int32
	}{
		{"postgres://fixture@localhost/fixture?sslmode=disable", int32(max(16, runtime.NumCPU()))},
		{"postgres://fixture@localhost/fixture?sslmode=disable&pool_max_conns=4", 4},
		{"host=localhost user=fixture dbname=fixture sslmode=disable pool_max_conns=3", 3},
		{"postgres://fixture@localhost/fixture?sslmode=disable&pool_max_conns=40", 40},
	} {
		cfg, err := dbconn.ParsePoolConfig(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxConns != tc.want {
			t.Fatalf("maximum=%d, want=%d", cfg.MaxConns, tc.want)
		}
	}
	for _, value := range []string{"0", "-1", "not-a-number"} {
		if _, err := dbconn.ParsePoolConfig("postgres://fixture@localhost/fixture?pool_max_conns=" + value); err == nil {
			t.Fatal("invalid budget accepted")
		}
	}
}

func TestPoolSettingsAreLocalAcrossAllConnectionPaths(t *testing.T) {
	raw := "postgres://fixture@localhost/fixture?sslmode=require&channel_binding=require&pool_max_conns=9&pool_min_conns=2&pool_max_conn_lifetime=30m"
	pool, err := dbconn.ParsePoolConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pool.MaxConns != 9 || pool.MinConns != 2 || pool.MaxConnLifetime != 30*time.Minute {
		t.Fatal("operator settings changed")
	}
	direct, err := dbconn.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*pgx.ConnConfig{direct, pool.ConnConfig} {
		if cfg.RequireAuth != "scram-sha-256" || cfg.ChannelBinding != "require" {
			t.Fatal("authentication requirement changed")
		}
		for _, key := range []string{"pool_max_conns", "pool_min_conns", "pool_max_conn_lifetime"} {
			if _, exists := cfg.RuntimeParams[key]; exists {
				t.Fatal("pool option leaked into server startup parameters")
			}
		}
	}
}

func TestBindingPolicyPreservesOptionalModes(t *testing.T) {
	for _, mode := range []string{"prefer", "disable", "require"} {
		t.Run(mode, func(t *testing.T) {
			cfg, err := dbconn.ParseConfig("postgres://fixture@localhost/fixture?sslmode=disable&channel_binding=" + mode)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ChannelBinding != mode {
				t.Fatal("channel binding mode changed")
			}
			if mode == "require" && cfg.RequireAuth != "scram-sha-256" {
				t.Fatal("missing SCRAM requirement")
			}
			if mode != "require" && cfg.RequireAuth != "" {
				t.Fatal("optional authentication unexpectedly constrained")
			}
		})
	}
}

func TestBindingRequirementFromEnvironment(t *testing.T) {
	t.Setenv("PGCHANNELBINDING", "require")
	cfg, err := dbconn.ParseConfig("postgres://fixture@localhost/fixture?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChannelBinding != "require" || cfg.RequireAuth != "scram-sha-256" {
		t.Fatal("environment requirement bypassed")
	}
}
