package dbconn_test

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

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
