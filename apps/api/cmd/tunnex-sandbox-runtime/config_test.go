package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"golang.org/x/crypto/ssh"
)

func roleFixture(t *testing.T) config {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return config{
		APIUID: 1000, ProbeKeyFile: state + "/worker/main-probe-key", CAFile: state + "/worker/main-api-ca.pem",
		Remote: &remoteConfig{URL: "https://fixture.invalid"},
		Binding: sandboxes.BoundedRuntimeBinding{Mode: "persistent", OrgID: uuid.New(), CreatorID: uuid.New(), GatewayID: uuid.New(), TerminalDeviceID: uuid.New(), MemoryMiB: 128, CPUs: 1, MaxTTLSeconds: 900,
			Profiles: []sandboxes.QualifiedRuntimeProfile{{TemplateID: uuid.New(), ConfigDigest: "sha256:" + strings.Repeat("c", 64), Architecture: "amd64", PIDs: 64, QualificationEvidence: "source-test-only"}}},
		Supervision: &supervisionConfig{Enabled: true, ActorUID: 1101, SupervisorUID: 1101, ProbePublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))},
	}
}

func TestSplitRoleRequiresExplicitOperatorPins(t *testing.T) {
	for _, role := range []string{roleActor, roleTransport} {
		cfg := roleFixture(t)
		if key, err := validateRole(cfg, role, 1101); err != nil || key == nil {
			t.Fatal("valid split role rejected", role, err)
		}
		for name, mutate := range map[string]func(*config){
			"missing-opt-in":            func(c *config) { c.Supervision = nil },
			"disabled":                  func(c *config) { c.Supervision.Enabled = false },
			"foreign-actor":             func(c *config) { c.Supervision.ActorUID = 1102 },
			"foreign-supervisor":        func(c *config) { c.Supervision.SupervisorUID = 1102 },
			"trial":                     func(c *config) { c.Binding.Mode = "trial" },
			"broaden-memory":            func(c *config) { c.Binding.MemoryMiB = 256 },
			"broaden-ttl":               func(c *config) { c.Binding.MaxTTLSeconds = 901 },
			"broaden-pids":              func(c *config) { c.Binding.Profiles[0].PIDs = 128 },
			"foreign-probe-path":        func(c *config) { c.ProbeKeyFile = "/tmp/key" },
			"private-key-in-public-pin": func(c *config) { c.Supervision.ProbePublicKey = "-----BEGIN OPENSSH PRIVATE KEY-----" },
			"extra-public-key":          func(c *config) { c.Supervision.ProbePublicKey += c.Supervision.ProbePublicKey },
			"key-options": func(c *config) {
				c.Supervision.ProbePublicKey = "command=\"unexpected\" " + c.Supervision.ProbePublicKey
			},
		} {
			t.Run(role+"/"+name, func(t *testing.T) {
				c := roleFixture(t)
				mutate(&c)
				if _, err := validateRole(c, role, 1101); err == nil {
					t.Fatal("unsafe role/config accepted")
				}
			})
		}
	}
}

func TestLegacyRolePreservesSeparateAPIUIDAndNoSplitActivation(t *testing.T) {
	cfg := roleFixture(t)
	if _, err := validateRole(cfg, roleCombined, 1101); err == nil {
		t.Fatal("split config silently entered legacy mode")
	}
	cfg.Supervision = nil
	if key, err := validateRole(cfg, roleCombined, 1101); err != nil || key != nil {
		t.Fatal("legacy defaults changed", err)
	}
	cfg.APIUID = 1101
	if _, err := validateRole(cfg, roleCombined, 1101); err == nil {
		t.Fatal("legacy same-UID boundary broadened")
	}
	cfg = roleFixture(t)
	cfg.Remote = nil
	if _, err := validateRole(cfg, roleTransport, 1101); err == nil {
		t.Fatal("transport without controller admitted")
	}
	if _, err := validateRole(cfg, roleActor, 1101); err != nil {
		t.Fatal("actor unnecessarily requires controller credentials", err)
	}
	if _, err := validateRole(cfg, "unknown", 1101); err == nil {
		t.Fatal("unknown role admitted")
	}
	if _, err := validateRole(cfg, roleActor, 0); err == nil {
		t.Fatal("root execution admitted")
	}
}

func TestPortableOperatorPathsPreserveRoleAndOwnershipPins(t *testing.T) {
	cfg := roleFixture(t)
	cfg.StateRoot, cfg.RunRoot = "/var/lib/customer-sandbox", "/run/customer-sandbox"
	cfg.ActorControlCgroup = "/customer.slice/customer-actor.service/control"
	cfg.ProbeKeyFile = cfg.StateRoot + "/worker/main-probe-key"
	cfg.CAFile = cfg.StateRoot + "/worker/main-api-ca.pem"
	cfg.Supervision.ActorUID, cfg.Supervision.SupervisorUID = 2401, 2401
	if _, err := validateRole(cfg, roleActor, 2401); err != nil {
		t.Fatal("portable operator layout rejected", err)
	}
	if _, err := validateRole(cfg, roleActor, 1101); err == nil {
		t.Fatal("portable layout bypassed configured OS identity")
	}
	for name, change := range map[string]func(*config){
		"relative-state":   func(c *config) { c.StateRoot = "state" },
		"unclean-state":    func(c *config) { c.StateRoot += "/../state" },
		"root":             func(c *config) { c.RunRoot = "/" },
		"partial-layout":   func(c *config) { c.RunRoot = "" },
		"same-roots":       func(c *config) { c.RunRoot = c.StateRoot },
		"nested-state":     func(c *config) { c.StateRoot = c.RunRoot + "/state" },
		"nested-run":       func(c *config) { c.RunRoot = c.StateRoot + "/run" },
		"foreign-probe":    func(c *config) { c.ProbeKeyFile = state + "/worker/main-probe-key" },
		"foreign-ca":       func(c *config) { c.CAFile = state + "/worker/main-api-ca.pem" },
		"arbitrary-cgroup": func(c *config) { c.ActorControlCgroup = "/sys/fs/cgroup" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := cfg
			change(&copy)
			if _, err := validateRole(copy, roleActor, 2401); err == nil {
				t.Fatal("unsafe portable layout accepted")
			}
		})
	}
	legacy, err := roleFixture(t).paths()
	if err != nil || legacy.State != state || legacy.Run != runtime || legacy.ActorControl != "/tnxsandboxqual.slice/tunnex-sandbox-qual-actor.service/control" {
		t.Fatal("legacy layout changed", err)
	}
}
