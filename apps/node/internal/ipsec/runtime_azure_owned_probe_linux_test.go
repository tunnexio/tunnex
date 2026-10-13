//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Read-only diagnostic of an already running owned gateway. Never starts a
// daemon, stages credentials, installs nft rules, or modifies the journal.
func TestAzureOwnedNativeProbeStages(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_PROBE") != "1" {
		t.Skip("explicit owned gateway diagnostic only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := NewDaemonClient(filepath.Join(daemonRunDirectory, "charon.vici"))
	if err != nil {
		t.Fatal("stage=daemon_client result=fail")
	}
	alive := func() bool { _, e := client.Inspect(ctx); return e == nil }
	probe, err := newRuntimePlatformProbe("/sbin/ip", "/usr/sbin/nft", client, alive)
	if err != nil {
		t.Fatal("stage=constructor result=fail")
	}
	failed := false
	report := func(name string, ok bool) {
		result := "pass"
		if !ok {
			result = "fail"
			failed = true
		}
		t.Logf("stage=%s result=%s", name, result)
	}
	ns, err := probe.namespace()
	report("namespace", err == nil && validKernelNamespace(ns))
	_, err = probe.clock()
	report("clock", err == nil)
	report("daemon_alive", probe.alive())
	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"privilege", probe.privilege}, {"packaged", probe.packaged},
		{"daemon", probe.daemon}, {"kernel", probe.kernel}, {"xfrm", probe.xfrm},
		{"environment", probe.environment}, {"nft", probe.nft},
	} {
		report(step.name, step.run(ctx) == nil)
	}
	originalFailed := failed
	rules, re := runKernelCommand(ctx, "/sbin/ip", "-j", "-4", "rule", "show")
	report("default_rules_read", re == nil)
	report("default_rules", re == nil && runtimeDefaultRules(rules))
	raw, ne := runKernelCommand(ctx, "/usr/sbin/nft", "-j", "list", "ruleset")
	report("nft_ruleset_read", ne == nil)
	report("raw_hook_census", ne == nil && runtimeHookCensus(raw, nil))
	path := "/usr/sbin/iptables-nft-save"
	_, pe := os.Stat(path)
	report("iptables_path", pe == nil)
	version, ve := runKernelCommand(ctx, path, "-V")
	report("iptables_version_read", ve == nil)
	report("iptables_version_qualified", ve == nil && strings.HasPrefix(strings.TrimSpace(string(version)), "iptables-nft-save v") && strings.HasSuffix(strings.TrimSpace(string(version)), " (nf_tables)"))
	listing, le := runKernelCommand(ctx, path, "-t", "nat")
	report("iptables_nat_read", le == nil)
	_, portsOK := runtimeDockerDNSPorts(listing)
	report("docker_dns_ports", le == nil && portsOK)
	report("docker_dns_census", ne == nil && le == nil && runtimeDockerDNSCensus(raw, listing, nil))
	report("docker_dns_qualified", ne == nil && runtimeQualifiedHookCensus(ctx, "/usr/sbin/nft", raw, nil))
	// Report ordinary baseline separately; never change installed policy.
	root, ok := runtimeJSONObject(raw)
	if ok {
		rows, valid := kernelObjects(root["nftables"])
		if valid {
			retained := []map[string]json.RawMessage{}
			for _, row := range rows {
				keep := true
				for kind, value := range row {
					object, valid := kernelObject(value)
					if valid {
						family, _ := kernelString(object, "family")
						table, _ := kernelString(object, "table")
						if kind == "table" {
							table, _ = kernelString(object, "name")
						}
						if family == "ip" && table == "nat" {
							keep = false
						}
					}
				}
				if keep {
					retained = append(retained, row)
				}
			}
			baseline, _ := json.Marshal(map[string]any{"nftables": retained})
			report("baseline_without_docker_nat", runtimeHookCensus(baseline, nil))
		}
	}
	failed = originalFailed
	if failed {
		t.Fatal("owned native probe refused one or more stages")
	}
}
