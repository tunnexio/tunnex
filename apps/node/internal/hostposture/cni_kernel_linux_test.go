//go:build linux

package hostposture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

func cniKernelSnapshot(ipMasq, aws, malformed bool) string {
	rows := []any{
		map[string]any{"chain": map[string]any{"family": "ip", "table": "nat", "name": "IP-MASQ-AGENT", "handle": 1}},
		map[string]any{"chain": map[string]any{"family": "ip", "table": "nat", "name": "AWS-SNAT-CHAIN-0", "handle": 2}},
	}
	expr := []any{
		map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "daddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": "10.99.0.0", "len": 24}}}},
		map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "wg0"}},
		map[string]any{"return": nil},
	}
	for _, item := range []struct {
		present       bool
		chain, marker string
		handle        int
	}{
		{ipMasq, "IP-MASQ-AGENT", "tunnex_k8s_ip_masq_bypass", 3},
		{aws, "AWS-SNAT-CHAIN-0", k8snetprep.AWSOwnedRuleComment, 4},
	} {
		if !item.present {
			continue
		}
		shape := expr
		if malformed && item.chain == "AWS-SNAT-CHAIN-0" {
			shape = []any{map[string]any{"accept": nil}}
		}
		rows = append(rows, map[string]any{"rule": map[string]any{"family": "ip", "table": "nat", "chain": item.chain, "handle": item.handle, "comment": item.marker, "expr": shape}})
	}
	// Foreign compat JSON is deliberately opaque and must never be rewritten.
	rows = append(rows, map[string]any{"rule": map[string]any{"family": "ip", "table": "nat", "chain": "AWS-SNAT-CHAIN-0", "handle": 5, "expr": []any{map[string]any{"xt": nil}}}})
	body, _ := json.Marshal(map[string]any{"nftables": rows})
	return string(body)
}

func cniKernelIPTablesSave(ipMasq, aws bool) string {
	listing := "*nat\n:IP-MASQ-AGENT - [0:0]\n:AWS-SNAT-CHAIN-0 - [0:0]\n"
	if ipMasq {
		listing += "-A IP-MASQ-AGENT -d 10.99.0.0/24 -o wg0 -m comment --comment tunnex_k8s_ip_masq_bypass -j RETURN\n"
	}
	if aws {
		listing += "-A AWS-SNAT-CHAIN-0 -d 10.99.0.0/24 -o wg0 -m comment --comment tunnex_k8s_aws_snat_bypass -j RETURN\n"
	}
	return listing + "-A AWS-SNAT-CHAIN-0 -j SNAT --to-source 192.0.2.1\nCOMMIT\n"
}

func TestKernelNewEpochBaselineCensusesBothCNINamespacesWithoutMutation(t *testing.T) {
	for _, namespace := range []string{"legacy", "aws", "malformed AWS"} {
		t.Run(namespace, func(t *testing.T) {
			kernel, harness, _ := newStagedLinkHarness(t)
			base := kernel.runner
			kernel.runner = runnerFunc(func(ctx context.Context, name string, input []byte, args ...string) (string, error) {
				if name == "iptables-nft-save" {
					if strings.Join(args, " ") == "-V" {
						return "iptables-nft-save v1.8.8 (nf_tables)", nil
					}
					return cniKernelIPTablesSave(namespace == "legacy", namespace != "legacy"), nil
				}
				if name == "nft" && strings.Join(args, " ") == "-j -a list ruleset" {
					return cniKernelSnapshot(namespace == "legacy", namespace != "legacy", namespace == "malformed AWS"), nil
				}
				return base.RunInput(ctx, name, input, args...)
			})
			if _, err := kernel.CaptureBaseline(t.Context(), testStagingName); err == nil {
				t.Fatal("new baseline accepted leftover CNI ownership")
			}
			if len(harness.mutations) != 0 {
				t.Fatalf("baseline mutated host: %v", harness.mutations)
			}
		})
	}
}

func TestKernelCleanupUsesOnlyActualJournalCNIReceipts(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			kernel, harness, journal := newStagedLinkHarness(t)
			journal = committedHarnessJournal(journal, harness)
			journal.SchemaVersion = schema
			if schema < 3 {
				journal.Artifacts.AWSCNI = nil
			}
			if schema == 1 {
				journal.Artifacts.WireGuard.StagingName = ""
				journal.Artifacts.WireGuard.StagingIfIndex = 0
				journal.Artifacts.WireGuard.Phase = ""
			}
			journal.State = StateRestoring
			journal.Owners = nil
			base := kernel.runner
			ipMasq, aws := schema == 3, true
			inspections, deletes := 0, []string{}
			kernel.runner = runnerFunc(func(ctx context.Context, name string, input []byte, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if name == "iptables-nft-save" {
					if schema < 3 {
						t.Error("legacy cleanup acquired an AWS tool dependency")
					}
					if joined == "-V" {
						return "iptables-nft-save v1.8.8 (nf_tables)", nil
					}
					return cniKernelIPTablesSave(ipMasq, aws), nil
				}
				if name == "nft" && joined == "-j -a list ruleset" {
					inspections++
					return cniKernelSnapshot(ipMasq, aws, false), nil
				}
				if name == "nft" && strings.HasPrefix(joined, "delete rule ip nat ") {
					switch joined {
					case "delete rule ip nat IP-MASQ-AGENT handle 3":
						ipMasq = false
					case "delete rule ip nat AWS-SNAT-CHAIN-0 handle 4":
						aws = false
					default:
						t.Errorf("cleanup touched foreign rule: %s", joined)
					}
					deletes = append(deletes, joined)
					return "", nil
				}
				return base.RunInput(ctx, name, input, args...)
			})
			if err := kernel.RestoreAndCleanup(t.Context(), &journal); err != nil {
				t.Fatal(err)
			}
			if schema < 3 && (inspections != 0 || len(deletes) != 0 || !aws) {
				t.Fatal("historical journal enumerated or removed AWS namespace")
			}
			if schema == 3 && (inspections != 4 || len(deletes) != 2 || aws || ipMasq) {
				t.Fatalf("v3 cleanup missed exact receipts: scans=%d deletes=%v", inspections, deletes)
			}
			if err := kernel.RestoreAndCleanup(t.Context(), &journal); err != nil {
				t.Fatalf("already-absent exact cleanup replay failed: %v", err)
			}
		})
	}
}

func TestKernelMalformedAWSReceiptArtifactBlocksAllCleanup(t *testing.T) {
	kernel, harness, journal := newStagedLinkHarness(t)
	journal = committedHarnessJournal(journal, harness)
	journal.State = StateRestoring
	journal.Owners = nil
	base := kernel.runner
	mutations := 0
	kernel.runner = runnerFunc(func(ctx context.Context, name string, input []byte, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if name == "nft" && joined == "-j -a list ruleset" {
			return cniKernelSnapshot(true, true, true), nil
		}
		if name == "nft" && strings.HasPrefix(joined, "delete ") {
			mutations++
		}
		return base.RunInput(ctx, name, input, args...)
	})
	if err := kernel.RestoreAndCleanup(t.Context(), &journal); err == nil {
		t.Fatal("malformed owned AWS artifact accepted")
	}
	if mutations != 0 || len(harness.mutations) != 0 {
		t.Fatal("malformed ownership allowed partial cleanup")
	}
}

func TestKernelCNICleanupDeadlineBlocksLateInspectionBeforeMutation(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			kernel, harness, journal := newStagedLinkHarness(t)
			journal = committedHarnessJournal(journal, harness)
			journal.SchemaVersion = schema
			if schema < 3 {
				journal.Artifacts.AWSCNI = nil
			}
			if schema == 1 {
				journal.Artifacts.WireGuard.StagingName = ""
				journal.Artifacts.WireGuard.StagingIfIndex = 0
				journal.Artifacts.WireGuard.Phase = ""
			}
			journal.State, journal.Owners = StateRestoring, nil
			base := kernel.runner
			inspected, mutated := false, false
			start := time.Now()
			kernel.runner = runnerFunc(func(ctx context.Context, name string, input []byte, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if name == "nft" && (joined == "-j -a list ruleset" || joined == "-a list chain ip nat IP-MASQ-AGENT") {
					inspected = true
					deadline, ok := ctx.Deadline()
					if !ok || deadline.After(start.Add(cniCleanupOperationTimeout)) {
						t.Fatal("CNI cleanup has no complete-operation deadline")
					}
					<-ctx.Done()
					// Deliberately ignore cancellation and return an owned rule.
					// No caller may act on this late readback.
					if schema == 3 {
						return cniKernelSnapshot(true, true, false), nil
					}
					return "table ip nat {\nchain IP-MASQ-AGENT {\nip daddr 10.99.0.0/24 oifname wg0 return comment \"tunnex_k8s_ip_masq_bypass\" # handle 3\n}\n}", nil
				}
				if name == "nft" && strings.HasPrefix(joined, "delete ") {
					mutated = true
				}
				return base.RunInput(ctx, name, input, args...)
			})
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			err := kernel.RestoreAndCleanup(ctx, &journal)
			// The historical adapter deliberately bounds its error text rather
			// than retaining the underlying sentinel. Preserve that contract:
			// prove the context expired, the operation refused, and nothing wrote.
			if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) || !inspected || mutated || len(harness.mutations) != 0 {
				t.Fatalf("late CNI inspection escaped budget: err=%v inspected=%v mutated=%v linkChanges=%v", err, inspected, mutated, harness.mutations)
			}
		})
	}
}
