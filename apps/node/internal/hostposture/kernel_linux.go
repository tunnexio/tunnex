//go:build linux

package hostposture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
	RunInput(context.Context, string, []byte, ...string) (string, error)
}

type realCommandRunner struct{}

type commandFailure struct {
	name string
	args []string
	out  string
	err  error
}

func (e *commandFailure) Error() string {
	return fmt.Sprintf("%s %s: %v: %s", e.name, strings.Join(e.args, " "), e.err, boundedReason(e.out))
}
func (e *commandFailure) Unwrap() error { return e.err }
func (e *commandFailure) ExitCode() int {
	var exit *exec.ExitError
	if errors.As(e.err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func (realCommandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return realCommandRunner{}.RunInput(ctx, name, nil, args...)
}

func (realCommandRunner) RunInput(ctx context.Context, name string, input []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", &commandFailure{name: name, args: append([]string(nil), args...), out: string(out), err: err}
	}
	return string(out), nil
}

type LinuxKernel struct {
	procSys      string
	runner       CommandRunner
	setLinkAlias func(context.Context, int, string) error
	renameLink   func(context.Context, int, string) error
	deleteLink   func(context.Context, int) error
}

func NewLinuxKernel(procSys string, runner CommandRunner) (*LinuxKernel, error) {
	procSys = filepath.Clean(procSys)
	if !filepath.IsAbs(procSys) || procSys == string(filepath.Separator) {
		return nil, fmt.Errorf("host proc sys path must be absolute and narrow")
	}
	if runner == nil {
		runner = realCommandRunner{}
	}
	return &LinuxKernel{
		procSys:      procSys,
		runner:       runner,
		setLinkAlias: setLinkAliasByIndex,
		renameLink:   renameLinkByIndex,
		deleteLink:   deleteLinkByIndex,
	}, nil
}

func (k *LinuxKernel) CaptureBaseline(ctx context.Context, stagingName string) ([]SysctlReceipt, error) {
	if !validWireGuardStagingName(stagingName) {
		return nil, fmt.Errorf("WireGuard staging identity is invalid")
	}
	originals := desiredSysctls()
	for i := range originals {
		value, err := k.readSysctl(originals[i].Key)
		if err != nil {
			return nil, err
		}
		originals[i].Original = value
	}
	if link, present, err := k.inspectWireGuard(ctx); err != nil {
		return nil, err
	} else if present {
		return nil, fmt.Errorf("ambiguous pre-Tunnex WireGuard interface %s (ifindex %d)", link.Name, link.IfIndex)
	}
	candidates, err := k.inspectWireGuardOwnershipCandidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(candidates) != 0 {
		return nil, fmt.Errorf("ambiguous pre-Tunnex WireGuard ownership candidate %s (ifindex %d)", candidates[0].Name, candidates[0].IfIndex)
	}
	for _, table := range fixedArtifacts().NFTables {
		if present, err := k.nftTablePresent(ctx, table); err != nil {
			return nil, err
		} else if present {
			return nil, fmt.Errorf("ambiguous pre-Tunnex nft table %s/%s", table.Family, table.Name)
		}
	}
	owned, state, err := k.cniReconciler().OwnedArtifacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("observe pre-Tunnex CNI ownership: %w", err)
	}
	if state == k8snetprep.StateBlocked {
		return nil, fmt.Errorf("observe pre-Tunnex CNI ownership: adapter state is blocked")
	}
	if len(owned) != 0 {
		return nil, fmt.Errorf("ambiguous pre-Tunnex CNI ownership markers remain")
	}
	docker, err := k.dockerOwnedRules(ctx)
	if err != nil {
		return nil, err
	}
	if len(docker) != 0 {
		return nil, fmt.Errorf("ambiguous pre-Tunnex Docker forwarding markers remain")
	}
	routes, rules, err := k.ownedRoutesAndRules(ctx)
	if err != nil {
		return nil, err
	}
	if len(routes) != 0 || len(rules) != 0 {
		return nil, fmt.Errorf("ambiguous pre-Tunnex route ownership signatures remain")
	}
	return originals, nil
}

func (k *LinuxKernel) Prepare(ctx context.Context, journal *Journal, checkpoint func(*Journal) error) error {
	if journal == nil {
		return fmt.Errorf("journal is required")
	}
	if err := journal.validate(journal.NodeName); err != nil {
		return err
	}
	if journal.SchemaVersion == LegacyJournalSchemaVersion && journal.State != StateActive {
		return fmt.Errorf("schema-v1 preparing journals require a clean provider-managed node replacement")
	}
	if err := k.refuseUnexpectedWireGuardCandidates(ctx, journal.Artifacts.WireGuard); err != nil {
		return err
	}
	if journal.SchemaVersion == LegacyJournalSchemaVersion {
		link, present, err := k.inspectWireGuard(ctx)
		if err != nil {
			return err
		}
		want := journal.Artifacts.WireGuard
		if !present || !exactWireGuardLink(link, want.Name, want.Alias, want.IfIndex) {
			return fmt.Errorf("schema-v1 active WireGuard readback is ambiguous")
		}
		// Active schema-v1 is compatibility readback only. Enforce performs the
		// exact existing-artifact checks; this path never creates or marks state.
		return nil
	} else {
		if checkpoint == nil {
			return fmt.Errorf("durable WireGuard preparation checkpoint is required")
		}
		if err := k.prepareStagedWireGuard(ctx, journal, checkpoint); err != nil {
			return err
		}
	}
	for _, table := range journal.Artifacts.NFTables {
		present, err := k.nftTablePresent(ctx, table)
		if err != nil {
			return err
		}
		if !present {
			script := fmt.Sprintf("add table %s %s\nadd chain %s %s tunnex_posture_owner\nadd rule %s %s tunnex_posture_owner counter comment \"%s\"\n",
				table.Family, table.Name, table.Family, table.Name, table.Family, table.Name, table.Comment)
			if _, err := k.runner.RunInput(ctx, "nft", []byte(script), "-f", "-"); err != nil {
				return fmt.Errorf("create journal-owned nft table %s/%s: %w", table.Family, table.Name, err)
			}
		}
		if err := k.verifyNFTMarker(ctx, table); err != nil {
			return err
		}
	}
	return k.enforceSysctls(journal.Sysctls)
}

func (k *LinuxKernel) prepareStagedWireGuard(ctx context.Context, journal *Journal, checkpoint func(*Journal) error) error {
	receipt := &journal.Artifacts.WireGuard
	for {
		if err := k.refuseUnexpectedWireGuardCandidates(ctx, *receipt); err != nil {
			return err
		}
		switch receipt.Phase {
		case WireGuardPhaseStagingPlanned:
			final, finalPresent, err := k.inspectLink(ctx, receipt.Name)
			if err != nil {
				return err
			}
			if finalPresent {
				return fmt.Errorf("refuse preexisting final WireGuard interface %s (ifindex %d)", final.Name, final.IfIndex)
			}
			staged, stagedPresent, err := k.inspectLink(ctx, receipt.StagingName)
			if err != nil {
				return err
			}
			if !stagedPresent {
				if _, err := k.runner.Run(ctx, "ip", "link", "add", "name", receipt.StagingName, "type", "wireguard"); err != nil {
					return fmt.Errorf("create journal-bound WireGuard staging interface: %w", err)
				}
				staged, stagedPresent, err = k.inspectLink(ctx, receipt.StagingName)
				if err != nil {
					return fmt.Errorf("read back WireGuard staging interface: %w", err)
				}
			}
			if !stagedPresent || staged.Name != receipt.StagingName || staged.Kind != "wireguard" || staged.Alias != "" || staged.IfIndex < 1 {
				return fmt.Errorf("journal-bound WireGuard staging interface is missing or ambiguous")
			}
			receipt.StagingIfIndex = staged.IfIndex
			receipt.Phase = WireGuardPhaseStagingCreated
			if err := checkpoint(journal); err != nil {
				return err
			}

		case WireGuardPhaseStagingCreated:
			if err := k.refuseFinalLink(ctx, receipt.Name); err != nil {
				return err
			}
			staged, present, err := k.inspectLink(ctx, receipt.StagingName)
			if err != nil {
				return err
			}
			if !present || staged.Name != receipt.StagingName || staged.Kind != "wireguard" || staged.IfIndex != receipt.StagingIfIndex || (staged.Alias != "" && staged.Alias != receipt.Alias) {
				return fmt.Errorf("journal-bound WireGuard staging readback is ambiguous")
			}
			if staged.Alias == "" {
				if err := k.setLinkAlias(ctx, receipt.StagingIfIndex, receipt.Alias); err != nil {
					return fmt.Errorf("mark journal-bound WireGuard staging interface: %w", err)
				}
				staged, present, err = k.inspectLink(ctx, receipt.StagingName)
				if err != nil {
					return fmt.Errorf("read back marked WireGuard staging interface: %w", err)
				}
			}
			if !present || staged.Name != receipt.StagingName || staged.Kind != "wireguard" || staged.Alias != receipt.Alias || staged.IfIndex != receipt.StagingIfIndex {
				return fmt.Errorf("WireGuard staging ownership marker readback is ambiguous")
			}
			receipt.Phase = WireGuardPhaseStagingMarked
			if err := checkpoint(journal); err != nil {
				return err
			}

		case WireGuardPhaseStagingMarked:
			final, finalPresent, err := k.inspectLink(ctx, receipt.Name)
			if err != nil {
				return err
			}
			staged, stagedPresent, err := k.inspectLink(ctx, receipt.StagingName)
			if err != nil {
				return err
			}
			if finalPresent {
				if stagedPresent || !exactWireGuardLink(final, receipt.Name, receipt.Alias, receipt.StagingIfIndex) {
					return fmt.Errorf("final WireGuard recovery readback is ambiguous")
				}
			} else {
				if !stagedPresent || !exactWireGuardLink(staged, receipt.StagingName, receipt.Alias, receipt.StagingIfIndex) {
					return fmt.Errorf("marked WireGuard staging readback is ambiguous")
				}
				if err := k.renameLink(ctx, receipt.StagingIfIndex, receipt.Name); err != nil {
					return fmt.Errorf("publish journal-owned WireGuard interface: %w", err)
				}
				final, finalPresent, err = k.inspectLink(ctx, receipt.Name)
				if err != nil {
					return fmt.Errorf("read back final WireGuard interface: %w", err)
				}
				if !finalPresent || !exactWireGuardLink(final, receipt.Name, receipt.Alias, receipt.StagingIfIndex) {
					return fmt.Errorf("final WireGuard ownership readback is ambiguous")
				}
				if _, stillStaged, err := k.inspectLink(ctx, receipt.StagingName); err != nil {
					return err
				} else if stillStaged {
					return fmt.Errorf("WireGuard staging interface remains after final rename")
				}
			}
			receipt.IfIndex = final.IfIndex
			receipt.Phase = WireGuardPhaseCommitted
			if err := checkpoint(journal); err != nil {
				return err
			}

		case WireGuardPhaseCommitted:
			final, present, err := k.inspectLink(ctx, receipt.Name)
			if err != nil {
				return err
			}
			if !present || !exactWireGuardLink(final, receipt.Name, receipt.Alias, receipt.IfIndex) {
				return fmt.Errorf("journal-owned WireGuard interface readback is ambiguous")
			}
			if _, staged, err := k.inspectLink(ctx, receipt.StagingName); err != nil {
				return err
			} else if staged {
				return fmt.Errorf("unexpected WireGuard staging interface remains")
			}
			return nil

		default:
			return fmt.Errorf("journal WireGuard phase %q is unsupported", receipt.Phase)
		}
	}
}

func (k *LinuxKernel) refuseFinalLink(ctx context.Context, name string) error {
	link, present, err := k.inspectLink(ctx, name)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("refuse preexisting final WireGuard interface %s (ifindex %d)", link.Name, link.IfIndex)
	}
	return nil
}

func exactWireGuardLink(link wireGuardLink, name, alias string, ifIndex int) bool {
	return ifIndex > 0 && link.Name == name && link.Kind == "wireguard" && link.Alias == alias && link.IfIndex == ifIndex
}

func (k *LinuxKernel) refuseUnexpectedWireGuardCandidates(ctx context.Context, receipt WireGuardReceipt) error {
	candidates, err := k.inspectWireGuardOwnershipCandidates(ctx)
	if err != nil {
		return err
	}
	if len(candidates) > 1 {
		return fmt.Errorf("multiple Tunnex WireGuard ownership candidates are present")
	}
	for _, candidate := range candidates {
		if wireGuardCandidateAllowed(receipt, candidate) {
			continue
		}
		return fmt.Errorf("unexpected Tunnex WireGuard ownership candidate %s (ifindex %d)", candidate.Name, candidate.IfIndex)
	}
	// wg0 with an empty or foreign alias is intentionally not in the ownership
	// candidate set above, but it still blocks before any prepare/cleanup
	// mutation. It must never be adopted or cleaned by public name alone.
	final, finalPresent, err := k.inspectLink(ctx, receipt.Name)
	if err != nil {
		return err
	}
	if finalPresent {
		matched := len(candidates) == 1 && candidates[0].Name == final.Name
		if !matched {
			return fmt.Errorf("unexpected final WireGuard interface %s (ifindex %d)", final.Name, final.IfIndex)
		}
	}
	return nil
}

func wireGuardCandidateAllowed(receipt WireGuardReceipt, candidate wireGuardLink) bool {
	if receipt.StagingName == "" {
		return exactWireGuardLink(candidate, receipt.Name, receipt.Alias, receipt.IfIndex)
	}
	switch receipt.Phase {
	case WireGuardPhaseStagingPlanned:
		return candidate.Name == receipt.StagingName && candidate.Kind == "wireguard" && candidate.Alias == "" && candidate.IfIndex > 0
	case WireGuardPhaseStagingCreated:
		return candidate.Name == receipt.StagingName && candidate.Kind == "wireguard" && candidate.IfIndex == receipt.StagingIfIndex &&
			(candidate.Alias == "" || candidate.Alias == receipt.Alias)
	case WireGuardPhaseStagingMarked:
		// Rename is the only mutation between the marked and committed
		// checkpoints, so either name can be the one exact crash intermediate.
		return exactWireGuardLink(candidate, receipt.StagingName, receipt.Alias, receipt.StagingIfIndex) ||
			exactWireGuardLink(candidate, receipt.Name, receipt.Alias, receipt.StagingIfIndex)
	case WireGuardPhaseCommitted:
		return exactWireGuardLink(candidate, receipt.Name, receipt.Alias, receipt.IfIndex)
	default:
		return false
	}
}

func (k *LinuxKernel) Enforce(ctx context.Context, journal Journal) error {
	if err := journal.validate(journal.NodeName); err != nil {
		return err
	}
	if err := k.refuseUnexpectedWireGuardCandidates(ctx, journal.Artifacts.WireGuard); err != nil {
		return err
	}
	link, present, err := k.inspectWireGuard(ctx)
	if err != nil {
		return err
	}
	if !present || link.Name != journal.Artifacts.WireGuard.Name || link.Kind != "wireguard" || link.Alias != journal.Artifacts.WireGuard.Alias || link.IfIndex != journal.Artifacts.WireGuard.IfIndex {
		return fmt.Errorf("journal-owned WireGuard interface readback is ambiguous")
	}
	for _, table := range journal.Artifacts.NFTables {
		if err := k.verifyNFTMarker(ctx, table); err != nil {
			return err
		}
	}
	return k.enforceSysctls(journal.Sysctls)
}

func (k *LinuxKernel) RestoreAndCleanup(ctx context.Context, journal *Journal) error {
	if journal == nil {
		return fmt.Errorf("journal is required")
	}
	if err := journal.validate(journal.NodeName); err != nil {
		return err
	}
	if err := k.refuseUnexpectedWireGuardCandidates(ctx, journal.Artifacts.WireGuard); err != nil {
		return err
	}
	if _, err := k.cniReconciler().Withdraw(ctx); err != nil {
		return fmt.Errorf("withdraw exact journaled CNI artifacts: %w", err)
	}
	if err := k.cleanupDockerRules(ctx); err != nil {
		return err
	}
	if err := k.cleanupRoutesAndRules(ctx); err != nil {
		return err
	}
	for _, table := range journal.Artifacts.NFTables {
		present, err := k.nftTablePresent(ctx, table)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if err := k.verifyNFTMarker(ctx, table); err != nil {
			return fmt.Errorf("refuse ambiguous nft cleanup: %w", err)
		}
		if _, err := k.runner.Run(ctx, "nft", "delete", "table", table.Family, table.Name); err != nil {
			return fmt.Errorf("delete journal-owned nft table %s/%s: %w", table.Family, table.Name, err)
		}
	}
	if journal.SchemaVersion == LegacyJournalSchemaVersion {
		if err := k.cleanupLegacyWireGuard(ctx, journal); err != nil {
			return err
		}
	} else if err := k.cleanupStagedWireGuard(ctx, journal); err != nil {
		return err
	}
	return k.restoreSysctls(journal.Sysctls)
}

func (k *LinuxKernel) cleanupLegacyWireGuard(ctx context.Context, journal *Journal) error {
	link, present, err := k.inspectWireGuard(ctx)
	if err != nil || !present {
		return err
	}
	want := &journal.Artifacts.WireGuard
	// Schema-v1 compatibility is deliberately limited to an already-persisted
	// positive ifindex plus the exact final alias identity. Public name/kind/alias
	// fields alone never become cleanup authority, and alias-empty wg0 is foreign.
	if !exactWireGuardLink(link, want.Name, want.Alias, want.IfIndex) {
		return fmt.Errorf("refuse ambiguous WireGuard cleanup")
	}
	if err := k.deleteLink(ctx, want.IfIndex); err != nil {
		return fmt.Errorf("delete journal-owned WireGuard interface: %w", err)
	}
	return nil
}

func (k *LinuxKernel) cleanupStagedWireGuard(ctx context.Context, journal *Journal) error {
	receipt := &journal.Artifacts.WireGuard
	final, finalPresent, err := k.inspectLink(ctx, receipt.Name)
	if err != nil {
		return err
	}
	staged, stagedPresent, err := k.inspectLink(ctx, receipt.StagingName)
	if err != nil {
		return err
	}
	if finalPresent && stagedPresent {
		return fmt.Errorf("refuse ambiguous WireGuard cleanup: final and staging links coexist")
	}
	deleteName := ""
	switch receipt.Phase {
	case WireGuardPhaseStagingPlanned:
		if finalPresent {
			return fmt.Errorf("refuse ambiguous WireGuard cleanup: final link predates publication")
		}
		// A crash can occur after the journal-bound name is created but before
		// its ifindex checkpoint. At this phase only that exact random name,
		// wireguard kind, and empty alias are safe to remove.
		if stagedPresent {
			if staged.Name != receipt.StagingName || staged.Kind != "wireguard" || staged.Alias != "" || staged.IfIndex < 1 {
				return fmt.Errorf("refuse ambiguous WireGuard staging cleanup")
			}
			deleteName = receipt.StagingName
		}

	case WireGuardPhaseStagingCreated:
		if finalPresent {
			return fmt.Errorf("refuse ambiguous WireGuard cleanup: final link predates marked checkpoint")
		}
		if stagedPresent {
			if staged.Name != receipt.StagingName || staged.Kind != "wireguard" || staged.IfIndex != receipt.StagingIfIndex || (staged.Alias != "" && staged.Alias != receipt.Alias) {
				return fmt.Errorf("refuse ambiguous WireGuard staging cleanup")
			}
			deleteName = receipt.StagingName
		}

	case WireGuardPhaseStagingMarked:
		if stagedPresent {
			if !exactWireGuardLink(staged, receipt.StagingName, receipt.Alias, receipt.StagingIfIndex) {
				return fmt.Errorf("refuse ambiguous marked WireGuard staging cleanup")
			}
			deleteName = receipt.StagingName
		} else if finalPresent {
			if !exactWireGuardLink(final, receipt.Name, receipt.Alias, receipt.StagingIfIndex) {
				return fmt.Errorf("refuse ambiguous renamed WireGuard cleanup")
			}
			deleteName = receipt.Name
		}

	case WireGuardPhaseCommitted:
		if stagedPresent {
			return fmt.Errorf("refuse ambiguous WireGuard cleanup: staging link remains after publication")
		}
		if finalPresent {
			if !exactWireGuardLink(final, receipt.Name, receipt.Alias, receipt.IfIndex) {
				return fmt.Errorf("refuse ambiguous final WireGuard cleanup")
			}
			deleteName = receipt.Name
		}

	default:
		return fmt.Errorf("refuse cleanup for unsupported WireGuard phase %q", receipt.Phase)
	}
	if deleteName == "" {
		return nil
	}
	deleteIndex := staged.IfIndex
	if deleteName == receipt.Name {
		deleteIndex = final.IfIndex
	}
	if err := k.deleteLink(ctx, deleteIndex); err != nil {
		return fmt.Errorf("delete journal-owned WireGuard interface %s: %w", deleteName, err)
	}
	return nil
}

func (k *LinuxKernel) restoreSysctls(receipts []SysctlReceipt) error {
	for i := range receipts {
		receipt := &receipts[i]
		if receipt.Restored || receipt.Skipped {
			continue
		}
		live, err := k.readSysctl(receipt.Key)
		if err != nil {
			return err
		}
		if live != receipt.Desired {
			receipt.Skipped = true
			continue
		}
		if err := k.writeAndReadSysctl(receipt.Key, receipt.Original); err != nil {
			return fmt.Errorf("restore %s: %w", receipt.Key, err)
		}
		receipt.Restored = true
	}
	return nil
}

func (k *LinuxKernel) enforceSysctls(receipts []SysctlReceipt) error {
	for _, receipt := range receipts {
		if err := k.writeAndReadSysctl(receipt.Key, receipt.Desired); err != nil {
			return fmt.Errorf("enforce %s: %w", receipt.Key, err)
		}
	}
	return nil
}

func (k *LinuxKernel) readSysctl(key string) (string, error) {
	path := filepath.Join(k.procSys, filepath.FromSlash(key))
	if !strings.HasPrefix(path, k.procSys+string(filepath.Separator)) {
		return "", fmt.Errorf("sysctl path escaped fixed host root")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read host sysctl %s: %w", key, err)
	}
	value := strings.TrimSpace(string(body))
	if value == "" || len(value) > 32 || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("host sysctl %s has an invalid value", key)
	}
	return value, nil
}

func (k *LinuxKernel) writeAndReadSysctl(key, value string) error {
	if value == "" || len(value) > 32 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("refuse invalid sysctl value")
	}
	path := filepath.Join(k.procSys, filepath.FromSlash(key))
	if !strings.HasPrefix(path, k.procSys+string(filepath.Separator)) {
		return fmt.Errorf("sysctl path escaped fixed host root")
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return err
	}
	live, err := k.readSysctl(key)
	if err != nil {
		return err
	}
	if live != value {
		return fmt.Errorf("readback=%q desired=%q", live, value)
	}
	return nil
}

type wireGuardLink struct {
	Name    string
	Alias   string
	Kind    string
	IfIndex int
}

type linkReadbackRow struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname"`
	IfAlias  string `json:"ifalias"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func (k *LinuxKernel) inspectWireGuard(ctx context.Context) (wireGuardLink, bool, error) {
	return k.inspectLink(ctx, DefaultWireGuardIface)
}

func (k *LinuxKernel) inspectLink(ctx context.Context, name string) (wireGuardLink, bool, error) {
	out, err := k.runner.Run(ctx, "ip", "-j", "-d", "link", "show", "dev", name)
	if err != nil {
		if commandAbsent(err, "does not exist", "cannot find device") {
			return wireGuardLink{}, false, nil
		}
		return wireGuardLink{}, false, fmt.Errorf("inspect link %s: %w", name, err)
	}
	var rows []linkReadbackRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		return wireGuardLink{}, false, fmt.Errorf("link %s readback is malformed or ambiguous", name)
	}
	row := rows[0]
	return wireGuardLink{Name: row.IfName, Alias: row.IfAlias, Kind: row.LinkInfo.Kind, IfIndex: row.IfIndex}, true, nil
}

func (k *LinuxKernel) inspectWireGuardOwnershipCandidates(ctx context.Context) ([]wireGuardLink, error) {
	out, err := k.runner.Run(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("inspect WireGuard staging interfaces: %w", err)
	}
	if len(out) > MaxKubernetesResponse {
		return nil, fmt.Errorf("WireGuard staging readback exceeds bounded size")
	}
	var rows []linkReadbackRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("WireGuard staging readback is malformed")
	}
	links := make([]wireGuardLink, 0)
	for _, row := range rows {
		if !validWireGuardStagingName(row.IfName) && row.IfAlias != WireGuardAlias {
			continue
		}
		links = append(links, wireGuardLink{Name: row.IfName, Alias: row.IfAlias, Kind: row.LinkInfo.Kind, IfIndex: row.IfIndex})
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
	return links, nil
}

func (k *LinuxKernel) nftTablePresent(ctx context.Context, table NFTTableReceipt) (bool, error) {
	_, err := k.runner.Run(ctx, "nft", "list", "table", table.Family, table.Name)
	if err == nil {
		return true, nil
	}
	if commandAbsent(err, "no such file or directory", "not found") {
		return false, nil
	}
	return false, fmt.Errorf("inspect nft table %s/%s: %w", table.Family, table.Name, err)
}

func (k *LinuxKernel) verifyNFTMarker(ctx context.Context, table NFTTableReceipt) error {
	out, err := k.runner.Run(ctx, "nft", "-a", "list", "chain", table.Family, table.Name, "tunnex_posture_owner")
	if err != nil {
		return fmt.Errorf("read nft ownership marker %s/%s: %w", table.Family, table.Name, err)
	}
	return ValidateNFTMarkerChain(out, table.Comment)
}

func commandAbsent(err error, needles ...string) bool {
	if err == nil {
		return false
	}
	type exitStatus interface{ ExitCode() int }
	var exited exitStatus
	if !errors.As(err, &exited) || exited.ExitCode() < 0 {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, needle := range needles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func (k *LinuxKernel) cniReconciler() *k8snetprep.Reconciler {
	return k8snetprep.New(DefaultWireGuardIface, func(ctx context.Context, args ...string) (string, error) {
		return k.runner.Run(ctx, "nft", args...)
	})
}

type dockerRule struct{ handle string }

var dockerOwnedRuleRE = regexp.MustCompile(`^\s*(?:iifname|oifname)\s+"?wg0"?\s+ip\s+(?:saddr|daddr)\s+([^[:space:]]+)\s+counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+accept\s+comment\s+"tunnex-site-fwd"\s+# handle ([0-9]+)\s*$`)

func (k *LinuxKernel) dockerOwnedRules(ctx context.Context) ([]dockerRule, error) {
	out, err := k.runner.Run(ctx, "nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER")
	if err != nil {
		if commandAbsent(err, "no such file or directory", "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect Docker forwarding chain: %w", err)
	}
	var rules []dockerRule
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "tunnex-site-fwd"`) {
			continue
		}
		match := dockerOwnedRuleRE.FindStringSubmatch(line)
		if len(match) != 3 {
			return nil, fmt.Errorf("Tunnex-marked Docker rule has an unrecognized shape")
		}
		if _, err := parsePrefixOrAddress(match[1]); err != nil {
			return nil, fmt.Errorf("Tunnex-marked Docker rule has invalid scope")
		}
		rules = append(rules, dockerRule{handle: match[2]})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].handle > rules[j].handle })
	return rules, nil
}

func (k *LinuxKernel) cleanupDockerRules(ctx context.Context) error {
	rules, err := k.dockerOwnedRules(ctx)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if _, err := k.runner.Run(ctx, "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", rule.handle); err != nil {
			return fmt.Errorf("delete journaled Docker forwarding rule: %w", err)
		}
	}
	remaining, err := k.dockerOwnedRules(ctx)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return fmt.Errorf("journaled Docker forwarding rules remain after cleanup")
	}
	return nil
}

type ownedRoute struct {
	family string
	prefix string
}
type ownedRule struct {
	family string
	prefix string
}

func (k *LinuxKernel) ownedRoutesAndRules(ctx context.Context) ([]ownedRoute, []ownedRule, error) {
	var routes []ownedRoute
	var rules []ownedRule
	for _, family := range []string{"-4", "-6"} {
		out, err := k.runner.Run(ctx, "ip", family, "route", "show")
		if err != nil {
			return nil, nil, fmt.Errorf("enumerate journaled routes: %w", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !hasTokens(fields, "dev", DefaultWireGuardIface, "proto", "static", "metric", strconv.Itoa(RouteMetric)) {
				continue
			}
			prefix, err := parsePrefixOrAddress(fields[0])
			if err != nil || (family == "-4") != prefix.Addr().Is4() {
				return nil, nil, fmt.Errorf("journal-owned route has an unrecognized destination")
			}
			routes = append(routes, ownedRoute{family: family, prefix: prefix.String()})
		}
		out, err = k.runner.Run(ctx, "ip", family, "rule", "show", "pref", strconv.Itoa(ReturnRulePriority))
		if err != nil {
			return nil, nil, fmt.Errorf("enumerate journaled return rules: %w", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.TrimSuffix(fields[0], ":") != strconv.Itoa(ReturnRulePriority) {
				continue
			}
			to, lookup := tokenValue(fields, "to"), tokenValue(fields, "lookup")
			if to == "" || lookup != ReturnRuleLookup {
				continue
			}
			prefix, err := parsePrefixOrAddress(to)
			if err != nil || (family == "-4") != prefix.Addr().Is4() {
				return nil, nil, fmt.Errorf("journal-owned return rule has an unrecognized destination")
			}
			rules = append(rules, ownedRule{family: family, prefix: prefix.String()})
		}
	}
	return routes, rules, nil
}

func (k *LinuxKernel) cleanupRoutesAndRules(ctx context.Context) error {
	routes, rules, err := k.ownedRoutesAndRules(ctx)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if _, err := k.runner.Run(ctx, "ip", route.family, "route", "del", route.prefix, "dev", DefaultWireGuardIface, "proto", "static", "metric", strconv.Itoa(RouteMetric)); err != nil {
			return fmt.Errorf("delete journaled route %s: %w", route.prefix, err)
		}
	}
	for _, rule := range rules {
		if _, err := k.runner.Run(ctx, "ip", rule.family, "rule", "del", "pref", strconv.Itoa(ReturnRulePriority), "to", rule.prefix, "lookup", ReturnRuleLookup); err != nil {
			return fmt.Errorf("delete journaled return rule %s: %w", rule.prefix, err)
		}
	}
	routes, rules, err = k.ownedRoutesAndRules(ctx)
	if err != nil {
		return err
	}
	if len(routes) != 0 || len(rules) != 0 {
		return fmt.Errorf("journaled route artifacts remain after cleanup")
	}
	return nil
}

func hasTokens(fields []string, pairs ...string) bool {
	for i := 0; i < len(pairs); i += 2 {
		if tokenValue(fields, pairs[i]) != pairs[i+1] {
			return false
		}
	}
	return true
}

func tokenValue(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}

func parsePrefixOrAddress(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid address or prefix")
}
