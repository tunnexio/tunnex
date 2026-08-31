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
	procSys         string
	runner          CommandRunner
	createWireGuard func(context.Context) error
}

func NewLinuxKernel(procSys string, runner CommandRunner) (*LinuxKernel, error) {
	procSys = filepath.Clean(procSys)
	if !filepath.IsAbs(procSys) || procSys == string(filepath.Separator) {
		return nil, fmt.Errorf("host proc sys path must be absolute and narrow")
	}
	if runner == nil {
		runner = realCommandRunner{}
	}
	return &LinuxKernel{procSys: procSys, runner: runner, createWireGuard: createWireGuardLinkAtomic}, nil
}

func (k *LinuxKernel) CaptureBaseline(ctx context.Context) ([]SysctlReceipt, error) {
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

func (k *LinuxKernel) Prepare(ctx context.Context, journal *Journal) error {
	if journal == nil {
		return fmt.Errorf("journal is required")
	}
	if err := journal.validate(journal.NodeName); err != nil {
		return err
	}
	link, present, err := k.inspectWireGuard(ctx)
	if err != nil {
		return err
	}
	if !present {
		if k.createWireGuard == nil {
			return fmt.Errorf("atomic WireGuard creator is unavailable")
		}
		if err := k.createWireGuard(ctx); err != nil {
			return fmt.Errorf("create journal-owned WireGuard interface: %w", err)
		}
		link, present, err = k.inspectWireGuard(ctx)
		if err != nil {
			return fmt.Errorf("read back journal-owned WireGuard interface: %w", err)
		}
		if !present {
			return fmt.Errorf("journal-owned WireGuard interface is absent after creation")
		}
	}
	if link.Name != DefaultWireGuardIface || link.Kind != "wireguard" || link.Alias != WireGuardAlias || link.IfIndex < 1 {
		return fmt.Errorf("WireGuard ownership marker is missing or ambiguous")
	}
	if journal.Artifacts.WireGuard.IfIndex != 0 && journal.Artifacts.WireGuard.IfIndex != link.IfIndex {
		return fmt.Errorf("WireGuard ifindex changed from journal %d to %d", journal.Artifacts.WireGuard.IfIndex, link.IfIndex)
	}
	journal.Artifacts.WireGuard.IfIndex = link.IfIndex
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

func (k *LinuxKernel) Enforce(ctx context.Context, journal Journal) error {
	if err := journal.validate(journal.NodeName); err != nil {
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
	link, present, err := k.inspectWireGuard(ctx)
	if err != nil {
		return err
	}
	if present {
		want := &journal.Artifacts.WireGuard
		// The atomic RTM_NEWLINK operation publishes name, kind, and alias as one
		// kernel identity. If the manager crashed before persisting the returned
		// ifindex and the last Pod owner disappeared during that restart, the
		// durable preparing journal plus exact alias readback is still sufficient
		// ownership proof for bounded cleanup. No active/restored journal and no
		// unmarked or foreign interface may use this recovery path.
		if journal.State == StatePreparing && want.IfIndex == 0 &&
			link.Name == want.Name && link.Kind == "wireguard" && link.Alias == want.Alias && link.IfIndex > 0 {
			want.IfIndex = link.IfIndex
		}
		if want.IfIndex < 1 || link.Name != want.Name || link.Kind != "wireguard" || link.Alias != want.Alias || link.IfIndex != want.IfIndex {
			return fmt.Errorf("refuse ambiguous WireGuard cleanup")
		}
		if _, err := k.runner.Run(ctx, "ip", "link", "del", want.Name); err != nil {
			return fmt.Errorf("delete journal-owned WireGuard interface: %w", err)
		}
	}
	return k.restoreSysctls(journal.Sysctls)
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

func (k *LinuxKernel) inspectWireGuard(ctx context.Context) (wireGuardLink, bool, error) {
	out, err := k.runner.Run(ctx, "ip", "-j", "-d", "link", "show", "dev", DefaultWireGuardIface)
	if err != nil {
		if commandAbsent(err, "does not exist", "cannot find device") {
			return wireGuardLink{}, false, nil
		}
		return wireGuardLink{}, false, fmt.Errorf("inspect WireGuard interface: %w", err)
	}
	var rows []struct {
		IfIndex  int    `json:"ifindex"`
		IfName   string `json:"ifname"`
		IfAlias  string `json:"ifalias"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		return wireGuardLink{}, false, fmt.Errorf("WireGuard link readback is malformed or ambiguous")
	}
	row := rows[0]
	return wireGuardLink{Name: row.IfName, Alias: row.IfAlias, Kind: row.LinkInfo.Kind, IfIndex: row.IfIndex}, true, nil
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
