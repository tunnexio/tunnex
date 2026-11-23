package k8snetprep

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// K8N-1: a network plugin may hook `ip mangle POSTROUTING` (Calico does, for
// its policy marks). That chain runs before NAT POSTROUTING, and the NAT proof
// relies on tunnel traffic not carrying a Kubernetes mark (kubeMarks), so a
// mangle chain is accepted only when it is proved unable to set one. A filter
// chain cannot translate an address itself; marks are how it could select a
// masquerade.

// reservedMarkBits is every bit of kubeMarks.
const reservedMarkBits = 0x2000 | 0x4000 | 0x8000

// maxMarkProofChains bounds the chains one mark proof may visit.
const maxMarkProofChains = 64

// errMarkFactsNeeded marks a refusal that exists only because a MARK target's
// value is not in the nft listing. The caller may read the saved form of the
// mangle table and prove again.
var errMarkFactsNeeded = errors.New("mark target not read")

// proveCannotSetReservedMarks reads every rule reachable from base and returns
// nil only when none can change a reserved mark bit. rules holds each chain's
// rules with counters removed; saved is the same table as iptables-nft-save
// prints it, or nil when it was not read.
//
// It understands conditions (which only narrow a rule), verdicts, jumps to
// known chains, and the MARK target with the value its saved rule states.
// Every other statement or target is an error, never an assumption.
func proveCannotSetReservedMarks(chains map[string]bool, rules map[string][][]map[string]any, base string, saved map[string][]savedRule) error {
	seen := map[string]bool{}
	pending := []string{base}
	for len(pending) > 0 {
		chain := pending[0]
		pending = pending[1:]
		if seen[chain] {
			continue
		}
		if !chains[chain] {
			return fmt.Errorf("mangle rule jumps to unknown chain %s", chain)
		}
		seen[chain] = true
		if len(seen) > maxMarkProofChains {
			return errors.New("mangle POSTROUTING reaches too many chains")
		}
		paired := false
		for n, rule := range rules[chain] {
			for i, expr := range rule {
				if len(expr) != 1 {
					return fmt.Errorf("mangle chain %s has an unreadable statement", chain)
				}
				if _, ok := expr["match"]; ok {
					continue
				}
				kind, name := "", ""
				if xt, ok := expr["xt"]; ok {
					kind, name = xtDescriptor(xt)
					if kind == "match" && name != "" {
						continue
					}
				}
				if i != len(rule)-1 {
					return fmt.Errorf("mangle chain %s has a statement before the end of a rule that is not understood", chain)
				}
				switch {
				case hasKey(expr, "return"), hasKey(expr, "accept"), hasKey(expr, "drop"):
				case hasKey(expr, "jump"), hasKey(expr, "goto"):
					body, _ := expr["jump"].(map[string]any)
					if hasKey(expr, "goto") {
						body, _ = expr["goto"].(map[string]any)
					}
					target, ok := body["target"].(string)
					if !ok || len(body) != 1 || target == "" {
						return fmt.Errorf("mangle chain %s has an unreadable jump", chain)
					}
					pending = append(pending, target)
				case kind == "target" && name == "MARK":
					if saved == nil {
						return fmt.Errorf("mangle chain %s sets a mark that was not read: %w", chain, errMarkFactsNeeded)
					}
					if !paired {
						if err := pairSavedChain(chain, rules[chain], saved[chain]); err != nil {
							return err
						}
						paired = true
					}
					changed, ok := savedMarkChange(saved[chain][n].Args)
					if !ok {
						return fmt.Errorf("mangle chain %s has a MARK target that is not understood", chain)
					}
					if changed&reservedMarkBits != 0 {
						return fmt.Errorf("mangle chain %s can set a Kubernetes mark that selects a masquerade", chain)
					}
				default:
					return fmt.Errorf("mangle chain %s has a statement that is not understood", chain)
				}
			}
		}
	}
	return nil
}

// pairSavedChain checks that saved describes the same chain as the nft
// listing: the same number of rules, and for rule N of both the same number of
// set matches and the same target. Only then may rule N of saved be read as
// rule N of the listing.
func pairSavedChain(chain string, rules [][]map[string]any, saved []savedRule) error {
	if len(rules) != len(saved) {
		return fmt.Errorf("chain %s has %d rules but %d saved rules; it cannot be read", chain, len(rules), len(saved))
	}
	for n, rule := range rules {
		if opaqueSetMatches(rule) != len(saved[n].Sets) || ruleTarget(rule) != saved[n].Target {
			return fmt.Errorf("chain %s rule %d does not pair with its saved rule; it cannot be read", chain, n+1)
		}
	}
	return nil
}

// savedMarkChange reads the arguments iptables-nft-save prints after
// `-j MARK` and returns every mark bit the target can change. The save form is
// always `--set-xmark VALUE/MASK`: the kernel clears MASK and XORs VALUE, so
// the bits of either may change.
func savedMarkChange(args []string) (uint32, bool) {
	if len(args) != 2 || args[0] != "--set-xmark" {
		return 0, false
	}
	value, mask, found := strings.Cut(args[1], "/")
	if !found {
		return 0, false
	}
	v, err := parseHexMark(value)
	if err != nil {
		return 0, false
	}
	m, err := parseHexMark(mask)
	if err != nil {
		return 0, false
	}
	return v | m, true
}

func parseHexMark(raw string) (uint32, error) {
	if !strings.HasPrefix(raw, "0x") {
		return 0, errors.New("mark is not hexadecimal")
	}
	n, err := strconv.ParseUint(raw[2:], 16, 32)
	return uint32(n), err
}
