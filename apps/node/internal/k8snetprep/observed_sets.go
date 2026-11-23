package k8snetprep

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// K8N-1: a network plugin may hide the condition of its masquerade rule behind
// a kernel ipset (Calico: "source is in my pools"). The nft JSON shows such a
// match as an opaque extension, so the set's name, direction and negation are
// read from iptables-nft-save, and its members from ipset. Nothing here writes.

const (
	maxSetNameBytes   = 31 // IPSET_MAXNAMELEN - 1
	maxSetMembers     = 4096
	maxSetSaveBytes   = 256 << 10
	maxSavedRuleBytes = 4096
)

// setNameRE is the only shape of set name this package reads, passes to ipset
// or reports. Any other name is refused, never quoted or escaped. A leading
// "-" is refused as well: ipset would read it as an option, not a name.
var setNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,30}$`)

func validSetName(name string) bool { return setNameRE.MatchString(name) }

// setMatch is one `-m set [!] --match-set NAME DIRS` of a saved rule.
type setMatch struct {
	Name    string
	Dirs    []string // "src" or "dst", one per dimension
	Negated bool
}

// parseSavedSetMatches reads iptables-nft-save output for one table and
// returns, per chain, the set matches of each rule in rule order. Rules with no
// set match keep their position with an empty list, so a caller can pair rule
// N of a chain with rule N of the nft listing.
func parseSavedSetMatches(saved string) (map[string][][]setMatch, error) {
	out := map[string][][]setMatch{}
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		if len(line) > maxSavedRuleBytes {
			return nil, errors.New("saved NAT rule exceeds bound")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.New("saved NAT rule has no chain")
		}
		chain := fields[1]
		matches := []setMatch{}
		for i := 2; i < len(fields); i++ {
			if fields[i] != "-m" || i+1 >= len(fields) || fields[i+1] != "set" {
				continue
			}
			j := i + 2
			negated := false
			if j < len(fields) && fields[j] == "!" {
				negated = true
				j++
			}
			if j+2 >= len(fields) || fields[j] != "--match-set" {
				return nil, fmt.Errorf("saved NAT rule in %s has a set match that is not understood", chain)
			}
			name, dirs := fields[j+1], strings.Split(fields[j+2], ",")
			if len(name) > maxSetNameBytes || !validSetName(name) {
				return nil, fmt.Errorf("saved NAT rule in %s names an invalid set", chain)
			}
			for _, dir := range dirs {
				if dir != "src" && dir != "dst" {
					return nil, fmt.Errorf("saved NAT rule in %s has a set direction that is not understood", chain)
				}
			}
			matches = append(matches, setMatch{Name: name, Dirs: dirs, Negated: negated})
			i = j + 2
		}
		out[chain] = append(out[chain], matches)
	}
	return out, nil
}

// savedRule is what one `-A` line of iptables-nft-save says that the nft
// listing may hide: its set matches, the target it ends in (empty when the
// rule has none) and that target's arguments.
type savedRule struct {
	Sets   []setMatch
	Target string
	Args   []string
}

// parseSavedRules reads iptables-nft-save output for one table and returns
// each chain's rules in rule order.
func parseSavedRules(saved string) (map[string][]savedRule, error) {
	sets, err := parseSavedSetMatches(saved)
	if err != nil {
		return nil, err
	}
	out := map[string][]savedRule{}
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		// parseSavedSetMatches accepted this line, so it has a chain.
		fields := strings.Fields(line)
		chain, target := fields[1], ""
		var args []string
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "-j" || fields[i] == "-g" {
				// The last one wins: text inside a comment that looks like a
				// target always precedes the real one.
				target, args = fields[i+1], fields[i+2:]
			}
		}
		out[chain] = append(out[chain], savedRule{Sets: sets[chain][len(out[chain])], Target: target, Args: args})
	}
	return out, nil
}

// parseIPSetSave reads `ipset save NAME` and returns the set's IPv4 members.
// Only hash:net and hash:ip sets of family inet are understood; anything else
// is an error, never an empty set.
func parseIPSetSave(name, saved string) ([]netip.Prefix, error) {
	if len(saved) > maxSetSaveBytes {
		return nil, fmt.Errorf("set %s exceeds bound", name)
	}
	created := false
	members := []netip.Prefix{}
	for _, line := range strings.Split(saved, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "create":
			if len(fields) < 3 || fields[1] != name {
				return nil, fmt.Errorf("set listing is not for %s", name)
			}
			if fields[2] != "hash:net" && fields[2] != "hash:ip" {
				return nil, fmt.Errorf("set %s has type %s, which is not understood", name, fields[2])
			}
			for i := 3; i+1 < len(fields); i++ {
				if fields[i] == "family" && fields[i+1] != "inet" {
					return nil, fmt.Errorf("set %s is not IPv4", name)
				}
			}
			created = true
		case "add":
			if !created || len(fields) < 3 || fields[1] != name {
				return nil, fmt.Errorf("set %s has an entry that is not understood", name)
			}
			if len(members) >= maxSetMembers {
				return nil, fmt.Errorf("set %s has too many members", name)
			}
			prefix, err := parseSetMember(fields[2])
			if err != nil {
				return nil, fmt.Errorf("set %s has a member that is not understood", name)
			}
			members = append(members, prefix)
		default:
			return nil, fmt.Errorf("set %s listing has a line that is not understood", name)
		}
	}
	if !created {
		return nil, fmt.Errorf("set %s was not listed", name)
	}
	return members, nil
}

func parseSetMember(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return netip.Prefix{}, errors.New("not an IPv4 network")
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, errors.New("not an IPv4 address")
	}
	return netip.PrefixFrom(addr, 32), nil
}

// setsLimitSourceOutside reports whether the rule's set matches positively
// limit its SOURCE to addresses outside tunnel, and names the sets that carry
// that proof. It is true only for a non-negated, source-only match on a set
// that was read and whose every member is disjoint from tunnel. A negated
// match, a destination match, an unread set or an overlapping member proves
// nothing: the caller must then refuse the rule.
func setsLimitSourceOutside(matches []setMatch, sets map[string][]netip.Prefix, tunnel netip.Prefix) (bool, []string) {
	proof := []string{}
	for _, match := range matches {
		if match.Negated || len(match.Dirs) != 1 || match.Dirs[0] != "src" {
			continue
		}
		members, read := sets[match.Name]
		if !read {
			continue
		}
		outside := true
		for _, member := range members {
			if member.Overlaps(tunnel) {
				outside = false
				break
			}
		}
		if outside {
			proof = append(proof, match.Name)
		}
	}
	return len(proof) > 0, proof
}
