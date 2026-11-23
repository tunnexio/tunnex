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
// Only hash:net and hash:ip sets of family inet are understood, and only with
// a header whose every option is known not to change what a member matches
// (checkSetHeader); anything else is an error, never an empty set.
//
// A member line is read by its address or network alone. What may follow it
// (timeout, packets, bytes, comment, skbmark, skbprio, skbqueue, nomatch) can
// only make the set match less: a `nomatch` network is an exception cut out
// of a wider member and is still counted here as a member.
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
			if created {
				return nil, fmt.Errorf("set %s is listed twice", name)
			}
			if fields[2] != "hash:net" && fields[2] != "hash:ip" {
				return nil, fmt.Errorf("set %s has type %s, which is not understood", name, fields[2])
			}
			if err := checkSetHeader(name, fields[3:]); err != nil {
				return nil, err
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

// setHeaderOptions is every option this package accepts after the type on the
// `create` line of a hash:net or hash:ip set, with the form of its value ("" for
// an option that takes none). It is what ipset 7.24 prints for such a set, less
// the two options that change what a listed member matches:
//
//	family inet       required; inet6 is refused
//	hashsize, maxelem, bucketsize, initval
//	                  how the kernel stores the set
//	timeout           members expire by themselves: the set can only match less
//	counters, comment, skbinfo
//	                  per-member extras; skbinfo is used by the SET target with
//	                  --map-set, never by a `-m set` match
//	forceadd          a full set evicts a member to take a new one
//	netmask 32        an address is stored as itself (ipset does not print it)
//
// Refused: `netmask N` below 32 and any `bitmask`. A hash:ip set created with
// one stores and prints the masked address, so the member `10.5.6.0` of a
// `netmask 24` set matches all of 10.5.6.0/24, and with a bitmask the matching
// addresses need not even be one range. Refused as well: every option not
// listed here, an option given twice, and a value of another form.
var setHeaderOptions = map[string]*regexp.Regexp{
	"family":     regexp.MustCompile(`^inet6?$`),
	"hashsize":   setHeaderNumberRE,
	"maxelem":    setHeaderNumberRE,
	"bucketsize": setHeaderNumberRE,
	"timeout":    setHeaderNumberRE,
	"netmask":    setHeaderNumberRE,
	"initval":    regexp.MustCompile(`^0x[0-9a-fA-F]{1,8}$`),
	"counters":   nil,
	"comment":    nil,
	"skbinfo":    nil,
	"forceadd":   nil,
}

var setHeaderNumberRE = regexp.MustCompile(`^[0-9]{1,10}$`)

// checkSetHeader reads the options of a `create` line, after the set's type.
func checkSetHeader(name string, options []string) error {
	seen := map[string]bool{}
	for i := 0; i < len(options); i++ {
		option := options[i]
		if option == "bitmask" {
			return fmt.Errorf("set %s has a bitmask: its members match more addresses than are listed", name)
		}
		form, known := setHeaderOptions[option]
		if !known || seen[option] {
			return fmt.Errorf("set %s has a header option that is not understood", name)
		}
		seen[option] = true
		if form == nil {
			continue
		}
		i++
		if i >= len(options) || !form.MatchString(options[i]) {
			return fmt.Errorf("set %s has a header option that is not understood", name)
		}
		switch {
		case option == "family" && options[i] != "inet":
			return fmt.Errorf("set %s is not IPv4", name)
		case option == "netmask" && options[i] != "32":
			return fmt.Errorf("set %s has netmask %s: its members match whole networks, not the addresses listed", name, options[i])
		}
	}
	if !seen["family"] {
		return fmt.Errorf("set %s does not state its family", name)
	}
	return nil
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
