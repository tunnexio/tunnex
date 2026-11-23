package k8snetprep

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Review finding 4. The walk skips kube-proxy's masquerade because traffic
// bound for the tunnel range carries no Kubernetes mark when it reaches
// `-m mark ! --mark 0x4000/0x4000 -j RETURN`. A rule earlier on the same path
// that sets the mark makes that false: kube-proxy's own chain then
// masquerades the packet. Before the fix a MARK target and a native `mangle`
// statement inside the NAT table were read as doing nothing.

// natMarkChains is ip nat as a kube-proxy node has it, with the rules under
// test placed in POSTROUTING before kube-proxy's chain.
func natMarkChains(first ...string) map[string][]string {
	return map[string][]string{
		"POSTROUTING": append(first, `[`+xtComment+`,{"jump":{"target":"KUBE-POSTROUTING"}}]`),
		"KUBE-POSTROUTING": {
			`[` + kubeUnmarked + `,` + returnVerdict + `]`,
			`[` + xtMark + `]`,
			`[` + xtComment + `,` + xtMasquerade + `]`,
		},
	}
}

// natMarkSaved is the saved text for natMarkChains, the rules under test
// given without their `-A POSTROUTING` prefix.
func natMarkSaved(t *testing.T, first ...string) *natSetFacts {
	t.Helper()
	lines := ""
	for _, rule := range first {
		lines += "-A POSTROUTING " + rule + "\n"
	}
	lines += "-A POSTROUTING -m comment --comment \"kubernetes postrouting rules\" -j KUBE-POSTROUTING\n" +
		"-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN\n" +
		"-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0\n" +
		"-A KUBE-POSTROUTING -m comment --comment \"kubernetes service traffic requiring SNAT\" -j MASQUERADE --random-fully\n"
	saved, err := parseSavedRules(lines)
	if err != nil {
		t.Fatal(err)
	}
	return &natSetFacts{saved: saved, members: map[string][]netip.Prefix{}}
}

func nativeMark(value string) string {
	return `{"mangle":{"key":{"meta":{"key":"mark"}},"value":` + value + `}}`
}

const oldMark = `{"meta":{"key":"mark"}}`

func TestObservedNATWalkReadsANativeMarkStatement(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	for name, tc := range map[string]struct {
		rule string
		want string // empty: accepted
	}{
		// What nft 1.1.6 prints for `meta mark set ...`, each form.
		"another bit":                       {rule: `[` + nativeMark(`1`) + `]`},
		"zero":                              {rule: `[` + nativeMark(`0`) + `]`},
		"or with another bit":               {rule: `[` + nativeMark(`{"|":[`+oldMark+`,256]}`) + `]`},
		"xor with another bit":              {rule: `[` + nativeMark(`{"^":[`+oldMark+`,256]}`) + `]`},
		"clearing the kube-proxy mark":      {rule: `[` + nativeMark(`{"&":[`+oldMark+`,4294950911]}`) + `]`},
		"and then or, another bit":          {rule: `[` + nativeMark(`{"|":[{"&":[`+oldMark+`,4294902271]},256]}`) + `]`},
		"and with a mask that has the bits": {rule: `[` + nativeMark(`{"&":[`+oldMark+`,65535]}`) + `]`},
		"before a verdict":                  {rule: `[` + nativeMark(`1`) + `,` + returnVerdict + `]`},
		"before a pod-sourced masquerade":   {rule: `[` + saddr("==", "10.244.0.0", 16) + `,` + nativeMark(`1`) + `,{"masquerade":null}]`},

		"the kube-proxy mark":          {rule: `[` + nativeMark(`16384`) + `]`, want: "NAT chain POSTROUTING can set a Kubernetes mark"},
		"the portmap mark":             {rule: `[` + nativeMark(`8192`) + `]`, want: "can set a Kubernetes mark"},
		"the drop mark":                {rule: `[` + nativeMark(`32768`) + `]`, want: "can set a Kubernetes mark"},
		"every bit":                    {rule: `[` + nativeMark(`4294967295`) + `]`, want: "can set a Kubernetes mark"},
		"or with the mark":             {rule: `[` + nativeMark(`{"|":[`+oldMark+`,16384]}`) + `]`, want: "can set a Kubernetes mark"},
		"xor with the mark":            {rule: `[` + nativeMark(`{"^":[`+oldMark+`,16384]}`) + `]`, want: "can set a Kubernetes mark"},
		"and then or with the mark":    {rule: `[` + nativeMark(`{"|":[{"&":[`+oldMark+`,4294902271]},24576]}`) + `]`, want: "can set a Kubernetes mark"},
		"or of two constants":          {rule: `[` + nativeMark(`{"|":[256,16384]}`) + `]`, want: "can set a Kubernetes mark"},
		"and of two constants":         {rule: `[` + nativeMark(`{"&":[65535,16384]}`) + `]`, want: "can set a Kubernetes mark"},
		"before a verdict, the mark":   {rule: `[` + nativeMark(`16384`) + `,` + returnVerdict + `]`, want: "can set a Kubernetes mark"},
		"behind another destination":   {rule: `[` + daddr("==", "10.0.0.0", 8) + `,` + nativeMark(`16384`) + `]`, want: "can set a Kubernetes mark"},
		"set, then matched and used":   {rule: `[` + nativeMark(`16384`) + `,{"match":{"op":"==","left":{"&":[` + oldMark + `,16384]},"right":16384}},{"masquerade":null}]`, want: "can set a Kubernetes mark"},
		"from the connection mark":     {rule: `[` + nativeMark(`{"ct":{"key":"mark"}}`) + `]`, want: "sets a mark to a value that is not understood"},
		"connection mark, masked":      {rule: `[` + nativeMark(`{"&":[{"ct":{"key":"mark"}},255]}`) + `]`, want: "sets a mark to a value that is not understood"},
		"from a map":                   {rule: `[` + nativeMark(`{"map":{"key":{"payload":{"protocol":"ip","field":"dscp"}},"data":{"set":[["ef",16384]]}}}`) + `]`, want: "value that is not understood"},
		"from a number generator":      {rule: `[` + nativeMark(`{"numgen":{"mode":"inc","mod":2,"offset":0}}`) + `]`, want: "value that is not understood"},
		"shifted":                      {rule: `[` + nativeMark(`{"<<":[`+oldMark+`,1]}`) + `]`, want: "value that is not understood"},
		"a string":                     {rule: `[` + nativeMark(`"0x1"`) + `]`, want: "value that is not understood"},
		"a negative number":            {rule: `[` + nativeMark(`-1`) + `]`, want: "value that is not understood"},
		"a fraction":                   {rule: `[` + nativeMark(`1.5`) + `]`, want: "value that is not understood"},
		"more than 32 bits":            {rule: `[` + nativeMark(`4294967296`) + `]`, want: "value that is not understood"},
		"three operands":               {rule: `[` + nativeMark(`{"|":[`+oldMark+`,1,2]}`) + `]`, want: "value that is not understood"},
		"nested too deeply":            {rule: `[` + nativeMark(`{"|":[{"|":[{"|":[{"|":[{"|":[`+oldMark+`,1]},1]},1]},1]},1]}`) + `]`, want: "value that is not understood"},
		"no value":                     {rule: `[{"mangle":{"key":{"meta":{"key":"mark"}},"flags":1}}]`, want: "value that is not understood"},
		"source address rewritten":     {rule: `[{"mangle":{"key":{"payload":{"protocol":"ip","field":"saddr"}},"value":"10.0.0.1"}}]`, want: "NAT chain POSTROUTING rewrites a packet field with a statement that is not understood"},
		"destination rewritten":        {rule: `[` + daddr("==", "10.0.0.0", 8) + `,{"mangle":{"key":{"payload":{"protocol":"ip","field":"daddr"}},"value":"100.96.0.5"}}]`, want: "rewrites a packet field"},
		"connection mark set":          {rule: `[{"mangle":{"key":{"ct":{"key":"mark"}},"value":` + oldMark + `}}]`, want: "rewrites a packet field"},
		"priority set":                 {rule: `[{"mangle":{"key":{"meta":{"key":"priority"}},"value":"1:2"}}]`, want: "rewrites a packet field"},
		"DSCP set before a verdict":    {rule: `[{"mangle":{"key":{"payload":{"protocol":"ip","field":"dscp"}},"value":"ef"}},` + returnVerdict + `]`, want: "rewrites a packet field"},
		"mangle that is not an object": {rule: `[{"mangle":null}]`, want: "rewrites a packet field"},
		"mangle with a third member":   {rule: `[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1,"flags":1}}]`, want: "rewrites a packet field"},
	} {
		names, rules := observedRules(t, natMarkChains(tc.rule))
		_, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, nil)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		case err != nil && errors.Is(err, errSetFactsNeeded):
			t.Errorf("%s: a native statement asked for saved text: %v", name, err)
		}
	}
}

func TestObservedNATWalkReadsAMarkTargetFromItsSavedRule(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	mark := `[` + xtMark + `]`

	// Without the saved text the value is unknown: refused, and the caller is
	// told that reading the saved rules may lift it.
	names, rules := observedRules(t, natMarkChains(mark))
	_, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, nil)
	if err == nil || !errors.Is(err, errSetFactsNeeded) || err.Error() != "NAT chain POSTROUTING sets a mark whose value was not read" {
		t.Fatalf("unread MARK: %v", err)
	}

	for name, tc := range map[string]struct {
		saved string
		want  string // empty: accepted
	}{
		"Calico's mark":                 {saved: "-j MARK --set-xmark 0x0/0x1b0000"},
		"another bit":                   {saved: "-m comment --comment x -j MARK --set-xmark 0x100/0x100"},
		"sets the kube-proxy mark":      {saved: "-j MARK --set-xmark 0x4000/0x4000", want: "NAT chain POSTROUTING can set a Kubernetes mark that selects a masquerade"},
		"toggles the kube-proxy mark":   {saved: "-j MARK --set-xmark 0x4000/0x0", want: "can set a Kubernetes mark"},
		"sets the portmap mark":         {saved: "-j MARK --set-xmark 0x2000/0x2000", want: "can set a Kubernetes mark"},
		"sets every bit":                {saved: "-j MARK --set-xmark 0xffffffff/0xffffffff", want: "can set a Kubernetes mark"},
		"clears the kube-proxy mark":    {saved: "-j MARK --set-xmark 0x0/0x4000", want: "can set a Kubernetes mark"},
		"another option":                {saved: "-j MARK --set-mark 0x1", want: "MARK target that is not understood"},
		"no mask":                       {saved: "-j MARK --set-xmark 0x1", want: "MARK target that is not understood"},
		"decimal value":                 {saved: "-j MARK --set-xmark 16384/16384", want: "MARK target that is not understood"},
		"saved rule has another target": {saved: "-j RETURN", want: "does not pair with its saved rule"},
		"saved rule carries a set":      {saved: "-m set --match-set pods src -j MARK --set-xmark 0x0/0x1", want: "does not pair with its saved rule"},
	} {
		names, rules := observedRules(t, natMarkChains(mark))
		_, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, natMarkSaved(t, tc.saved))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
		// Collecting the sets a proof needs walks the same way.
		_, collectErr := setsNeededForProof(names, rules, "POSTROUTING", tunnel, "wg0", nil, natMarkSaved(t, tc.saved).saved)
		if (collectErr == nil) != (err == nil) {
			t.Errorf("%s: collecting sets: %v, proving: %v", name, collectErr, err)
		}
	}

	// The saved text at hand has a rule more or a rule less for the chain.
	names, rules = observedRules(t, natMarkChains(mark))
	if _, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, natMarkSaved(t)); err == nil || !strings.Contains(err.Error(), "POSTROUTING has 2 rules but 1 saved rules") {
		t.Errorf("saved text with a rule less: %v", err)
	}
	// The saved text does not hold the chain at all, as when the manager
	// carried other chains only.
	chains := natMarkChains(`[{"jump":{"target":"cni"}}]`)
	chains["cni"] = []string{mark}
	names, rules = observedRules(t, chains)
	if _, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, natMarkSaved(t, "-j cni")); err == nil || err.Error() != "NAT chain cni sets a mark whose value was not read: its saved rules are not at hand" || errors.Is(err, errSetFactsNeeded) {
		t.Errorf("chain not in the saved text: %v", err)
	}
}

// A MARK target that traffic bound for the tunnel range cannot reach is not
// read: kube-proxy's own chains stay accepted with no saved text at all, as
// on every captured node.
func TestObservedNATWalkDoesNotReadAMarkItCannotReach(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	for name, chains := range map[string]map[string][]string{
		"kube-proxy's chain alone":      natMarkChains(),
		"behind another destination":    natMarkChains(`[` + daddr("==", "10.0.0.0", 8) + `,` + xtMark + `]`),
		"behind the mark it would need": natMarkChains(`[{"match":{"op":"==","left":{"&":[` + oldMark + `,8192]},"right":8192}},` + xtMark + `]`),
		"after a certain accept":        natMarkChains(`[`+daddr("==", "100.64.0.0", 10)+`,{"accept":null}]`, `[`+xtMark+`]`),
		"in a chain nothing jumps to": func() map[string][]string {
			c := natMarkChains()
			c["KUBE-MARK-MASQ"] = []string{`[` + xtMark + `]`}
			return c
		}(),
	} {
		names, rules := observedRules(t, chains)
		if _, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Reached through a jump, behind an extension match, or as the target of a
	// goto, it is read.
	for name, chains := range map[string]map[string][]string{
		"behind an extension match": natMarkChains(`[` + xtAddrtype + `,` + xtMark + `]`),
		"in a chain jumped to": func() map[string][]string {
			c := natMarkChains(`[{"jump":{"target":"cni"}}]`)
			c["cni"] = []string{`[` + xtMark + `]`}
			return c
		}(),
		"in a chain reached by goto": func() map[string][]string {
			c := natMarkChains(`[` + xtAddrtype + `,{"goto":{"target":"cni"}}]`)
			c["cni"] = []string{`[` + xtMark + `]`}
			return c
		}(),
	} {
		names, rules := observedRules(t, chains)
		if _, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg0", nil, nil); err == nil || !errors.Is(err, errSetFactsNeeded) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMarkBitsTurnedOn(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint32
		ok    bool
	}{
		{`0`, 0, true},
		{`16384`, 0x4000, true},
		{`4294967295`, 0xffffffff, true},
		{oldMark, 0, true},
		{`{"|":[` + oldMark + `,16384]}`, 0x4000, true},
		{`{"^":[` + oldMark + `,24576]}`, 0x6000, true},
		{`{"&":[` + oldMark + `,16384]}`, 0, true},
		{`{"&":[16384,` + oldMark + `]}`, 0, true},
		{`{"&":[24576,16385]}`, 0x4000, true},
		{`{"|":[{"&":[` + oldMark + `,4294902271]},256]}`, 0x100, true},
		{`{"^":[{"&":[` + oldMark + `,4294950911]},16384]}`, 0x4000, true},
		{`{"ct":{"key":"mark"}}`, 0, false},
		{`{"meta":{"key":"priority"}}`, 0, false},
		{`{"|":[` + oldMark + `]}`, 0, false},
		{`{"|":[` + oldMark + `,{"ct":{"key":"mark"}}]}`, 0, false},
		{`{"|":[` + oldMark + `,1],"&":[` + oldMark + `,1]}`, 0, false},
		{`{">>":[` + oldMark + `,1]}`, 0, false},
		{`[16384]`, 0, false},
		{`null`, 0, false},
		{`true`, 0, false},
	} {
		names, rules := observedRules(t, map[string][]string{"c": {`[{"probe":` + tc.value + `}]`}})
		_ = names
		got, ok := markBitsTurnedOn(rules["c"][0][0]["probe"], 0)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: %#x %v, want %#x %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}
