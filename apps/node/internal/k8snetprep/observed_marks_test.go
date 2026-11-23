package k8snetprep

import (
	"errors"
	"net/netip"
	"testing"
)

func oifname(op, name string) string {
	return `{"match":{"op":"` + op + `","left":{"meta":{"key":"oifname"}},"right":"` + name + `"}}`
}

// A masquerade bound to one exact output interface cannot apply to traffic
// that leaves through the tunnel interface. Nothing weaker is accepted.
func TestObservedReadsExactOutputInterface(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	for _, tc := range []struct {
		name, rule, egress string
		accepted           bool
	}{
		{"another exact interface", oifname("==", "tunl0"), "wg0", true},
		{"the tunnel interface itself", oifname("==", "wg0"), "wg0", false},
		{"egress not known", oifname("==", "tunl0"), "", false},
		{"wildcard", oifname("==", "tunl*"), "wg0", false},
		{"wildcard that covers the tunnel", oifname("==", "wg*"), "wg0", false},
		{"negated", oifname("!=", "tunl0"), "wg0", false},
		{"negated tunnel interface", oifname("!=", "wg0"), "wg0", false},
		{"set of names", `{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":{"set":["tunl0","eth0"]}}}`, "wg0", false},
		{"input interface", `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tunl0"}}`, "wg0", false},
	} {
		names, rules := observedRules(t, map[string][]string{"POSTROUTING": {`[` + tc.rule + `,` + xtAddrtype + `,` + xtMasquerade + `]`}})
		_, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, tc.egress, nil, nil)
		if (err == nil) != tc.accepted {
			t.Errorf("%s: accepted=%v, err=%v", tc.name, err == nil, err)
		}
	}
	names, rules := observedRules(t, map[string][]string{"POSTROUTING": nil})
	if _, err := proveNoTunnelSourceNATWithSets(names, rules, "POSTROUTING", tunnel, "wg*", nil, nil); err == nil {
		t.Error("a wildcard tunnel interface was accepted")
	}
}

func mangleSaved(t *testing.T, lines string) map[string][]savedRule {
	t.Helper()
	saved, err := parseSavedRules(lines)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestMangleHookIsAcceptedOnlyWhenItCannotSetAKubernetesMark(t *testing.T) {
	chains := map[string][]string{
		"POSTROUTING": {`[` + xtComment + `,{"jump":{"target":"cni"}}]`},
		"cni": {
			`[` + xtComment + `,` + kubeUnmarked + `,` + returnVerdict + `]`,
			`[` + xtComment + `,` + xtMark + `]`,
		},
	}
	save := func(mark string) string {
		return "-A POSTROUTING -m comment --comment x -j cni\n" +
			"-A cni -m comment --comment \"a -j MARK --set-xmark 0x0/0x0\" -m mark ! --mark 0x4000/0x4000 -j RETURN\n" +
			"-A cni -m comment --comment y -j MARK " + mark + "\n"
	}
	names, rules := observedRules(t, chains)
	if err := proveCannotSetReservedMarks(names, rules, "POSTROUTING", nil); !errors.Is(err, errMarkFactsNeeded) {
		t.Fatalf("unread MARK: %v", err)
	}
	for mark, accepted := range map[string]bool{
		"--set-xmark 0x0/0x1b0000":         true,
		"--set-xmark 0x10000/0x10000":      true,
		"--set-xmark 0x4000/0x4000":        false, // kube-proxy masquerade mark
		"--set-xmark 0x0/0x4000":           false, // clears it: still a change
		"--set-xmark 0x2000/0x0":           false, // XOR without a mask
		"--set-xmark 0x8000/0xffffffff":    false,
		"--set-xmark 0x0/0xffffffff":       false, // --set-mark 0
		"--set-xmark 0x1/0x1 --extra":      false,
		"--set-mark 0x1":                   false, // not a form the save prints
		"--set-xmark 0x1":                  false,
		"--set-xmark 1/1":                  false,
		"--set-xmark 0x100000000/0x1":      false,
		"--set-xmark 0x1/0x1 -j ACCEPT":    false, // target no longer pairs
		"--set-xmark 0x0/0x1b0000 -g cni2": false,
	} {
		err := proveCannotSetReservedMarks(names, rules, "POSTROUTING", mangleSaved(t, save(mark)))
		if (err == nil) != accepted {
			t.Errorf("%s: accepted=%v, err=%v", mark, err == nil, err)
		}
	}
	// The saved text must describe the same chain: a rule more, a rule less
	// or another order is refused, not read by position.
	for name, text := range map[string]string{
		"missing rule": "-A POSTROUTING -j cni\n-A cni -j MARK --set-xmark 0x0/0x1\n",
		"swapped":      "-A POSTROUTING -j cni\n-A cni -j MARK --set-xmark 0x0/0x1\n-A cni -j RETURN\n",
		"empty":        "",
	} {
		if err := proveCannotSetReservedMarks(names, rules, "POSTROUTING", mangleSaved(t, text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMangleHookRefusesWhatItCannotRead(t *testing.T) {
	for name, chains := range map[string]map[string][]string{
		"other extension target":  {"POSTROUTING": {`[{"xt":{"type":"target","name":"CONNMARK"}}]`}},
		"native mark statement":   {"POSTROUTING": {`[{"mangle":{"key":{"meta":{"key":"mark"}},"value":16384}}]`}},
		"untyped extension":       {"POSTROUTING": {`[{"xt":null}]`}},
		"jump to a missing chain": {"POSTROUTING": {`[{"jump":{"target":"GONE"}}]`}},
		"target before the end":   {"POSTROUTING": {`[` + xtMark + `,` + returnVerdict + `]`}},
		"two keys":                {"POSTROUTING": {`[{"return":null,"accept":null}]`}},
		"reached through a goto":  {"POSTROUTING": {`[{"goto":{"target":"A"}}]`}, "A": {`[{"xt":{"type":"target","name":"DSCP"}}]`}},
	} {
		names, rules := observedRules(t, chains)
		err := proveCannotSetReservedMarks(names, rules, "POSTROUTING", map[string][]savedRule{})
		if err == nil || errors.Is(err, errMarkFactsNeeded) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A chain that only matches, returns and loops back sets nothing.
	names, rules := observedRules(t, map[string][]string{
		"POSTROUTING": {`[` + xtComment + `,{"jump":{"target":"A"}}]`, `[` + xtComment + `]`},
		"A":           {`[` + kubeUnmarked + `,{"accept":null}]`, `[{"jump":{"target":"POSTROUTING"}}]`, `[{"drop":null}]`},
	})
	if err := proveCannotSetReservedMarks(names, rules, "POSTROUTING", nil); err != nil {
		t.Errorf("chain without a mark target: %v", err)
	}
}
