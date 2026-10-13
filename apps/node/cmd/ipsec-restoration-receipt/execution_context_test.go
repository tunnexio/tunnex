package main

import "testing"

func TestHelperHostSupervisorExecutionContext(t *testing.T) {
	boot := "6133d07a-dfbf-4372-9039-324214fe824b"
	host, target := "net:[4026531840]", "net:[4026532520]"
	if err := validateExecutionContext(boot, host, boot, target, true); err != nil {
		t.Fatal("independently verified container target refused from host supervisor", err)
	}
	for name, check := range map[string]struct {
		hostBoot, selfNS, targetBoot, targetNS string
		fresh                                  bool
	}{
		"legacy host cannot name foreign target": {boot, host, boot, target, false},
		"fresh cannot change host boot":          {boot, host, "foreign", target, true},
	} {
		t.Run(name, func(t *testing.T) {
			if validateExecutionContext(check.hostBoot, check.selfNS, check.targetBoot, check.targetNS, check.fresh) == nil {
				t.Fatal("unverified context accepted")
			}
		})
	}
	if err := validateExecutionContext(boot, target, boot, target, false); err != nil {
		t.Fatal("legacy same-namespace invocation refused", err)
	}
}
