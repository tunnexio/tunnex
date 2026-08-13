package devices

import (
	"encoding/json"
	"testing"
	"time"
)

func osCheck(mode, minJSON string) HealthCheckConfig {
	return HealthCheckConfig{Kind: CheckOSVersion, Mode: mode, Param: json.RawMessage(`{"min":` + minJSON + `}`)}
}

func diskCheck(mode string) HealthCheckConfig {
	return HealthCheckConfig{Kind: CheckDiskEncryption, Mode: mode}
}

func bp(b bool) *bool { return &b }

func TestEvaluateHealthNoChecksIsCompliant(t *testing.T) {
	ev := evaluateHealth(nil, HealthFacts{Platform: "macos", OSVersion: "14.5", DiskEncrypted: bp(false)})
	if ev.State != "compliant" || ev.Blocked || len(ev.FailedChecks) != 0 {
		t.Fatalf("no configured checks must evaluate compliant (default-off by construction): %+v", ev)
	}
}

func TestEvaluateHealthDiskEncryption(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		encrypted *bool
		wantState string
		wantBlock bool
	}{
		{"require+encrypted passes", ModeRequire, bp(true), "compliant", false},
		{"require+unencrypted blocks", ModeRequire, bp(false), "noncompliant", true},
		{"warn+unencrypted never gates", ModeWarn, bp(false), "noncompliant", false},
		// A required check cannot pass without a positive fact. An absent helper
		// result is indeterminate and therefore blocks fail-closed.
		{"require+indeterminate fact blocks", ModeRequire, nil, "noncompliant", true},
		{"warn+indeterminate fact is visible but does not gate", ModeWarn, nil, "noncompliant", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := evaluateHealth([]HealthCheckConfig{diskCheck(c.mode)},
				HealthFacts{Platform: "macos", OSVersion: "14.5", DiskEncrypted: c.encrypted})
			if ev.State != c.wantState || ev.Blocked != c.wantBlock {
				t.Fatalf("got state=%s blocked=%v, want state=%s blocked=%v", ev.State, ev.Blocked, c.wantState, c.wantBlock)
			}
		})
	}
}

func TestEvaluateHealthOSVersionPerPlatform(t *testing.T) {
	check := osCheck(ModeRequire, `{"macos":"14.0","windows":"10.0.22631"}`)
	cases := []struct {
		name      string
		platform  string
		version   string
		wantBlock bool
	}{
		{"macos at min passes", "macos", "14.0", false},
		{"macos above min passes", "macos", "15.1", false},
		{"macos below min blocks", "macos", "13.6", true},
		{"windows below min blocks", "windows", "10.0.19045", true},
		{"windows at min passes", "windows", "10.0.22631", false},
		// A platform ABSENT from min is NOT enforced on it (fail-open per the
		// threat model — the macOS min must not black-hole a Windows fleet).
		{"unconfigured platform passes", "linux", "0.1", false},
		// Numeric segment compare, not string compare: "9" < "10".
		{"numeric not lexicographic", "macos", "9.9", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := evaluateHealth([]HealthCheckConfig{check},
				HealthFacts{Platform: c.platform, OSVersion: c.version, DiskEncrypted: bp(true)})
			if ev.Blocked != c.wantBlock {
				t.Fatalf("platform=%s version=%s: blocked=%v, want %v", c.platform, c.version, ev.Blocked, c.wantBlock)
			}
		})
	}
}

func TestEvaluateHealthUnparseableVersionBlocksUnderRequire(t *testing.T) {
	// A garbled version under an opted-in require min is a POSITIVE bad report
	// (not absence): it gates. Absence semantics apply only to missing reports.
	ev := evaluateHealth([]HealthCheckConfig{osCheck(ModeRequire, `{"macos":"14.0"}`)},
		HealthFacts{Platform: "macos", OSVersion: "garbage", DiskEncrypted: bp(true)})
	if !ev.Blocked {
		t.Fatal("unparseable os_version under a require-mode min must block")
	}
}

func TestEvaluateHealthWarnAndRequireCombine(t *testing.T) {
	checks := []HealthCheckConfig{diskCheck(ModeWarn), osCheck(ModeRequire, `{"macos":"14.0"}`)}
	ev := evaluateHealth(checks, HealthFacts{Platform: "macos", OSVersion: "13.0", DiskEncrypted: bp(false)})
	if !ev.Blocked || ev.State != "noncompliant" || len(ev.FailedChecks) != 2 {
		t.Fatalf("want both checks failed and blocked (require wins): %+v", ev)
	}
	// Warn-only failure must not block.
	ev = evaluateHealth(checks, HealthFacts{Platform: "macos", OSVersion: "14.1", DiskEncrypted: bp(false)})
	if ev.Blocked || ev.State != "noncompliant" || len(ev.FailedChecks) != 1 {
		t.Fatalf("warn-only failure must surface without gating: %+v", ev)
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		v, min string
		want   bool
	}{
		{"14.5", "14.0", false},
		{"14.0", "14.0", false},
		{"13.9.9", "14.0", true},
		{"10.0.22631", "10.0.19045", false},
		{"14", "14.0.0", false},       // missing segments are zero
		{"14.0.1", "14", false},       // longer version above shorter min
		{"22631H2.1", "22631", false}, // leading digits of a segment are used
		{"", "14.0", true},            // empty = unparseable = less
	}
	for _, c := range cases {
		if got := versionLess(c.v, c.min); got != c.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}

func TestHealthInfoFor(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)
	stale := now.Add(-HealthStaleTTL - time.Minute)
	state := "noncompliant"
	osv := "13.0"
	fc := []byte(`[{"kind":"os_version","mode":"require"}]`)

	// Never reported: unknown, no facts — absence is not compliance.
	info := healthInfoFor(false, nil, nil, nil, nil, nil, now)
	if info.State != "unknown" || info.Blocked || len(info.FailedChecks) != 0 {
		t.Fatalf("never-reported must be unknown: %+v", info)
	}

	// Fresh report: state + failed checks surface as current claims.
	info = healthInfoFor(true, &state, fc, &osv, bp(true), &fresh, now)
	if info.State != "noncompliant" || !info.Blocked || len(info.FailedChecks) != 1 || info.OSVersion != "13.0" {
		t.Fatalf("fresh report must surface state+failures: %+v", info)
	}

	// Stale report: state degrades to unknown (stale = absence) and its failures
	// are no longer current claims — but the raw facts + reported_at stay visible,
	// and a not-yet-swept block is still shown (the device IS still excluded).
	info = healthInfoFor(true, &state, fc, &osv, bp(true), &stale, now)
	if info.State != "unknown" || len(info.FailedChecks) != 0 {
		t.Fatalf("stale report must read unknown with no current failures: %+v", info)
	}
	if !info.Blocked || info.OSVersion != "13.0" || info.ReportedAt == nil {
		t.Fatalf("stale report must keep the block flag + raw facts visible: %+v", info)
	}
}

func TestValidateHealthCheck(t *testing.T) {
	if err := validateHealthCheck(CheckDiskEncryption, ModeRequire, nil); err != nil {
		t.Fatalf("disk_encryption with no param must validate: %v", err)
	}
	if err := validateHealthCheck(CheckDiskEncryption, ModeWarn, json.RawMessage(`{"min":{}}`)); err == nil {
		t.Fatal("disk_encryption with a param must be rejected")
	}
	if err := validateHealthCheck(CheckOSVersion, ModeRequire, json.RawMessage(`{"min":{"macos":"14.0"}}`)); err != nil {
		t.Fatalf("valid os_version param must validate: %v", err)
	}
	if err := validateHealthCheck(CheckOSVersion, ModeRequire, nil); err == nil {
		t.Fatal("os_version without a min param must be rejected")
	}
	if err := validateHealthCheck(CheckOSVersion, ModeRequire, json.RawMessage(`{"min":{"amiga":"1.0"}}`)); err == nil {
		t.Fatal("unknown platform in min must be rejected")
	}
	if err := validateHealthCheck(CheckOSVersion, ModeRequire, json.RawMessage(`{"min":{"macos":"latest"}}`)); err == nil {
		t.Fatal("non-numeric min version must be rejected")
	}
	if err := validateHealthCheck("edr_present", ModeRequire, nil); err == nil {
		t.Fatal("edr_present is S7.5.3b — must be rejected in v1")
	}
	if err := validateHealthCheck(CheckDiskEncryption, "block", nil); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}
