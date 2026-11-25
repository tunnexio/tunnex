package bootstrap

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// SA-UX-3: the helper and launcher may print only allow-listed codes, and every allow-listed code is printed by one
// of them, so the gateway, the control plane and the target cannot drift.
func TestSetupErrorCodesMatchTargetScripts(t *testing.T) {
	seen := map[string]bool{}
	for _, source := range []string{Helper, Authorize} {
		for _, m := range regexp.MustCompile(`'(setup_[a-z_]+)'`).FindAllStringSubmatch(source, -1) {
			seen[m[1]] = true
		}
	}
	var unknown, unused []string
	for code := range seen {
		if !SetupErrorCodes[code] {
			unknown = append(unknown, code)
		}
	}
	for code := range SetupErrorCodes {
		if !seen[code] {
			unused = append(unused, code)
		}
		if !regexp.MustCompile(`^setup_[a-z_]+$`).MatchString(code) || len(SetupErrorPrefix)+len(code) > setupErrorLineLimit {
			t.Fatalf("code %q is not a short snake_case setup_ code", code)
		}
	}
	sort.Strings(unknown)
	sort.Strings(unused)
	if len(unknown) > 0 || len(unused) > 0 {
		t.Fatalf("target scripts print codes outside the allow-list %v; allow-listed codes never printed %v", unknown, unused)
	}
	if !strings.Contains(Helper, "ERROR_PREFIX = '"+SetupErrorPrefix+"'") || !strings.Contains(Authorize, "'"+SetupErrorPrefix+"'") {
		t.Fatal("target scripts do not use the shared structured line prefix")
	}
}

func TestParseSetupErrorAcceptsOnlyExactAllowListedLines(t *testing.T) {
	for _, tc := range []struct {
		name, output, want string
	}{
		{"exact", "Detected Linux: Ubuntu\nTUNNEX SSH SETUP ERROR setup_existing_setup\nError: Existing setup found\n", "setup_existing_setup"},
		{"crlf", "TUNNEX SSH SETUP ERROR setup_port_in_use\r\n", "setup_port_in_use"},
		{"last wins", "TUNNEX SSH SETUP ERROR setup_not_root\nTUNNEX SSH SETUP ERROR setup_ip_mismatch\n", "setup_ip_mismatch"},
		{"no line", "Error: something\n", ""},
		{"unknown code", "TUNNEX SSH SETUP ERROR setup_exfiltrate\n", ""},
		{"trailing text", "TUNNEX SSH SETUP ERROR setup_not_root secret=abc\n", ""},
		{"free text", "TUNNEX SSH SETUP ERROR Existing setup found at /etc\n", ""},
		{"leading text", "x TUNNEX SSH SETUP ERROR setup_not_root\n", ""},
		{"oversize", "TUNNEX SSH SETUP ERROR setup_not_root" + strings.Repeat(" ", 80) + "\n", ""},
		{"missing space", "TUNNEX SSH SETUP ERRORsetup_not_root\n", ""},
		{"attestation is not an error", "TUNNEX HOST KEY ATTESTATION {}\n", ""},
	} {
		if got := ParseSetupError([]byte(tc.output)); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
