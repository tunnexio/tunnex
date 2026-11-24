package serveraccess

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

// SA-UX-2 item 8: every reason code the API or gateway can emit has human text in the dashboard, so no raw code
// reaches the UI. The web test asserts the rendering for every code in the same list.
func TestEveryServerAccessCodeHasWebText(t *testing.T) {
	web, e := os.ReadFile(filepath.Join("..", "..", "..", "web", "src", "lib", "serverAccessReasons.ts"))
	if e != nil {
		t.Fatal(e)
	}
	known := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z_]+): \{ text:`).FindAllStringSubmatch(string(web), -1) {
		known[m[1]] = true
	}
	need := map[string]bool{}
	for code := range denyMessages {
		need[code] = true
	}
	for code := range enrollmentFailures {
		need[code] = true
	}
	need["ssh_host_key_unverified"] = true
	need[authorityReason(nil)] = true
	for _, result := range []string{"failed", "ssh_host_key_mismatch", "ssh_unreachable", "ssh_authentication_failed", "ssh_pty_failed"} {
		reason, _ := terminalwire.ResultReason(result)
		need[reason] = true
	}
	files, _ := filepath.Glob("*.go")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`apierr\.(?:BadRequest|Conflict|NotFound|Forbidden)\("([a-z_]+)"`),
		regexp.MustCompile(`apierr\.New\(\d+, "([a-z_]+)"`),
		regexp.MustCompile(`deny\("([a-z_]+)"\)`),
		regexp.MustCompile(`\bend\([^)]*"([a-z_]+)"\)`),
		regexp.MustCompile(`reason :?= "([a-z_]+)"`),
		regexp.MustCompile(`Reason[A-Za-z]* = "([a-z_]+)"`),
		regexp.MustCompile(`THEN '([a-z_]+)' ELSE '[a-z_]+' END FROM server_access_sessions`),
		regexp.MustCompile(`THEN '[a-z_]+' ELSE '([a-z_]+)' END FROM server_access_sessions`),
	}
	for _, f := range files {
		if filepath.Ext(f) != ".go" || len(f) > 8 && f[len(f)-8:] == "_test.go" {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, p := range patterns {
			for _, m := range p.FindAllStringSubmatch(string(src), -1) {
				need[m[1]] = true
			}
		}
	}
	var missing []string
	for code := range need {
		if code != "" && !known[code] {
			missing = append(missing, code)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("Server Access codes without dashboard text in serverAccessReasons.ts: %v", missing)
	}
}
