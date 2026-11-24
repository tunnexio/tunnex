package nodes

import (
	"strings"
	"testing"
)

func TestReportedAgentVersionIsBoundedOrIgnored(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.45":               "v0.1.45",
		"  v0.1.45\n":           "v0.1.45",
		"k8n4-3f2a1b0":          "k8n4-3f2a1b0",
		"dev":                   "dev",
		"1.2.3+build.7~rc1":     "1.2.3+build.7~rc1",
		"":                      "",
		"   ":                   "",
		"v1 <script>":           "",
		"v1\x00":                "",
		"-leading-dash":         "",
		"v1.2.3\nInjected: yes": "",
		strings.Repeat("a", 50): strings.Repeat("a", 50),
		strings.Repeat("a", 51): "",
		"ünïcode":               "",
	} {
		if got := reportedAgentVersion(in); got != want {
			t.Errorf("reportedAgentVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
