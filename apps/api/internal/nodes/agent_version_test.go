package nodes

import (
	"strings"
	"testing"
)

func TestReportedAgentVersionIsBoundedOrIgnored(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.45":      "v0.1.45",
		"  v0.1.45\n":  "v0.1.45",
		"k8n4-3f2a1b0": "k8n4-3f2a1b0",
		"dev":          "dev",
		// CI stamps a release tag, or the full commit sha for untagged builds.
		"0d4e2d55a1b2c3d4e5f60718293a4b5c6d7e8f90": "0d4e2d55a1b2c3d4e5f60718293a4b5c6d7e8f90",
		"1.2.3+build.7~rc1":                        "1.2.3+build.7~rc1",
		"":                                         "",
		"   ":                                      "",
		"v1 <script>":                              "",
		"v1\x00":                                   "",
		"-leading-dash":                            "",
		"v1.2.3\nInjected: yes":                    "",
		strings.Repeat("a", 50):                    strings.Repeat("a", 50),
		strings.Repeat("a", 51):                    "",
		"ünïcode":                                  "",
	} {
		if got := reportedAgentVersion(in); got != want {
			t.Errorf("reportedAgentVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
