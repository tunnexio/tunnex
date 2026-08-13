package http

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoUnloggedFiveHundredPath — S11-5 census (the condition that makes the two-site fix survive).
//
// THE DEFECT THIS GUARDS: an unmapped error becoming a 500 whose body deliberately carries no internal
// detail. Unless the WRAPPED CAUSE is logged, it is destroyed and the only record is `status:500` — which is
// how the audit-nil defect (a NOT NULL violation 500ing every audited DELETE) stayed invisible until it was
// reproduced against the DB directly.
//
// apierr.Write is the ONE seam that logs cause + request_id. It was NOT the only path: agentchannel.go had
// four hand-rolled `http.Error(w, "internal error", 500)` sites on the FLEET'S OWN reporting channel
// (ReportStatus / IngestBatch / desired-state / flow-events) — structurally identical paths, one guarded and
// one not: guard-not-mirrored, 5th instance. Those now route through apierr.Write.
//
// This census keeps it that way: a NEW hand-rolled 500 anywhere under internal/http fails the build, so the
// sixth path cannot be unmirrored by default. Adding one is fine — route it through apierr.Write (or add a
// justified exemption here, deliberately, in review).
func TestNoUnloggedFiveHundredPath(t *testing.T) {
	// Any direct write of a 500 that does NOT go through apierr.Write.
	directFiveHundred := regexp.MustCompile(`http\.Error\([^)]*http\.StatusInternalServerError`)
	// Constructing the status by number is the same defect wearing a different face.
	numericFiveHundred := regexp.MustCompile(`WriteHeader\(\s*500\s*\)|http\.Error\([^)]*,\s*500\s*\)`)

	var offenders []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if directFiveHundred.MatchString(line) || numericFiveHundred.MatchString(line) {
				offenders = append(offenders, filepath.ToSlash(path)+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) != 0 {
		t.Fatalf("a 500 is produced WITHOUT going through apierr.Write, so its cause is discarded unlogged "+
			"(S11-5). Route it through apierr.Write(w, r, err):\n  %s", strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
