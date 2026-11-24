package serveraccess

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// Every refusal the UI can show must read as a sentence, not "Terminal access is unavailable: <code>".
func TestEveryDenyReasonHasAPlainSentence(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`deny\("([a-z_]+)"\)`)
	seen := map[string]bool{}
	envName := regexp.MustCompile(`TUNNEX_[A-Z_]+`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) < 40 {
		t.Fatalf("found only %d deny reasons; the scan is broken", len(seen))
	}
	for reason := range seen {
		var e *apierr.Error
		if !errors.As(deny(reason), &e) {
			t.Fatalf("%s: not an apierr", reason)
		}
		if e.Code != reason {
			t.Errorf("%s: code changed to %q (clients match on it)", reason, e.Code)
		}
		// Environment variable names are allowed; snake_case codes are not.
		if strings.Contains(envName.ReplaceAllString(e.Message, ""), "_") || !strings.HasSuffix(e.Message, ".") || strings.Contains(e.Message, "Terminal access is unavailable: ") {
			t.Errorf("%s: message is not a plain sentence: %q", reason, e.Message)
		}
	}
}

func TestLockedGatewayRefusalNamesTheOperatorSetting(t *testing.T) {
	var e *apierr.Error
	errors.As(deny("gateway_terminal_unavailable"), &e)
	for _, want := range []string{"gateway", "TUNNEX_SERVER_ACCESS_ENABLED=false", "TUNNEX_GATEWAY_SERVER_ACCESS_ENABLED=false"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("gateway_terminal_unavailable message %q lacks %q", e.Message, want)
		}
	}
}
