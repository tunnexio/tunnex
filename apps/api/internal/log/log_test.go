package log

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestSafeTextBoundsAndRemovesDisplayControls(t *testing.T) {
	for _, input := range []string{"ok\r\nforged\tentry\x1b[0m", "a\u2028b\u2029c\u202ed", strings.Repeat("界", 3000), string([]byte{0xff, '\n'})} {
		got := SafeText(input)
		if len(got) > 2048 || !utf8.ValidString(got) {
			t.Fatalf("invalid bounded UTF-8 log value: %d bytes", len(got))
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
				t.Fatalf("display control survived: %q", got)
			}
		}
	}
	if got := SafeText("GET /sites?name=Mumbai"); got != "GET /sites?name=Mumbai" {
		t.Fatalf("ordinary diagnostic changed: %q", got)
	}
}
