package apierr

import (
	"strings"
	"testing"
)

func TestSafeLogTextIsBoundedAndSingleLine(t *testing.T) {
	got := safeLogText("first\r\nsecond\tthird")
	if strings.ContainsAny(got, "\r\n\t") || got != "first  second third" {
		t.Fatalf("safeLogText=%q", got)
	}
	if got := safeLogText(strings.Repeat("x", 4096)); len(got) > 2048 {
		t.Fatalf("safeLogText length=%d", len(got))
	}
}
