package rdpwire

import (
	"bytes"
	"strings"
	"testing"
)

func TestClipboardDirectionAndBounds(t *testing.T) {
	for _, p := range []string{"", "off", "copy", "unknown"} {
		if _, err := EncodeClipboardPaste(p, []byte("hello")); err == nil {
			t.Fatalf("paste accepted for %q", p)
		}
	}
	for _, p := range []string{"paste", "both"} {
		out, err := EncodeClipboardPaste(p, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out, []byte("10.text/plain")) || !bytes.Contains(out, []byte("aGVsbG8=")) {
			t.Fatalf("invalid text stream: %s", out)
		}
	}
	for _, text := range [][]byte{nil, []byte(strings.Repeat("x", 8193)), {0}, {0xff}, []byte(strings.Repeat("界", 2731))} {
		if err := ValidateClipboardPaste("both", text); err == nil {
			t.Fatal("invalid text accepted")
		}
	}
	if err := ValidateClipboardPaste("both", []byte(strings.Repeat("x", 8192))); err != nil {
		t.Fatal(err)
	}
	if CanCopy("paste") || CanPaste("copy") || CanCopy("unknown") {
		t.Fatal("direction policy bypass")
	}
	if err := ValidateInput(Encode("clipboard", "0", "text/plain")); err == nil {
		t.Fatal("generic desktop input opened clipboard stream")
	}
	if err := ValidateInput(Encode("blob", "0", "aGVsbG8=")); err == nil {
		t.Fatal("generic desktop input injected blob")
	}
}
