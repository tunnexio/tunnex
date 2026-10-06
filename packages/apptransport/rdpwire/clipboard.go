package rdpwire

import (
	"bytes"
	"encoding/base64"
	"errors"
	"unicode/utf8"
)

// Clipboard is text-only and bounded. Unknown policies fail closed.
const MaxClipboardBytes = 8192

func ValidClipboardPolicy(p string) bool {
	return p == "off" || p == "paste" || p == "copy" || p == "both"
}
func CanPaste(p string) bool { return p == "paste" || p == "both" }
func CanCopy(p string) bool  { return p == "copy" || p == "both" }
func ValidateClipboardPaste(policy string, text []byte) error {
	if !CanPaste(policy) || len(text) == 0 || len(text) > MaxClipboardBytes || !utf8.Valid(text) || bytes.IndexByte(text, 0) >= 0 {
		return errors.New("clipboard paste denied")
	}
	return nil
}

// Only a dedicated text frame may open a clipboard stream. Generic browser
// desktop input cannot create streams, inject blobs, or transfer files.
func EncodeClipboardPaste(policy string, text []byte) ([]byte, error) {
	if e := ValidateClipboardPaste(policy, text); e != nil {
		return nil, e
	}
	out := Encode("clipboard", "0", "text/plain")
	for len(text) > 0 {
		n := min(4096, len(text))
		out = append(out, Encode("blob", "0", base64.StdEncoding.EncodeToString(text[:n]))...)
		text = text[n:]
	}
	return append(out, Encode("end", "0")...), nil
}
