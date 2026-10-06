package rdpwire

import (
	"bufio"
	"bytes"
	"testing"
)

func TestDesktopInputBoundary(t *testing.T) {
	for _, p := range [][]string{{"key", "65", "1"}, {"mouse", "20", "30", "1"}, {"size", "1280", "720"}, {"sync", "123"}} {
		if e := ValidateInput(Encode(p...)); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range [][]string{{"connect", "10.0.0.2"}, {"clipboard", "x"}, {"file", "x"}, {"key", "65", "2"}, {"size", "100000", "720"}, {"mouse", "0", "0", "32"}} {
		if ValidateInput(Encode(p...)) == nil {
			t.Fatalf("accepted %v", p)
		}
	}
	if ValidateInput([]byte("99.key;")) == nil {
		t.Fatal("accepted truncated frame")
	}
}
func TestUnicodeCredentialEncoding(t *testing.T) {
	b := Encode("connect", "päss秘密")
	p, e := Read(bufio.NewReader(bytes.NewReader(b)))
	if e != nil || len(p) != 2 || p[1] != "päss秘密" {
		t.Fatalf("roundtrip: %v %v", p, e)
	}
}

func TestSyncDoesNotExtendIdleDeadline(t *testing.T) {
	if HasUserInput(Encode("sync", "123")) {
		t.Fatal("sync treated as user activity")
	}
	if !HasUserInput(Encode("mouse", "10", "20", "0")) {
		t.Fatal("mouse activity ignored")
	}
}

func TestDesktopRenderingAcknowledgements(t *testing.T) {
	for _, parts := range [][]string{{"sync", "1791256317000"}, {"ack", "0", "OK", "0"}, {"ack", "12", "BAD TYPE", "783"}} {
		if err := ValidateInput(Encode(parts...)); err != nil {
			t.Fatalf("render acknowledgement rejected: %v", err)
		}
		if HasUserInput(Encode(parts...)) {
			t.Fatal("render acknowledgement extended idle deadline")
		}
	}
	for _, parts := range [][]string{{"sync", "9007199254740992"}, {"ack", "65536", "OK", "0"}, {"ack", "0", "bad\nmessage", "0"}, {"ack", "0", "OK", "65536"}, {"blob", "0", "data"}, {"file", "0", "text/plain", "file"}} {
		if ValidateInput(Encode(parts...)) == nil {
			t.Fatalf("unsafe frame accepted: %s", parts[0])
		}
	}
}
