package terminalwire

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

type fragmentWriter struct{ bytes.Buffer }

func (w *fragmentWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}
func TestFramesEnforceTerminalOnly(t *testing.T) {
	cases := []Frame{{Type: "exec", Data: []byte("id")}, {Type: "input", Data: []byte("a"), Rows: 1}, {Type: "input", Data: bytes.Repeat([]byte("a"), MaxDataBytes+1)}, {Type: "resize", Rows: 401, Cols: 80}, {Type: "resize", Rows: 24, Cols: 80, Reason: "bypass"}, {Type: "forward"}, {Type: "resize", Rows: 24, Cols: 80, Data: []byte("a")}}
	for _, f := range cases {
		if f.ValidateInput() == nil {
			t.Fatalf("accepted invalid frame %+v", f)
		}
	}
	for _, f := range []Frame{{Type: "input", Data: []byte("héllo")}, {Type: "resize", Rows: 40, Cols: 120}} {
		if e := f.ValidateInput(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestStrictWireAndFragmentedWriter(t *testing.T) {
	for _, raw := range []string{`{"type":"resize","rows":24,"cols":80,"exec":"id"}` + "\n", `{"type":"input","data":"YQ=="} {}` + "\n", strings.Repeat("x", MaxFrameBytes) + "\n"} {
		if _, e := Read(bufio.NewReaderSize(strings.NewReader(raw), MaxFrameBytes)); e == nil {
			t.Fatal("accepted malformed or oversized frame")
		}
	}
	w := &fragmentWriter{}
	f := Frame{Type: "output", Data: []byte("héllo")}
	if e := Write(w, f); e != nil {
		t.Fatal(e)
	}
	got, e := Read(bufio.NewReader(&w.Buffer))
	if e != nil || string(got.Data) != "héllo" {
		t.Fatalf("fragmented roundtrip: %v %+v", e, got)
	}
	if e := Write(zeroWriter{}, f); e != io.ErrShortWrite {
		t.Fatalf("zero progress writer: %v", e)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
