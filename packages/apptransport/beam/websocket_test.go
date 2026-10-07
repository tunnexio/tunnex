package beam

import (
	"bytes"
	"io"
	"testing"
)

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

type countedReader struct {
	io.Reader
	n int
}

func (r *countedReader) Read(p []byte) (int, error) { n, e := r.Reader.Read(p); r.n += n; return n, e }
func TestFrameValidationStreamingChunkBoundariesAndInterleavedControl(t *testing.T) {
	for _, masked := range []bool{true, false} {
		normal := bytes.Join([][]byte{frame(false, 1, 126, masked), frame(true, 9, 3, masked), frame(true, 0, 128, masked), frame(true, 2, 65536, masked), frame(true, 10, 125, masked)}, nil)
		var out bytes.Buffer
		if _, e := copyFrames(&out, byteReader{bytes.NewReader(normal)}, masked); e != nil || !bytes.Equal(normal, out.Bytes()) {
			t.Fatal("one-byte boundaries changed data", masked, e)
		}
	}
}
func TestFrameValidationRejectsHeadersBeforePayloadAndFragmentBounds(t *testing.T) {
	cases := [][]byte{{0x81, 127, 0, 0, 0, 0, 0, 0x10, 0, 1}, {0x81, 126, 0, 1}, {0x81, 127, 0, 0, 0, 0, 0, 0, 0, 126}, {0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, {0x89, 126, 0, 126}, {0x08, 0}, {0x88, 1}, {0x83, 0}, {0xc1, 0}, {0x80, 0}, {0x81, 0x80, 0, 0, 0, 0}}
	for _, header := range cases {
		reader := &countedReader{Reader: io.MultiReader(bytes.NewReader(header), io.LimitReader(zeroReader{}, 100<<20))}
		if _, e := copyFrames(io.Discard, reader, false); e == nil {
			t.Fatal("invalid header accepted", header)
		}
		if reader.n > 14 {
			t.Fatal("invalid frame payload was read", reader.n)
		}
	}
	readers := []io.Reader{bytes.NewReader(frame(false, 2, 1<<20, false))}
	for i := 0; i < 16; i++ {
		readers = append(readers, bytes.NewReader(frame(false, 0, 1<<20, false)))
	}
	if _, e := copyFrames(io.Discard, io.MultiReader(readers...), false); e == nil {
		t.Fatal("fragmented message over 16MiB accepted")
	}
	var fragments bytes.Buffer
	fragments.Write(frame(false, 1, 0, false))
	for i := 0; i < 1024; i++ {
		fragments.Write(frame(false, 0, 0, false))
	}
	if _, e := copyFrames(io.Discard, &fragments, false); e == nil {
		t.Fatal("unbounded fragment count accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
