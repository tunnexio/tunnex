package beam

import (
	"encoding/binary"
	"io"
)

// copyFrames validates a constant 14-byte header and streams payload unchanged.
// Compression is not negotiated; neither a frame nor a message is buffered.
func copyFrames(dst io.Writer, src io.Reader, masked bool) (int64, error) {
	var header [14]byte
	var total int64
	var message uint64
	fragments := 0
	fragmented := false
	for {
		_, e := io.ReadFull(src, header[:2])
		if e == io.EOF {
			if fragmented {
				return total, errRefused
			}
			return total, nil
		}
		if e != nil {
			return total, e
		}
		fin := header[0]&0x80 != 0
		opcode := header[0] & 15
		if header[0]&0x70 != 0 || (header[1]&0x80 != 0) != masked {
			return total, errRefused
		}
		size := uint64(header[1] & 127)
		n := 2
		switch size {
		case 126:
			if _, e = io.ReadFull(src, header[2:4]); e != nil {
				return total, e
			}
			size = uint64(binary.BigEndian.Uint16(header[2:4]))
			n = 4
			if size < 126 {
				return total, errRefused
			}
		case 127:
			if _, e = io.ReadFull(src, header[2:10]); e != nil {
				return total, e
			}
			size = binary.BigEndian.Uint64(header[2:10])
			n = 10
			if size < 65536 || size>>63 != 0 {
				return total, errRefused
			}
		}
		if size > 1<<20 {
			return total, errRefused
		}
		switch opcode {
		case 0:
			if !fragmented {
				return total, errRefused
			}
			message += size
			fragments++
			if fin {
				fragmented = false
			}
		case 1, 2:
			if fragmented {
				return total, errRefused
			}
			message = size
			fragments = 1
			fragmented = !fin
		case 8, 9, 10:
			if !fin || size > 125 || (opcode == 8 && size == 1) {
				return total, errRefused
			}
		default:
			return total, errRefused
		}
		if message > maxBody || fragments > 1024 {
			return total, errRefused
		}
		if masked {
			if _, e = io.ReadFull(src, header[n:n+4]); e != nil {
				return total, e
			}
			n += 4
		}
		written, e := dst.Write(header[:n])
		total += int64(written)
		if e != nil {
			return total, e
		}
		if written != n {
			return total, io.ErrShortWrite
		}
		copied, e := io.CopyN(dst, src, int64(size))
		total += copied
		if e != nil {
			return total, e
		}
	}
}
