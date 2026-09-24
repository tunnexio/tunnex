package ipsec

// This limited implementation follows strongSwan's documented VICI protocol.
// It is independent of libvici/govici and performs no cryptographic operations.
import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"time"
)

var ErrDaemonProtocol = errors.New("IPsec daemon operation failed")

const (
	viciFrameLimit     = 512 * 1024
	viciAggregateLimit = 4 * 1024 * 1024
	viciElementLimit   = 4096
	viciDepthLimit     = 16
	viciEventLimit     = 1024
)

type viciValue struct {
	kind    byte
	scalar  []byte
	list    [][]byte
	section viciMessage
}
type viciMessage map[string]viciValue

func viciScalar(value []byte) viciValue       { return viciValue{kind: 3, scalar: value} }
func viciText(value string) viciValue         { return viciScalar([]byte(value)) }
func viciSection(value viciMessage) viciValue { return viciValue{kind: 1, section: value} }
func viciList(values ...string) viciValue {
	out := viciValue{kind: 4, list: make([][]byte, 0, len(values))}
	for _, v := range values {
		out.list = append(out.list, []byte(v))
	}
	return out
}
func validVICIName(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, v := range []byte(value) {
		if v < 32 || v > 126 {
			return false
		}
	}
	return true
}
func encodeVICI(message viciMessage) ([]byte, error) {
	result := make([]byte, 0, 256)
	elements := 0
	add := func(data ...byte) bool {
		if len(data) > viciFrameLimit-len(result) {
			return false
		}
		result = append(result, data...)
		return true
	}
	name := func(value string) bool { return validVICIName(value) && add(byte(len(value))) && add([]byte(value)...) }
	value := func(raw []byte) bool {
		return len(raw) <= 65535 && add(byte(len(raw)>>8), byte(len(raw))) && add(raw...)
	}
	var encode func(viciMessage, int) bool
	encode = func(m viciMessage, depth int) bool {
		if depth > viciDepthLimit {
			return false
		}
		keys := make([]string, 0, len(m))
		if len(m) > viciElementLimit {
			return false
		}
		for key := range m {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			elements++
			if elements > viciElementLimit {
				return false
			}
			v := m[key]
			if !add(v.kind) || !name(key) {
				return false
			}
			switch v.kind {
			case 3:
				if !value(v.scalar) {
					return false
				}
			case 1:
				if !encode(v.section, depth+1) || !add(2) {
					return false
				}
			case 4:
				if len(v.list) > viciElementLimit-elements {
					return false
				}
				for _, item := range v.list {
					elements++
					if !add(5) || !value(item) {
						return false
					}
				}
				if !add(6) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !encode(message, 0) {
		clear(result)
		return nil, ErrDaemonProtocol
	}
	return result, nil
}
func decodeVICI(raw []byte) (viciMessage, error) {
	if len(raw) > viciFrameLimit {
		return nil, ErrDaemonProtocol
	}
	pos, count := 0, 0
	name := func() (string, bool) {
		if pos >= len(raw) {
			return "", false
		}
		n := int(raw[pos])
		pos++
		if n > len(raw)-pos {
			return "", false
		}
		v := string(raw[pos : pos+n])
		pos += n
		return v, validVICIName(v)
	}
	value := func() ([]byte, bool) {
		if len(raw)-pos < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		if n > len(raw)-pos {
			return nil, false
		}
		v := append([]byte{}, raw[pos:pos+n]...)
		pos += n
		return v, true
	}
	var decode func(int, bool) (viciMessage, bool)
	decode = func(depth int, nested bool) (viciMessage, bool) {
		if depth > viciDepthLimit {
			return nil, false
		}
		m := viciMessage{}
		for pos < len(raw) {
			kind := raw[pos]
			pos++
			if kind == 2 {
				return m, nested
			}
			count++
			if count > viciElementLimit {
				return nil, false
			}
			if kind != 1 && kind != 3 && kind != 4 {
				return nil, false
			}
			key, ok := name()
			if !ok {
				return nil, false
			}
			if _, exists := m[key]; exists {
				return nil, false
			}
			switch kind {
			case 1:
				section, ok := decode(depth+1, true)
				if !ok {
					return nil, false
				}
				m[key] = viciSection(section)
			case 3:
				scalar, ok := value()
				if !ok {
					return nil, false
				}
				m[key] = viciScalar(scalar)
			case 4:
				list := viciValue{kind: 4, list: [][]byte{}}
				closed := false
				for pos < len(raw) {
					item := raw[pos]
					pos++
					if item == 6 {
						closed = true
						break
					}
					count++
					if item != 5 || count > viciElementLimit {
						return nil, false
					}
					v, ok := value()
					if !ok {
						return nil, false
					}
					list.list = append(list.list, v)
				}
				if !closed {
					return nil, false
				}
				m[key] = list
			}
		}
		return m, !nested
	}
	out, ok := decode(0, false)
	if !ok || pos != len(raw) {
		return nil, ErrDaemonProtocol
	}
	return out, nil
}
func readVICIPacket(reader io.Reader) ([]byte, error) {
	return readVICIPacketBound(reader, viciFrameLimit)
}
func readVICIPacketBound(reader io.Reader, remaining int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrDaemonProtocol
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > viciFrameLimit || uint64(size) > uint64(max(remaining, 0)) {
		return nil, ErrDaemonProtocol
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		clear(data)
		return nil, ErrDaemonProtocol
	}
	return data, nil
}
func writeVICIPacket(writer io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > viciFrameLimit {
		return ErrDaemonProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil || n <= 0 || n > len(part) {
				return ErrDaemonProtocol
			}
			part = part[n:]
		}
	}
	return nil
}
func viciNamedPacket(kind byte, name string, body []byte) ([]byte, error) {
	if !validVICIName(name) || len(body) > viciFrameLimit-2-len(name) {
		return nil, ErrDaemonProtocol
	}
	out := make([]byte, 0, 2+len(name)+len(body))
	out = append(out, kind, byte(len(name)))
	out = append(out, []byte(name)...)
	return append(out, body...), nil
}

type viciTransport struct {
	dial func(context.Context) (net.Conn, error)
}

// A connection carries one bounded command only. Closing it also unregisters the
// event stream, and prevents response ambiguity or cancellation from leaking into
// a later command. No diagnostic/control-log event subscription is supported.
func (transport viciTransport) call(ctx context.Context, command, event string, message viciMessage) (viciMessage, []viciMessage, error) {
	if ctx == nil || ctx.Err() != nil || transport.dial == nil {
		return nil, nil, ErrDaemonProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := encodeVICI(message)
	if err != nil {
		return nil, nil, ErrDaemonProtocol
	}
	defer clear(body)
	packet, err := viciNamedPacket(0, command, body)
	if err != nil {
		return nil, nil, ErrDaemonProtocol
	}
	defer clear(packet)
	conn, err := transport.dial(ctx)
	if err != nil {
		return nil, nil, ErrDaemonProtocol
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return nil, nil, ErrDaemonProtocol
	}
	total := 0
	read := func() ([]byte, error) {
		p, e := readVICIPacketBound(conn, viciAggregateLimit-total)
		if e != nil {
			return nil, ErrDaemonProtocol
		}
		total += len(p)
		if total > viciAggregateLimit {
			clear(p)
			return nil, ErrDaemonProtocol
		}
		return p, nil
	}
	if event != "" {
		register, e := viciNamedPacket(3, event, nil)
		if e != nil || writeVICIPacket(conn, register) != nil {
			return nil, nil, ErrDaemonProtocol
		}
		response, e := read()
		if e != nil || len(response) != 1 || response[0] != 5 {
			return nil, nil, ErrDaemonProtocol
		}
	}
	if writeVICIPacket(conn, packet) != nil {
		return nil, nil, ErrDaemonProtocol
	}
	events := []viciMessage{}
	for {
		p, e := read()
		if e != nil {
			return nil, nil, ErrDaemonProtocol
		}
		switch p[0] {
		case 1:
			response, e := decodeVICI(p[1:])
			clear(p)
			if e != nil || ctx.Err() != nil {
				return nil, nil, ErrDaemonProtocol
			}
			return response, events, nil
		case 7:
			if event == "" || len(p) < 2 || int(p[1]) > len(p)-2 || string(p[2:2+int(p[1])]) != event || len(events) >= viciEventLimit {
				return nil, nil, ErrDaemonProtocol
			}
			decoded, e := decodeVICI(p[2+int(p[1]):])
			clear(p)
			if e != nil {
				return nil, nil, ErrDaemonProtocol
			}
			events = append(events, decoded)
		default:
			clear(p)
			return nil, nil, ErrDaemonProtocol
		}
	}
}
