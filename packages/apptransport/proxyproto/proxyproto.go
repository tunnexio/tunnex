// Package proxyproto writes and strictly reads PROXY protocol v2 headers for
// the Tunnex single-IP edge (LS-UX-1 E.1). The edge prepends the real client
// address to spliced TCP streams. A receiver trusts a header only when it
// carries the installation's pre-shared edge token; a stream that starts with
// the PROXY signature but fails any check is closed (fail closed). Streams
// without the signature are served unchanged, so direct callers keep working
// and can never claim another address.
package proxyproto

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Signature is the fixed 12-byte PROXY v2 preamble.
var Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// TokenTLV is the custom TLV type (PP2_TYPE_MIN_CUSTOM) carrying the edge token.
const TokenTLV = 0xE0

// MaxHeader bounds the header a receiver will read.
const MaxHeader = 512

var ErrInvalid = errors.New("invalid PROXY header")

// Header encodes a v2 PROXY header for a TCP stream from src to dst. A
// non-empty token is appended as the edge-token TLV.
func Header(src, dst *net.TCPAddr, token []byte) ([]byte, error) {
	if src == nil || dst == nil || len(token) > 255 {
		return nil, ErrInvalid
	}
	var fam byte
	var addrs []byte
	s4, d4 := src.IP.To4(), dst.IP.To4()
	switch {
	case s4 != nil && d4 != nil:
		fam = 0x11
		addrs = append(append(addrs, s4...), d4...)
	case s4 == nil && d4 == nil && src.IP.To16() != nil && dst.IP.To16() != nil:
		fam = 0x21
		addrs = append(append(addrs, src.IP.To16()...), dst.IP.To16()...)
	default:
		// Mixed families: express both as IPv6 (IPv4-mapped).
		fam = 0x21
		addrs = append(append(addrs, src.IP.To16()...), dst.IP.To16()...)
	}
	if src.Port < 0 || src.Port > 65535 || dst.Port < 0 || dst.Port > 65535 {
		return nil, ErrInvalid
	}
	addrs = binary.BigEndian.AppendUint16(addrs, uint16(src.Port))
	addrs = binary.BigEndian.AppendUint16(addrs, uint16(dst.Port))
	if len(token) > 0 {
		addrs = append(addrs, TokenTLV)
		addrs = binary.BigEndian.AppendUint16(addrs, uint16(len(token)))
		addrs = append(addrs, token...)
	}
	out := append([]byte{}, Signature...)
	out = append(out, 0x21, fam)
	out = binary.BigEndian.AppendUint16(out, uint16(len(addrs)))
	return append(out, addrs...), nil
}

// Read parses one header from r and returns the client address. The token
// TLV must be present and equal to token (constant time).
func Read(r io.Reader, token []byte) (*net.TCPAddr, error) {
	if len(token) == 0 {
		return nil, ErrInvalid
	}
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(r, fixed); err != nil || !bytes.Equal(fixed[:12], Signature) || fixed[12] != 0x21 {
		return nil, ErrInvalid
	}
	n := int(binary.BigEndian.Uint16(fixed[14:16]))
	if n > MaxHeader-16 {
		return nil, ErrInvalid
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrInvalid
	}
	var size int
	switch fixed[13] {
	case 0x11:
		size = 4
	case 0x21:
		size = 16
	default:
		return nil, ErrInvalid
	}
	if len(body) < 2*size+4 {
		return nil, ErrInvalid
	}
	src := &net.TCPAddr{IP: net.IP(append([]byte{}, body[:size]...)), Port: int(binary.BigEndian.Uint16(body[2*size : 2*size+2]))}
	tlvs := body[2*size+4:]
	found := false
	for len(tlvs) > 0 {
		if len(tlvs) < 3 {
			return nil, ErrInvalid
		}
		kind, length := tlvs[0], int(binary.BigEndian.Uint16(tlvs[1:3]))
		if len(tlvs) < 3+length {
			return nil, ErrInvalid
		}
		if kind == TokenTLV {
			if found || subtle.ConstantTimeCompare(tlvs[3:3+length], token) != 1 {
				return nil, ErrInvalid
			}
			found = true
		}
		tlvs = tlvs[3+length:]
	}
	if !found {
		return nil, ErrInvalid
	}
	return src, nil
}

type conn struct {
	net.Conn
	reader io.Reader
	remote net.Addr
}

func (c *conn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *conn) RemoteAddr() net.Addr       { return c.remote }

// Listener accepts edge streams (with a valid header) and direct streams
// (without the signature). Header reads happen off the Accept path, bounded
// by Timeout and by a fixed number of concurrent handshakes.
type Listener struct {
	net.Listener
	token   []byte
	timeout time.Duration
	ready   chan net.Conn
	errs    chan error
	slots   chan struct{}
	once    sync.Once
	done    chan struct{}
}

// NewListener wraps l. token must be non-empty.
func NewListener(l net.Listener, token []byte, timeout time.Duration) (*Listener, error) {
	if len(token) < 16 || len(token) > 255 {
		return nil, errors.New("edge token must be 16 to 255 bytes")
	}
	x := &Listener{Listener: l, token: append([]byte{}, token...), timeout: timeout, ready: make(chan net.Conn), errs: make(chan error, 1), slots: make(chan struct{}, 64), done: make(chan struct{})}
	go x.loop()
	return x, nil
}

func (l *Listener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errs <- err:
			case <-l.done:
			}
			return
		}
		select {
		case l.slots <- struct{}{}:
		case <-l.done:
			c.Close()
			return
		}
		go func() {
			defer func() { <-l.slots }()
			wrapped, err := l.handshake(c)
			if err != nil {
				c.Close()
				return
			}
			select {
			case l.ready <- wrapped:
			case <-l.done:
				wrapped.Close()
			}
		}()
	}
}

func (l *Listener) handshake(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(l.timeout))
	defer c.SetReadDeadline(time.Time{})
	reader := bufio.NewReaderSize(c, MaxHeader)
	peek, err := reader.Peek(len(Signature))
	if err != nil {
		// Short streams cannot carry a header; let TLS decide on them.
		if len(peek) > 0 && bytes.HasPrefix(Signature, peek) {
			return nil, ErrInvalid
		}
		return &conn{Conn: c, reader: reader, remote: c.RemoteAddr()}, nil
	}
	if !bytes.Equal(peek, Signature) {
		return &conn{Conn: c, reader: reader, remote: c.RemoteAddr()}, nil
	}
	src, err := Read(reader, l.token)
	if err != nil {
		return nil, err
	}
	return &conn{Conn: c, reader: reader, remote: src}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// LoadToken reads a private edge-token file holding 64 hex characters.
func LoadToken(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("edge token must be a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read edge token")
	}
	token, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(token) != 32 {
		return nil, errors.New("edge token must be 64 hex characters")
	}
	return token, nil
}
