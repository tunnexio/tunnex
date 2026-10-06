// Package rdpwire bounds the browser desktop protocol and excludes device redirection.
package rdpwire

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Credentials struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

func Encode(parts ...string) []byte {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d.%s", utf8.RuneCountInString(p), p)
	}
	b.WriteByte(';')
	return []byte(b.String())
}
func Read(r *bufio.Reader) ([]string, error) {
	out := []string{}
	total := 0
	for {
		digits := ""
		for {
			c, e := r.ReadByte()
			if e != nil {
				return nil, e
			}
			if c == '.' {
				break
			}
			if c < '0' || c > '9' || len(digits) >= 7 {
				return nil, errors.New("invalid instruction length")
			}
			digits += string(c)
		}
		n, e := strconv.Atoi(digits)
		if e != nil || n < 0 || n > 65536 || total+n > 65536 || len(out) >= 128 {
			return nil, errors.New("oversized instruction")
		}
		var b strings.Builder
		for i := 0; i < n; i++ {
			c, _, e := r.ReadRune()
			if e != nil {
				return nil, e
			}
			b.WriteRune(c)
		}
		out = append(out, b.String())
		total += n
		c, e := r.ReadByte()
		if e != nil {
			return nil, e
		}
		if c == ';' {
			return out, nil
		}
		if c != ',' {
			return nil, errors.New("invalid instruction delimiter")
		}
	}
}
func ValidateInput(data []byte) error {
	r := bufio.NewReader(bytes.NewReader(data))
	count := 0
	for r.Buffered() > 0 || count == 0 {
		p, e := Read(r)
		if e != nil {
			return e
		}
		count++
		if count > 100 {
			return errors.New("too many instructions")
		}
		want := map[string]int{"sync": 1, "key": 2, "mouse": 3, "size": 2, "nop": 0, "disconnect": 0, "ack": 3}
		n, ok := want[p[0]]
		if !ok || len(p) != n+1 {
			return errors.New("unsupported desktop instruction")
		}
		for i, a := range p[1:] {
			if p[0] == "ack" && i == 1 {
				if utf8.RuneCountInString(a) > 128 || strings.IndexFunc(a, unicode.IsControl) >= 0 {
					return errors.New("invalid acknowledgement message")
				}
				continue
			}
			maximum := int64(1 << 32)
			if p[0] == "sync" {
				maximum = 1<<53 - 1
			}
			if p[0] == "ack" {
				maximum = 65535
			}
			v, e := strconv.ParseInt(a, 10, 64)
			if e != nil || v < 0 || v > maximum {
				return errors.New("invalid desktop input")
			}
		}
		if p[0] == "size" {
			w, _ := strconv.Atoi(p[1])
			h, _ := strconv.Atoi(p[2])
			if w < 1 || h < 1 || w > 4096 || h > 4096 {
				return errors.New("invalid desktop dimensions")
			}
		}
		if p[0] == "key" && p[2] != "0" && p[2] != "1" {
			return errors.New("invalid key state")
		}
		if p[0] == "mouse" {
			mask, _ := strconv.Atoi(p[3])
			if mask > 31 {
				return errors.New("invalid mouse buttons")
			}
		}
		_, e = r.Peek(1)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
	}
	return nil
}

// HasUserInput excludes periodic sync acknowledgements from the idle deadline.
func HasUserInput(data []byte) bool {
	r := bufio.NewReader(bytes.NewReader(data))
	for {
		p, e := Read(r)
		if e != nil {
			return false
		}
		if p[0] == "key" || p[0] == "mouse" {
			return true
		}
		if _, e = r.Peek(1); e != nil {
			return false
		}
	}
}
