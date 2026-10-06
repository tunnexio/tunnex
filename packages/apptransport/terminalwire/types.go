// Package terminalwire defines purpose-specific browser SSH messages. App Access
// channels and arbitrary exec/subsystem/forwarding requests are never accepted.
package terminalwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const Purpose = "server_access_terminal_v1"
const MaxFrameBytes = 65536
const MaxDataBytes = 16384

type Frame struct {
	Type   string `json:"type"`
	Data   []byte `json:"data,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (f Frame) ValidateInput() error {
	if f.Reason != "" {
		return errors.New("invalid input fields")
	}
	switch f.Type {
	case "input":
		if len(f.Data) == 0 || len(f.Data) > MaxDataBytes || f.Rows != 0 || f.Cols != 0 {
			return errors.New("invalid input size")
		}
	case "resize":
		if len(f.Data) != 0 || f.Rows < 1 || f.Rows > 400 || f.Cols < 1 || f.Cols > 400 {
			return errors.New("invalid resize")
		}
	default:
		return errors.New("unsupported terminal message")
	}
	return nil
}
func Read(r *bufio.Reader) (Frame, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return Frame{}, err
	}
	if len(line) > MaxFrameBytes {
		return Frame{}, errors.New("oversized terminal frame")
	}
	var f Frame
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&f); err != nil {
		return Frame{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Frame{}, errors.New("trailing terminal message")
	}
	return f, nil
}
func Write(w io.Writer, f Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxFrameBytes {
		return errors.New("oversized terminal frame")
	}
	b = append(b, '\n')
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type Assignment struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}
type Material struct {
	EditorHostKey   []byte    `json:"editor_host_key,omitempty"`
	EditorClientKey string    `json:"editor_client_key,omitempty"`
	ClipboardPolicy string    `json:"clipboard_policy,omitempty"`
	OS              string    `json:"os,omitempty"`
	Domain          string    `json:"domain,omitempty"`
	SessionID       string    `json:"session_id"`
	IP              string    `json:"ip"`
	Port            int       `json:"port"`
	Account         string    `json:"account"`
	Fingerprint     string    `json:"fingerprint"`
	Certificate     string    `json:"certificate"`
	ExpiresAt       time.Time `json:"expires_at"`
	LeaseUntil      time.Time `json:"lease_until"`
	Kind            string    `json:"kind"`
}
type Lease struct {
	Until time.Time `json:"until"`
}

// ResultReason bounds redacted gateway outcomes; never transport raw SSH errors.
func ResultReason(result string) (string, bool) {
	switch result {
	case "ok":
		return "", true
	case "failed":
		return "ssh_connection_failed", true
	case "ssh_host_key_mismatch", "ssh_unreachable", "ssh_authentication_failed", "ssh_pty_failed":
		return result, true
	}
	return "", false
}
