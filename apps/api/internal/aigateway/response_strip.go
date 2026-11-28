package aigateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// engineMetadataField is the private engine's per-response diagnostics object
// (internal key names, routing, provider response headers, latency). It is
// never part of the public OpenAI/Anthropic response contract.
const engineMetadataField = "extra_fields"

// stripEngineMetadata removes every top-level engineMetadataField member from a
// JSON object by cutting it out of the original bytes. Nothing is re-encoded:
// field order, numbers and whitespace are unchanged, and input without the
// member (or that is not a JSON object) is returned as is. The error is
// reserved for a splice that would not be valid JSON; callers fail closed.
func stripEngineMetadata(data []byte) ([]byte, error) {
	// A key spelled with \u escapes decodes to the same name, so only skip
	// parsing when neither the plain name nor an escape can be present.
	if !bytes.Contains(data, []byte(engineMetadataField)) && !bytes.Contains(data, []byte(`\u`)) {
		return data, nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return data, nil
	}
	type member struct {
		start, end int64 // [start,end) holds the separating comma (if any), key and value
		drop       bool
	}
	open := d.InputOffset()
	prevEnd := open
	var members []member
	dropped := false
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return data, nil
		}
		key, ok := t.(string)
		if !ok {
			return data, nil
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return data, nil
		}
		end := d.InputOffset()
		members = append(members, member{prevEnd, end, key == engineMetadataField})
		dropped = dropped || key == engineMetadataField
		prevEnd = end
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return data, nil
	}
	if _, err := d.Token(); err != io.EOF {
		return data, nil
	}
	if !dropped {
		return data, nil
	}
	out := make([]byte, 0, len(data))
	out = append(out, data[:open]...)
	kept := 0
	for i, m := range members {
		if m.drop {
			continue
		}
		segment := data[m.start:m.end]
		if kept == 0 && i > 0 {
			// The first kept member followed a removed one: drop its comma.
			j := 0
			for j < len(segment) && isJSONSpace(segment[j]) {
				j++
			}
			if j < len(segment) && segment[j] == ',' {
				segment = segment[j+1:]
			}
		}
		out = append(out, segment...)
		kept++
	}
	out = append(out, data[prevEnd:]...)
	if !json.Valid(out) {
		return nil, errInvalidStrip
	}
	return out, nil
}

var errInvalidStrip = errors.New("engine metadata removal failed")

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// copySSEStripped relays an event stream one SSE event at a time, removing
// engine metadata from each event's JSON data. A complete event (terminated by
// a blank line) is written and flushed immediately; only the event in progress
// is held. Every upstream byte counts toward limit, so one event can never hold
// more than the response cap. It returns errResponseTooLarge on overflow,
// errInvalidStrip if metadata could not be removed safely, and otherwise the
// first write/flush error or nil at the end of the stream.
func copySSEStripped(dst io.Writer, flush func() error, src io.Reader, limit int64) error {
	br := bufio.NewReaderSize(src, 8<<10)
	var event [][]byte
	var read int64
	emit := func() error {
		if len(event) == 0 {
			return nil
		}
		out, err := stripSSEEvent(event)
		event = event[:0]
		if err != nil {
			return err
		}
		if _, err := dst.Write(out); err != nil {
			return err
		}
		return flush()
	}
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		read += int64(len(chunk))
		if read > limit {
			return errResponseTooLarge
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 {
			complete := line[len(line)-1] == '\n'
			event = append(event, line)
			line = nil
			if complete && isBlankSSELine(event[len(event)-1]) {
				if werr := emit(); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			// End of stream or upstream failure: deliver what was received,
			// then report a failure so the caller can abort the connection.
			if werr := emit(); werr != nil {
				return werr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

var errResponseTooLarge = errors.New("response too large")

func isBlankSSELine(line []byte) bool {
	return len(bytes.TrimRight(line, "\r\n")) == 0
}

func splitLineEnding(line []byte) ([]byte, []byte) {
	body := bytes.TrimRight(line, "\r\n")
	return body, line[len(body):]
}

// stripSSEEvent returns the event's bytes with engine metadata removed from its
// data. Events without metadata are returned byte for byte.
func stripSSEEvent(lines [][]byte) ([]byte, error) {
	var dataIdx []int
	var payloads [][]byte
	for i, l := range lines {
		body, _ := splitLineEnding(l)
		if bytes.HasPrefix(body, []byte("data:")) {
			v := body[len("data:"):]
			if len(v) > 0 && v[0] == ' ' {
				v = v[1:]
			}
			dataIdx = append(dataIdx, i)
			payloads = append(payloads, v)
		}
	}
	join := func() []byte { return bytes.Join(lines, nil) }
	if len(dataIdx) == 0 {
		return join(), nil
	}
	payload := bytes.Join(payloads, []byte("\n"))
	stripped, err := stripEngineMetadata(payload)
	if err != nil {
		return nil, err
	}
	if len(stripped) == len(payload) {
		// A payload that names the field but is not JSON (for example a chunk
		// truncated by an upstream failure) is refused rather than relayed.
		if bytes.Contains(payload, []byte(engineMetadataField)) && !json.Valid(payload) {
			return nil, errInvalidStrip
		}
		return join(), nil
	}
	first := lines[dataIdx[0]]
	_, ending := splitLineEnding(first)
	if len(ending) == 0 {
		ending = []byte("\n")
	}
	var replacement []byte
	for _, part := range bytes.Split(stripped, []byte("\n")) {
		replacement = append(replacement, "data: "...)
		replacement = append(replacement, part...)
		replacement = append(replacement, ending...)
	}
	var out []byte
	for i, l := range lines {
		switch {
		case i == dataIdx[0]:
			out = append(out, replacement...)
		case isDataLine(l):
			// Folded into the replacement above.
		default:
			out = append(out, l...)
		}
	}
	return out, nil
}

func isDataLine(line []byte) bool {
	body, _ := splitLineEnding(line)
	return bytes.HasPrefix(body, []byte("data:"))
}
