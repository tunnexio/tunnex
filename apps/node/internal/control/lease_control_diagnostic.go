package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

// Deliberately retains the public sentinel and never exposes remote or transport text.
type leaseControlFailure struct{ category string }

func (e leaseControlFailure) Error() string                  { return ErrIPsecControl.Error() }
func (e leaseControlFailure) Unwrap() error                  { return ErrIPsecControl }
func (e leaseControlFailure) IPsecLeaseFailureStage() string { return e.category }

// Only the two public API codes classify a Renew conflict. Other callers never
// read an error body; unknown bodies retain the existing closed HTTP category.
func leaseConflictCodeCategory(ctx context.Context, body io.Reader) string {
	const fallback = "http_409"
	if ctx.Err() != nil {
		return fallback
	}
	raw, err := io.ReadAll(io.LimitReader(body, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 || ctx.Err() != nil {
		return fallback
	}
	outer, ok := leaseCodeObject(raw)
	if !ok {
		return fallback
	}
	defer func() {
		for _, v := range outer {
			clear(v)
		}
	}()
	inner, ok := leaseCodeObject(outer["error"])
	if !ok {
		return fallback
	}
	defer func() {
		for _, v := range inner {
			clear(v)
		}
	}()
	var code string
	if json.Unmarshal(inner["code"], &code) != nil {
		return fallback
	}
	switch code {
	case "ipsec_connection_ineligible":
		return "http_409_ineligible"
	case "ipsec_connection_conflict":
		return "http_409_conflict"
	}
	return fallback
}
func leaseCodeObject(raw []byte) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, exists := values[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		values[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return nil, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, false
	}
	return values, true
}
