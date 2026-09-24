package ipsec_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func fixture(t *testing.T) (*crypto.Sealer, ipsec.PSKBinding) {
	t.Helper()
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatal("fixture sealer failed")
	}
	return sealer, ipsec.PSKBinding{OrgID: uuid.New(), ConnectionID: uuid.New(), TunnelID: uuid.New(), Revision: 7}
}

func refused(t *testing.T, value string, err error) {
	t.Helper()
	if value != "" || err != ipsec.ErrPSKEnvelope {
		t.Fatal("refusal must return empty output and the static envelope error")
	}
}

func envelope(t *testing.T, binding ipsec.PSKBinding, value string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"version": 1, "purpose": "tunnex-ipsec-psk", "org_id": binding.OrgID, "connection_id": binding.ConnectionID, "tunnel_id": binding.TunnelID, "revision": binding.Revision, "value": value})
	if err != nil {
		t.Fatal("fixture envelope encoding failed")
	}
	return raw
}

func sealRaw(t *testing.T, sealer *crypto.Sealer, raw []byte) string {
	t.Helper()
	sealed, err := sealer.Seal(raw)
	if err != nil {
		t.Fatal("fixture envelope sealing failed")
	}
	return sealed
}

func TestPSKEnvelopeRoundTripAndFreshNonce(t *testing.T) {
	sealer, binding := fixture(t)
	for name, value := range map[string]string{
		"one byte": "x", "preserved spaces": "  test secret  ", "unicode": "秘密-é",
		"max bytes": strings.Repeat("a", 4096), "max unicode bytes": strings.Repeat("é", 2048),
		"max escaped bytes": strings.Repeat("\"\\", 2048), "max html sensitive bytes": strings.Repeat("<", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := ipsec.SealPSK(sealer, binding, value)
			if err != nil || sealed == "" || len(sealed) > 16384 {
				t.Fatal("valid bounded input was not sealed")
			}
			got, err := ipsec.OpenPSK(sealer, binding, sealed)
			if err != nil || got != value {
				t.Fatal("round trip changed accepted input")
			}
			second, err := ipsec.SealPSK(sealer, binding, value)
			if err != nil || second == sealed {
				t.Fatal("repeat seal lacked fresh nonce")
			}
			raw, err := sealer.Open(sealed)
			if err != nil {
				t.Fatal("sealed envelope could not be inspected")
			}
			defer clear(raw)
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != 7 || string(fields["purpose"]) != `"tunnex-ipsec-psk"` || string(fields["version"]) != "1" {
				t.Fatal("envelope format lost purpose, version, or field contract")
			}
		})
	}
}

func TestPSKEnvelopeRejectsBindingSubstitution(t *testing.T) {
	sealer, binding := fixture(t)
	sealed, err := ipsec.SealPSK(sealer, binding, "synthetic-fixture")
	if err != nil {
		t.Fatal("fixture sealing failed")
	}
	for name, mutate := range map[string]func(*ipsec.PSKBinding){
		"org":        func(b *ipsec.PSKBinding) { b.OrgID = uuid.New() },
		"connection": func(b *ipsec.PSKBinding) { b.ConnectionID = uuid.New() },
		"tunnel":     func(b *ipsec.PSKBinding) { b.TunnelID = uuid.New() },
		"revision":   func(b *ipsec.PSKBinding) { b.Revision++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			got, err := ipsec.OpenPSK(sealer, changed, sealed)
			refused(t, got, err)
		})
	}
}

func TestPSKEnvelopeRejectsInvalidBindingAndNilSealer(t *testing.T) {
	sealer, binding := fixture(t)
	sealed := sealRaw(t, sealer, envelope(t, binding, "synthetic-fixture"))
	for name, mutate := range map[string]func(*ipsec.PSKBinding){
		"nil org":           func(b *ipsec.PSKBinding) { b.OrgID = uuid.Nil },
		"nil connection":    func(b *ipsec.PSKBinding) { b.ConnectionID = uuid.Nil },
		"nil tunnel":        func(b *ipsec.PSKBinding) { b.TunnelID = uuid.Nil },
		"zero revision":     func(b *ipsec.PSKBinding) { b.Revision = 0 },
		"negative revision": func(b *ipsec.PSKBinding) { b.Revision = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			got, err := ipsec.SealPSK(sealer, changed, "synthetic-fixture")
			refused(t, got, err)
			got, err = ipsec.OpenPSK(sealer, changed, sealed)
			refused(t, got, err)
		})
	}
	got, err := ipsec.SealPSK(nil, binding, "synthetic-fixture")
	refused(t, got, err)
	got, err = ipsec.OpenPSK(nil, binding, sealed)
	refused(t, got, err)
}

func TestPSKEnvelopeRejectsInvalidValues(t *testing.T) {
	sealer, binding := fixture(t)
	for name, value := range map[string]string{
		"empty": "", "spaces": "   ", "unicode whitespace": "\u2003\u00a0",
		"newline": "before\nafter", "tab": "before\tafter", "nul": "before\x00after", "delete": "before\x7fafter", "unicode control": "before\u0085after",
		"oversized bytes": strings.Repeat("x", 4097), "oversized unicode bytes": strings.Repeat("é", 2049),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ipsec.SealPSK(sealer, binding, value)
			refused(t, got, err)
			sealed := sealRaw(t, sealer, envelope(t, binding, value))
			got, err = ipsec.OpenPSK(sealer, binding, sealed)
			refused(t, got, err)
		})
	}
	t.Run("invalid utf8", func(t *testing.T) {
		got, err := ipsec.SealPSK(sealer, binding, string([]byte{0xff}))
		refused(t, got, err)
		raw := bytes.Replace(envelope(t, binding, "utf8-marker"), []byte("utf8-marker"), []byte{0xff}, 1)
		got, err = ipsec.OpenPSK(sealer, binding, sealRaw(t, sealer, raw))
		refused(t, got, err)
	})
}

func TestPSKEnvelopeRejectsInvalidAuthenticatedEnvelope(t *testing.T) {
	sealer, binding := fixture(t)
	for name, mutate := range map[string]func(map[string]any){
		"version":       func(e map[string]any) { e["version"] = 2 },
		"purpose":       func(e map[string]any) { e["purpose"] = "tunnex-ai-bifrost-key" },
		"org":           func(e map[string]any) { e["org_id"] = uuid.New() },
		"connection":    func(e map[string]any) { e["connection_id"] = uuid.New() },
		"tunnel":        func(e map[string]any) { e["tunnel_id"] = uuid.New() },
		"revision":      func(e map[string]any) { e["revision"] = 8 },
		"unknown field": func(e map[string]any) { e["extra"] = true },
		"missing value": func(e map[string]any) { delete(e, "value") },
		"wrong type":    func(e map[string]any) { e["value"] = 123 },
	} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(envelope(t, binding, "synthetic-fixture"), &fields) != nil {
				t.Fatal("fixture decode failed")
			}
			mutate(fields)
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal("fixture encode failed")
			}
			got, err := ipsec.OpenPSK(sealer, binding, sealRaw(t, sealer, raw))
			refused(t, got, err)
		})
	}
	for name, raw := range map[string][]byte{
		"trailing object": append(envelope(t, binding, "synthetic-fixture"), []byte(" {}")...),
		"trailing null":   append(envelope(t, binding, "synthetic-fixture"), []byte(" null")...),
		"malformed":       []byte("{"), "null envelope": []byte("null"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ipsec.OpenPSK(sealer, binding, sealRaw(t, sealer, raw))
			refused(t, got, err)
		})
	}
}

func TestPSKEnvelopeRejectsCiphertextFailures(t *testing.T) {
	sealer, binding := fixture(t)
	sealed := sealRaw(t, sealer, envelope(t, binding, "synthetic-fixture"))
	wrongKey, err := crypto.NewSealer(bytes.Repeat([]byte{0x40}, 32))
	if err != nil {
		t.Fatal("fixture sealer failed")
	}
	got, err := ipsec.OpenPSK(wrongKey, binding, sealed)
	refused(t, got, err)
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal("fixture base64 decode failed")
	}
	raw[len(raw)-1] ^= 1
	for name, ciphertext := range map[string]string{
		"empty": "", "malformed": "%%%", "short": "eA==",
		"oversized": strings.Repeat("A", 16385), "tampered": base64.StdEncoding.EncodeToString(raw),
	} {
		t.Run(name, func(t *testing.T) { got, err := ipsec.OpenPSK(sealer, binding, ciphertext); refused(t, got, err) })
	}
}
