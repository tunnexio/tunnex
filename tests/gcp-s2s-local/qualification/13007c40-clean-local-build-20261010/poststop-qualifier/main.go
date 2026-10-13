// Independent observational qualifier. No commands, leases, cleanup or receipts.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

const source = "13007c405cece2ab3a1a790b1b539980479336a3"
const reader = "7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f"

type capture struct {
	Source      string `json:"qualifier_source"`
	Image       string `json:"reader_image"`
	Reader      string `json:"reader_sha256"`
	Namespace   string `json:"namespace_before"`
	After       string `json:"namespace_after"`
	GuardStable bool   `json:"guard_identity_stable"`
	Expected    struct {
		ExpectedJSON string
		Digest       string
		Revision     uint64
		Namespace    string
	} `json:"expected_guard"`
	Actual     json.RawMessage        `json:"actual_guard"`
	Links      []ipsec.GuardInterface `json:"links"`
	JournalSHA string                 `json:"journal_sha256"`
}

func invalid() error { return errors.New("observational guard qualifier refused") }
func verify(c capture) error {
	if c.Source != source || c.Image != "sha256:9a051bbdc9eed316bfabf2914e26a1c5f454927665902b0c7e0d2ded8a5374d7" || c.Reader != reader || !c.GuardStable || c.Namespace != "net:[4026531840]" || c.After != c.Namespace || c.Expected.Namespace != c.Namespace || c.Expected.Revision == 0 {
		return invalid()
	}
	for _, s := range []string{c.Expected.Digest, c.JournalSHA} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
			return invalid()
		}
	}
	if ipsec.VerifyGuardWithdrawal([]byte(c.Expected.ExpectedJSON), c.Actual, c.Links) != nil {
		return invalid()
	}
	var objects struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	dec := json.NewDecoder(bytes.NewReader(c.Actual))
	dec.DisallowUnknownFields()
	if dec.Decode(&objects) != nil {
		return invalid()
	}
	sets := map[string]bool{}
	drops := map[string]bool{}
	for _, o := range objects.NFT {
		if raw, ok := o["set"]; ok {
			var s struct {
				Name string          `json:"name"`
				Elem json.RawMessage `json:"elem"`
			}
			if json.Unmarshal(raw, &s) != nil {
				return invalid()
			}
			if strings.HasPrefix(s.Name, "lease_") || strings.HasPrefix(s.Name, "reply_lease_") || strings.HasPrefix(s.Name, "sa_lease_") {
				if len(s.Elem) > 0 && string(s.Elem) != "[]" {
					return invalid()
				}
				sets[s.Name] = true
			}
		}
		// Separate element commands are never allowed to repopulate permit sets.
		if raw, ok := o["element"]; ok {
			var e struct {
				Name string          `json:"name"`
				Elem json.RawMessage `json:"elem"`
			}
			if json.Unmarshal(raw, &e) != nil {
				return invalid()
			}
			if strings.HasPrefix(e.Name, "lease_") || strings.HasPrefix(e.Name, "reply_lease_") || strings.HasPrefix(e.Name, "sa_lease_") {
				if string(e.Elem) != "[]" {
					return invalid()
				}
			}
		}
		if raw, ok := o["rule"]; ok {
			var r struct {
				Chain string                       `json:"chain"`
				Expr  []map[string]json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(raw, &r) != nil {
				return invalid()
			}
			if len(r.Expr) != 3 || len(r.Expr[0]) != 1 || len(r.Expr[1]) != 1 || len(r.Expr[2]) != 1 {
				continue
			}
			if _, ok := r.Expr[1]["counter"]; !ok {
				continue
			}
			if string(r.Expr[2]["drop"]) != "null" {
				continue
			}
			var m struct {
				Op   string `json:"op"`
				Left struct {
					Payload struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right struct {
					Prefix struct {
						Addr string `json:"addr"`
						Len  int    `json:"len"`
					} `json:"prefix"`
				} `json:"right"`
			}
			if json.Unmarshal(r.Expr[0]["match"], &m) != nil || m.Op != "==" || m.Left.Payload.Protocol != "ip" || m.Right.Prefix.Len != 24 {
				continue
			}
			if m.Right.Prefix.Addr == "10.80.0.0" || m.Right.Prefix.Addr == "10.81.0.0" {
				drops[r.Chain+":"+m.Left.Payload.Field+":"+m.Right.Prefix.Addr] = true
			}
		}
	}
	for _, id := range []string{"80c206678d844dd88e51ae4a10445cbb", "b79d7edafafe41cfaf2c4115d4ef32c6"} {
		for _, p := range []string{"lease_", "reply_lease_", "sa_lease_"} {
			if !sets[p+id] {
				return invalid()
			}
		}
	}
	for _, p := range []string{"10.80.0.0", "10.81.0.0"} {
		for _, v := range []string{"forward_guard:saddr:", "forward_guard:daddr:", "output_guard:saddr:", "output_guard:daddr:", "input_guard:saddr:", "postrouting_guard:daddr:"} {
			if !drops[v+p] {
				return invalid()
			}
		}
	}
	return nil
}
func main() {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 4<<20+1))
	if e != nil || len(raw) > 4<<20 {
		fail()
	}
	var c capture
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		fail()
	}
	var extra any
	if d.Decode(&extra) != io.EOF || verify(c) != nil {
		fail()
	}
	digest := sha256.Sum256(raw)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"qualifier_source": source, "capture_sha256": hex.EncodeToString(digest[:]), "namespace": c.Namespace, "guard_revision": c.Expected.Revision, "guard_digest": c.Expected.Digest, "journal_sha256": c.JournalSHA, "owned_table_prefix_refusal_verified": true, "permit_sets_actually_empty": true, "scope": "fresh captured owned table only; NOT host firewall census, lease/cleanup/restoration authority or packet proof"})
}
func fail() { fmt.Fprintln(os.Stderr, "Observational post-stop prefix refusal: REFUSED"); os.Exit(1) }
