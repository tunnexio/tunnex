// Owned-table observation only: no network commands, policy or lease authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

const source = "5121dc3374656449dd53dab9abd248216d5d5581"
const image = "sha256:b8f7ccba5b01cc9dd8ca0337c780c69d72e8037fcd5f16adfe98c53af4285ded"
const container = "5ed2a7643f2756b58c2920e7f9f74cf68078c5a794cc128e8a6a112684ce283e"
const namespace = "net:[4026531840]"
const boot = "9617762e-19db-4a21-bdee-909dfb31e501"
const reader = "7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f"
const classicInterfaceIndex uint64 = 20
const underlayInterfaceIndex uint64 = 2
const owner = "01a125fa-32f3-762b-83d4-d368447bf6ed"
const lease = "lease_b79d7edafafe41cfaf2c4115d4ef32c6"
const reply = "reply_lease_b79d7edafafe41cfaf2c4115d4ef32c6"
const saLease = "sa_lease_b79d7edafafe41cfaf2c4115d4ef32c6"

type capture struct {
	Source     string `json:"source_commit"`
	Container  string `json:"container_id"`
	Image      string `json:"image_id"`
	Boot       string `json:"boot_id"`
	Before     string `json:"namespace_before"`
	After      string `json:"namespace_after"`
	HostBefore string `json:"host_namespace_before"`
	HostAfter  string `json:"host_namespace_after"`
	Stable     bool   `json:"guard_identity_stable"`
	Reader     string `json:"reader_sha256"`
	Scope      string `json:"scope"`
	Expected   struct {
		ExpectedJSON string
		Digest       string
		Revision     uint64
		Namespace    string
	} `json:"expected_guard"`
	Actual json.RawMessage              `json:"actual_guard"`
	Links  []map[string]json.RawMessage `json:"links"`
}
type tupleObservation struct {
	Protocol       string            `json:"protocol"`
	Port           int               `json:"port"`
	Exact          int               `json:"exact_forward_original_rules"`
	Matching       int               `json:"matching_or_wider_forward_rules"`
	CanonicalRules []json.RawMessage `json:"verified_canonical_expected_rules,omitempty"`
}
type result struct {
	Scope     string             `json:"scope"`
	Source    string             `json:"source"`
	Mode      string             `json:"expect"`
	Protocol  string             `json:"protocol"`
	Revision  uint64             `json:"guard_revision"`
	Digest    string             `json:"guard_digest"`
	Readback  string             `json:"readback"`
	Tuples    []tupleObservation `json:"tuples"`
	LiveSets  map[string]bool    `json:"classic_live_sets"`
	Deadlines string             `json:"deadline_binding"`
}

func invalid() error { return errors.New("expiry guard observation refused") }
func decode(raw []byte) (map[string]any, error) {
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return nil, invalid()
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, invalid()
	}
	return v, nil
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func number(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	x, e := strconv.ParseUint(n.String(), 10, 64)
	return x, e == nil
}
func selector(v any, kind, key string) bool {
	m := object(object(v)[kind])
	field := "key"
	if kind == "payload" {
		field = "field"
	}
	return m[field] == key && (kind != "payload" || m["protocol"] == "ip")
}
func prefix(v any) (netip.Prefix, bool) {
	p := object(object(v)["prefix"])
	a, ok := p["addr"].(string)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, ok := number(p["len"])
	if !ok || bits > 32 {
		return netip.Prefix{}, false
	}
	addr, e := netip.ParseAddr(a)
	if e != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	out := netip.PrefixFrom(addr, int(bits))
	return out, out == out.Masked()
}
func portMatches(v any, want int) bool {
	if n, ok := number(v); ok {
		return n == uint64(want)
	}
	r, _ := object(v)["range"].([]any)
	if len(r) == 2 {
		a, ok := number(r[0])
		b, ok2 := number(r[1])
		return ok && ok2 && a <= uint64(want) && uint64(want) <= b
	}
	return true
}

// Full production readback has already validated the complete rule schema.
// Any unclassified condition prevents an exact allow; it cannot prove denial.
func appRule(expr []any, protocol string, port int) (matching, exact bool) {
	srcWant := netip.MustParsePrefix("10.70.0.0/24")
	dstWant := netip.MustParseAddr("10.81.0.10")
	accept := false
	exactFields := map[string]bool{}
	unknown := false
	for _, raw := range expr {
		o := object(raw)
		if _, ok := o["accept"]; ok {
			accept = true
			continue
		}
		if _, ok := o["counter"]; ok {
			continue
		}
		m := object(o["match"])
		if m == nil {
			unknown = true
			continue
		}
		left, right := m["left"], m["right"]
		if selector(left, "ct", "direction") {
			if m["op"] == "==" && right == "reply" {
				return false, false
			}
			if m["op"] == "==" && right == "original" {
				exactFields["direction"] = true
				continue
			}
			unknown = true
			continue
		}
		if selector(left, "payload", "saddr") || selector(left, "payload", "daddr") {
			p, ok := prefix(right)
			if !ok || m["op"] != "==" {
				unknown = true
				continue
			}
			if selector(left, "payload", "saddr") {
				if !p.Overlaps(srcWant) {
					return false, false
				}
				exactFields["source"] = p == srcWant
			} else {
				if !p.Contains(dstWant) {
					return false, false
				}
				exactFields["destination"] = p == netip.PrefixFrom(dstWant, 32)
			}
			continue
		}
		payload := object(object(left)["payload"])
		if payload != nil {
			p, _ := payload["protocol"].(string)
			if p == "tcp" || p == "udp" {
				if p != protocol {
					return false, false
				}
				if payload["field"] == "dport" && m["op"] == "==" {
					if !portMatches(right, port) {
						return false, false
					}
					n, ok := number(right)
					exactFields["port"] = ok && n == uint64(port)
					continue
				}
			}
			if p == "icmp" {
				return false, false
			}
			unknown = true
			continue
		}
		if selector(left, "meta", "l4proto") && m["op"] == "==" {
			if right != protocol {
				return false, false
			}
			unknown = true
			continue
		}
		if selector(left, "meta", "iif") || selector(left, "meta", "oif") {
			key := object(object(left)["meta"])["key"].(string)
			if m["op"] == "==" && right == "@"+lease && key == "oif" {
				exactFields["lease"] = true
				continue
			}
			n, ok := number(right)
			want := underlayInterfaceIndex
			if key == "oif" {
				want = classicInterfaceIndex
			}
			if m["op"] == "==" && ok {
				if n != want {
					return false, false
				}
				exactFields[key] = true
				continue
			}
			unknown = true
			continue
		}
		unknown = true
	}
	if !accept {
		return false, false
	}
	exact = !unknown && len(exactFields) == 7
	for _, key := range []string{"direction", "source", "destination", "port", "iif", "oif", "lease"} {
		exact = exact && exactFields[key]
	}
	return true, exact
}
func liveSet(s map[string]any, names map[string]int, index bool) bool {
	members, _ := s["elem"].([]any)
	if len(members) == 0 {
		return false
	}
	for _, raw := range members {
		e := object(object(raw)["elem"])
		v, ok := number(e["val"])
		if !ok {
			if n, ok2 := e["val"].(string); ok2 {
				v = uint64(names[n])
				ok = v > 0
			}
		}
		if !ok || index && v != classicInterfaceIndex {
			continue
		}
		timeout, tok := number(e["timeout"])
		if !tok {
			timeout, tok = number(s["timeout"])
		}
		expiry, eok := number(e["expires"])
		if !eok {
			expiry = timeout
		}
		if tok && timeout > 0 && timeout <= 60 && expiry > 0 && expiry <= timeout {
			return true
		}
	}
	return false
}
func verify(c capture, mode, protocol string) (result, error) {
	if (mode != "allow" && mode != "deny") || (protocol != "tcp" && protocol != "udp") || c.Source != source || c.Container != container || c.Image != image || c.Boot != boot || c.Reader != reader || !c.Stable || c.Before != namespace || c.After != namespace || c.HostBefore != namespace || c.HostAfter != namespace || c.Expected.Namespace != namespace || c.Expected.Revision == 0 {
		return result{}, invalid()
	}
	b, e := hex.DecodeString(c.Expected.Digest)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != c.Expected.Digest {
		return result{}, invalid()
	}
	links := []ipsec.GuardInterface{}
	names := map[string]int{}
	for _, raw := range c.Links {
		var l ipsec.GuardInterface
		if json.Unmarshal(raw["ifname"], &l.Name) != nil || json.Unmarshal(raw["ifindex"], &l.Index) != nil {
			return result{}, invalid()
		}
		links = append(links, l)
		names[l.Name] = l.Index
	}

	if names["ens4"] != int(underlayInterfaceIndex) || names["txe936e4aecebb"] != int(classicInterfaceIndex) {
		return result{}, invalid()
	}
	rb := "positive"
	if ipsec.VerifyGuardReadbackWithInterfaces([]byte(c.Expected.ExpectedJSON), c.Actual, links) != nil {
		if mode == "allow" || ipsec.VerifyGuardWithdrawal([]byte(c.Expected.ExpectedJSON), c.Actual, links) != nil {
			return result{}, invalid()
		}
		rb = "withdrawal structure only"
	}
	expected, e := decode([]byte(c.Expected.ExpectedJSON))
	if e != nil {
		return result{}, e
	}
	actual, e := decode(c.Actual)
	if e != nil {
		return result{}, e
	}
	observations := []tupleObservation{{Protocol: "tcp", Port: 8080}, {Protocol: "udp", Port: 9000}}
	drops := map[string]bool{}
	ownerMatch := false
	objects, _ := expected["nftables"].([]any)
	for _, raw := range objects {
		o := object(raw)
		if chain := object(o["chain"]); chain != nil && chain["name"] == "owner" {
			ownerMatch = chain["comment"] == fmt.Sprintf("tunnex-ipsec:%s:%d:%s", owner, c.Expected.Revision, c.Expected.Digest)
		}
		r := object(o["rule"])
		if r == nil {
			continue
		}
		expr, _ := r["expr"].([]any)
		if r["chain"] == "forward_guard" {
			for i := range observations {
				match, exact := appRule(expr, observations[i].Protocol, observations[i].Port)
				if match {
					observations[i].Matching++
					canonical, _ := json.Marshal(r)
					observations[i].CanonicalRules = append(observations[i].CanonicalRules, canonical)
				}
				if exact {
					observations[i].Exact++
				}
			}
		}
		if len(expr) == 3 {
			m := object(object(expr[0])["match"])
			p, ok := prefix(m["right"])
			_, drop := object(expr[2])["drop"]
			_, counter := object(expr[1])["counter"]
			if counter && ok && p == netip.MustParsePrefix("10.81.0.0/24") && m["op"] == "==" && drop {
				chain, _ := r["chain"].(string)
				for _, field := range []string{"saddr", "daddr"} {
					if selector(m["left"], "payload", field) {
						drops[chain+":"+field] = true
					}
				}
			}
		}
	}
	if !ownerMatch {
		return result{}, invalid()
	}
	for _, chain := range []string{"forward_guard:saddr", "forward_guard:daddr", "input_guard:saddr", "output_guard:saddr", "output_guard:daddr", "postrouting_guard:daddr"} {
		if !drops[chain] {
			return result{}, invalid()
		}
	}
	live := map[string]bool{lease: false, reply: false, saLease: false}
	objects, _ = actual["nftables"].([]any)
	for _, raw := range objects {
		s := object(object(raw)["set"])
		name, _ := s["name"].(string)
		if _, ok := live[name]; ok {
			live[name] = liveSet(s, names, name != saLease)
		}
	}
	for _, o := range observations {
		if o.Protocol != protocol {
			continue
		}
		if mode == "allow" {
			if rb != "positive" || o.Exact != 1 || o.Matching != 1 || !live[lease] || !live[reply] || !live[saLease] {
				return result{}, invalid()
			}
		} else if o.Matching != 0 {
			return result{}, invalid()
		}
	}
	return result{Scope: "verified owned-table observation; no packet/lease/cleanup authority", Source: source, Mode: mode, Protocol: protocol, Revision: c.Expected.Revision, Digest: c.Expected.Digest, Readback: rb, Tuples: observations, LiveSets: live, Deadlines: "normal API policy/deadline evidence bound externally; no per-rule policy ID claim"}, nil
}
func main() {
	mode := flag.String("expect", "", "allow or deny")
	protocol := flag.String("protocol", "", "tcp or udp")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Println(`{"completed":false,"error":"unexpected arguments refused"}`)
		os.Exit(1)
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 2*1024*1024+1))
	if e != nil || len(raw) > 2*1024*1024 {
		fmt.Println(`{"completed":false,"error":"bounded input refused"}`)
		os.Exit(1)
	}
	var c capture
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		fmt.Println(`{"completed":false,"error":"capture shape refused"}`)
		os.Exit(1)
	}
	if *mode == "transition-pending" {
  if *protocol != "tcp" && *protocol != "udp" { os.Exit(1) }
  if verifyTransitionEmpty(c) != nil { fmt.Println(`{"completed":false,"error":"unknown transition refused"}`); os.Exit(1) }
  sum := sha256.Sum256(raw)
  json.NewEncoder(os.Stdout).Encode(map[string]any{"completed":true,"capture_sha256":hex.EncodeToString(sum[:]),"guard_transition_qualified":true,"packet_authority":false,"source":source,"scope":"full canonical Classic denial and exact three empty sets; external native/HA/API/event proof required"})
  return
 }
 r, e := verify(c, *mode, *protocol)
	if e != nil {
		fmt.Println(`{"completed":false,"error":"expiry guard observation refused"}`)
		os.Exit(1)
	}
	sum := sha256.Sum256(raw)
	out := map[string]any{"completed": true, "capture_sha256": hex.EncodeToString(sum[:]), "observation": r}
	json.NewEncoder(os.Stdout).Encode(out)
}

// verifyTransitionEmpty preserves both original full canonical production proofs
// and both protocol permanent denials. Empty authority is observation only.
func verifyTransitionEmpty(c capture) error {
 for _, protocol := range []string{"tcp", "udp"} {
  if _, err := verify(c, "deny", protocol); err != nil { return err }
 }
 for _, raw := range [][]byte{[]byte(c.Expected.ExpectedJSON), c.Actual} {
  d, err := decode(raw); if err != nil { return err }
  rows, ok := d["nftables"].([]any); if !ok { return invalid() }
  found := map[string]bool{}
  for _, row := range rows {
   set := object(object(row)["set"]); name, _ := set["name"].(string)
   if name != lease && name != reply && name != saLease { continue }
   if found[name] { return invalid() }; found[name] = true
   if elems, present := set["elem"]; present {
    values, ok := elems.([]any); if !ok || len(values) != 0 { return invalid() }
   }
  }
  if len(found) != 3 { return invalid() }
 }
 return nil
}
