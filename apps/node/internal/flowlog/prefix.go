package flowlog

import "strings"

// The nft `log prefix` payload that names the grant which fired. Kept SHORT and ASCII: a
// tag + the rule uuid (or the deny sentinel) + a single delimiting space, so the kernel's
// appended packet fields are separable. (a): the kernel stamps this at match time, so
// attribution has no packet-tuple TOCTOU.
const (
	prefixTag = "tnx:"
	denyToken = "deny"
)

// EncodePrefix builds the log-prefix payload for a rule. An empty ruleID (a default-deny,
// no rule) encodes the deny sentinel. Callers (egress) place this in the nft `log prefix`.
func EncodePrefix(ruleID string) string {
	if ruleID == "" {
		return prefixTag + denyToken + " "
	}
	return prefixTag + ruleID + " "
}

// ParsePrefix extracts the rule attribution from a kernel log line's prefix token.
//   - ok=false  → the line is not ours (no tnx tag); the reader skips it.
//   - deny=true → a default-deny hit (ruleID is "").
//   - else      → ruleID names the grant that accepted the flow.
//
// It reads ONLY the prefix token; it never re-derives identity from the packet tuple.
func ParsePrefix(token string) (ruleID string, deny bool, ok bool) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, prefixTag) {
		return "", false, false
	}
	v := strings.TrimPrefix(token, prefixTag)
	if v == denyToken || v == "" {
		return "", true, true
	}
	return v, false, true
}
