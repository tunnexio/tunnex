// Package fqdn defines the normalized hostname contract shared by FQDN resource
// writers and resolver workers. It deliberately has no database or HTTP
// dependency so every producer applies the same D1 boundary before persistence.
package fqdn

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

var (
	// ErrInvalid is returned for every input outside the D1 FQDN-only contract.
	// Callers should not expose parser internals, which would turn validation into
	// a hostname syntax oracle.
	ErrInvalid = errors.New("invalid FQDN")

	lookupProfile = idna.New(
		idna.MapForLookup(),
		idna.StrictDomainName(true),
		idna.Transitional(false),
		idna.VerifyDNSLength(true),
	)
)

// Normalize converts a Unicode DNS name to its lower-case IDNA ASCII form.
// Exactly one trailing root dot is accepted as input but is never stored. Empty
// labels, wildcards, URLs, ports, underscores, IP literals, and whitespace are
// rejected rather than repaired. The returned string is therefore safe to use as
// the exact persisted and comparison value for an FQDN resource.
func Normalize(input string) (string, error) {
	if input == "" || strings.TrimSpace(input) != input {
		return "", ErrInvalid
	}
	if strings.HasSuffix(input, ".") {
		input = strings.TrimSuffix(input, ".")
	}
	if input == "" || strings.HasSuffix(input, ".") || !strings.Contains(input, ".") {
		return "", ErrInvalid
	}
	if strings.ContainsAny(input, "/:@[]*_") {
		return "", ErrInvalid
	}

	ascii, err := lookupProfile.ToASCII(input)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", ErrInvalid
	}
	ascii = strings.ToLower(ascii)
	if addr, err := netip.ParseAddr(ascii); err == nil && addr.IsValid() {
		return "", ErrInvalid
	}
	return ascii, nil
}
