package aigateway

import (
	"crypto/rand"
	"crypto/sha256"
	"hash/crc32"
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

// AI-KEYS-1 D2. A static key is `tnx_sk_`, 43 random base62 characters (about
// 256 bits) and a 6-character base62 CRC32 of the random part: 56 characters.
// The fixed prefix lets secret scanners match it; the checksum lets them drop
// false matches offline. Base62 keeps `-` and `_` out of the secret.
const (
	StaticKeyPrefix      = "tnx_sk_"
	staticKeyRandomLen   = 43
	staticKeyChecksumLen = 6
	staticKeyLen         = len(StaticKeyPrefix) + staticKeyRandomLen + staticKeyChecksumLen
	staticKeyAlphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func staticKeyChecksum(random string) string {
	v := uint64(crc32.ChecksumIEEE([]byte(random)))
	out := make([]byte, staticKeyChecksumLen)
	for i := staticKeyChecksumLen - 1; i >= 0; i-- {
		out[i] = staticKeyAlphabet[v%62]
		v /= 62
	}
	return string(out)
}

// newStaticKey returns the raw key, its SHA-256 and the display hint.
func newStaticKey() (string, []byte, string, error) {
	random := make([]byte, staticKeyRandomLen)
	max := big.NewInt(62)
	for i := range random {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", nil, "", err
		}
		random[i] = staticKeyAlphabet[n.Int64()]
	}
	raw := StaticKeyPrefix + string(random) + staticKeyChecksum(string(random))
	hash := sha256.Sum256([]byte(raw))
	return raw, hash[:], raw[len(raw)-4:], nil
}

// validStaticKeyFormat checks the shape and checksum before any lookup.
func validStaticKeyFormat(raw string) bool {
	if len(raw) != staticKeyLen || !strings.HasPrefix(raw, StaticKeyPrefix) {
		return false
	}
	body := raw[len(StaticKeyPrefix):]
	for i := 0; i < len(body); i++ {
		if strings.IndexByte(staticKeyAlphabet, body[i]) < 0 {
			return false
		}
	}
	random := body[:staticKeyRandomLen]
	return body[staticKeyRandomLen:] == staticKeyChecksum(random)
}

// LooksLikeStaticKey reports only whether a credential claims the static key
// prefix. Routes use it to choose the static key path; it is never authority.
func LooksLikeStaticKey(raw string) bool { return strings.HasPrefix(raw, StaticKeyPrefix) }

var privateIPv4Bounds = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// nonPublicRanges are refused anywhere in a public key's allowlist. A private
// range would match a misconfigured proxy's own address and let every caller
// through; reserved and documentation space is never a real client.
var nonPublicRanges = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/8", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
		"fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	}
	out := make([]netip.Prefix, len(values))
	for i, v := range values {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}()

// PrivateIPv4Prefix reports whether prefix lies wholly inside RFC 1918 space.
func PrivateIPv4Prefix(prefix netip.Prefix) bool {
	if !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return false
	}
	for _, bound := range privateIPv4Bounds {
		if bound.Bits() <= prefix.Bits() && bound.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// PublicPrefix reports whether prefix overlaps no private, reserved or
// documentation range. 0.0.0.0/0 and ::/0 therefore fail.
func PublicPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Addr().Zone() != "" {
		return false
	}
	for _, bad := range nonPublicRanges {
		if bad.Addr().BitLen() == prefix.Addr().BitLen() && bad.Overlaps(prefix) {
			return false
		}
	}
	return true
}

// canonicalStaticKeyCIDRs validates and sorts a key's source ranges.
func canonicalStaticKeyCIDRs(raw []string, scope string) ([]string, bool) {
	if len(raw) > 32 {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(v))
		if err != nil {
			return nil, false
		}
		switch scope {
		case "internal":
			if !PrivateIPv4Prefix(prefix) {
				return nil, false
			}
		case "public":
			if !PublicPrefix(prefix) {
				return nil, false
			}
		default:
			return nil, false
		}
		if seen[prefix.String()] {
			return nil, false
		}
		seen[prefix.String()] = true
		out = append(out, prefix.String())
	}
	sort.Strings(out)
	return out, true
}

func cidrsContain(cidrs []string, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, v := range cidrs {
		prefix, err := netip.ParsePrefix(v)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}
