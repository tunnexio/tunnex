// Package sandboxnetwork owns only namespace-bound sandbox WireGuard setup.
// It is not a gateway policy compiler or an authority to grant network access.
package sandboxnetwork

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid sandbox network plan")
var ErrOwnership = errors.New("sandbox network ownership mismatch")
var ErrUnavailable = errors.New("sandbox network unavailable")
var ErrMissing = errors.New("sandbox network missing")
var hexIdentity = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Binding struct {
	OrgID       uuid.UUID `json:"org_id"`
	SandboxID   uuid.UUID `json:"sandbox_id"`
	OperationID uuid.UUID `json:"operation_id"`
	GatewayID   uuid.UUID `json:"gateway_id"`
	PeerID      uuid.UUID `json:"peer_id"`
	Generation  int64     `json:"generation"`
	RuntimeID   string    `json:"runtime_id"`
	SpecHash    string    `json:"spec_hash"`
}

type Plan struct {
	Binding          Binding        `json:"binding"`
	PublicKey        string         `json:"public_key"`
	GatewayPublicKey string         `json:"gateway_public_key"`
	Address          netip.Prefix   `json:"address"`
	Endpoint         netip.AddrPort `json:"endpoint"`
	Routes           []netip.Prefix `json:"routes"`
	MTU              int            `json:"mtu"`
	KeepaliveSeconds int            `json:"keepalive_seconds"`
}

// Normalize supports only the explicitly admitted private IPv4 split profile.
// Unsupported DNS/full-tunnel configuration must be rejected by the caller,
// never silently removed. Endpoints are trusted literal IPs, not browser URLs.
func Normalize(p Plan) (Plan, error) {
	b := p.Binding
	if b.OrgID == uuid.Nil || b.SandboxID == uuid.Nil || b.OperationID == uuid.Nil || b.GatewayID == uuid.Nil || b.PeerID == uuid.Nil || b.Generation < 1 || !hexIdentity.MatchString(b.RuntimeID) || !hexIdentity.MatchString(b.SpecHash) || !validKey(p.PublicKey) || !validKey(p.GatewayPublicKey) || !p.Address.IsValid() || !p.Address.Addr().Is4() || !p.Address.Addr().IsPrivate() || p.Address.Bits() != 32 || !p.Endpoint.IsValid() || !p.Endpoint.Addr().Is4() || p.Endpoint.Addr().IsUnspecified() || p.Endpoint.Addr().IsMulticast() || p.Endpoint.Port() == 0 || p.MTU < 576 || p.MTU > 9000 || p.KeepaliveSeconds < 1 || p.KeepaliveSeconds > 120 || len(p.Routes) < 1 || len(p.Routes) > 32 {
		return Plan{}, ErrInvalid
	}
	p.Routes = slices.Clone(p.Routes)
	for _, route := range p.Routes {
		if !route.IsValid() || !route.Addr().Is4() || route != route.Masked() || !route.Addr().IsPrivate() || route.Bits() < 8 || !lastAddress(route).IsPrivate() {
			return Plan{}, ErrInvalid
		}
	}
	slices.SortFunc(p.Routes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	for i := 1; i < len(p.Routes); i++ {
		if p.Routes[i] == p.Routes[i-1] {
			return Plan{}, ErrInvalid
		}
	}
	return p, nil
}
func lastAddress(p netip.Prefix) netip.Addr {
	v := p.Addr().As4()
	for bit := p.Bits(); bit < 32; bit++ {
		v[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom4(v)
}
func validKey(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == value
}
func Identity(p Plan) (string, error) {
	p, err := Normalize(p)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func InterfaceName(p Plan) string {
	sum := sha256.Sum256(p.Binding.OperationID[:])
	return "tx" + hex.EncodeToString(sum[:])[:12]
}
func Alias(p Plan) string {
	hash, _ := Identity(p)
	return "tunnex:sandbox:" + p.Binding.SandboxID.String() + ":" + hash
}

// WireGuardConfig is supplied only as stdin to wg setconf. It is never stored in
// public manifests or returned by inspection; callers discard command stderr.
func WireGuardConfig(p Plan, privateKey string) ([]byte, error) {
	p, err := Normalize(p)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(raw) != 32 {
		return nil, ErrInvalid
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != p.PublicKey {
		return nil, ErrOwnership
	}
	routes := make([]string, len(p.Routes))
	for i, r := range p.Routes {
		routes[i] = r.String()
	}
	return []byte("[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + p.GatewayPublicKey + "\nEndpoint = " + p.Endpoint.String() + "\nAllowedIPs = " + strings.Join(routes, ", ") + "\nPersistentKeepalive = " + strconv.Itoa(p.KeepaliveSeconds) + "\n"), nil
}

type NamespaceIdentity struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	OwnerUID uint32 `json:"owner_uid"`
}
type Manifest struct {
	Plan      Plan              `json:"plan"`
	Namespace NamespaceIdentity `json:"namespace"`
}

func (m Manifest) Matches(p Plan, ns NamespaceIdentity) bool {
	a, ea := Identity(m.Plan)
	b, eb := Identity(p)
	return ea == nil && eb == nil && a == b && m.Namespace == ns && ns.Inode != 0
}
