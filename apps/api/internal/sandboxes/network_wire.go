package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Version1 internal node-helper wire contract. Field order/tags match the node
// public-plan fingerprint; no public API or workload input constructs this.
type networkWireBinding struct {
	OrgID       uuid.UUID `json:"org_id"`
	SandboxID   uuid.UUID `json:"sandbox_id"`
	OperationID uuid.UUID `json:"operation_id"`
	GatewayID   uuid.UUID `json:"gateway_id"`
	PeerID      uuid.UUID `json:"peer_id"`
	Generation  int64     `json:"generation"`
	RuntimeID   string    `json:"runtime_id"`
	SpecHash    string    `json:"spec_hash"`
}
type networkWirePlan struct {
	Binding          networkWireBinding `json:"binding"`
	PublicKey        string             `json:"public_key"`
	GatewayPublicKey string             `json:"gateway_public_key"`
	Address          netip.Prefix       `json:"address"`
	Endpoint         netip.AddrPort     `json:"endpoint"`
	Routes           []netip.Prefix     `json:"routes"`
	MTU              int                `json:"mtu"`
	KeepaliveSeconds int                `json:"keepalive_seconds"`
}

func privateNetworkPlan(target PrivateNetworkTarget, config []byte) (networkWirePlan, string, error) {
	var plan networkWirePlan
	public, err := persistedWireGuardPublicKey(config)
	if err != nil || public != target.PublicKey {
		return plan, "", ErrConflict
	}
	plan.Binding = networkWireBinding{target.OrgID, target.SandboxID, target.OperationID, target.GatewayID, target.PeerID, target.Generation, target.RuntimeID, target.SpecHash}
	plan.PublicKey = public
	plan.MTU = 1420
	plan.KeepaliveSeconds = 25
	section, private := "", ""
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return plan, "", ErrConflict
		}
		name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch section + name {
		case "[Interface]PrivateKey":
			private = value
		case "[Interface]Address":
			plan.Address, err = netip.ParsePrefix(value)
		case "[Interface]MTU":
			plan.MTU, err = strconv.Atoi(value)
		case "[Interface]DNS":
			return plan, "", ErrDisabled // unsupported profile; never silently strip requested DNS
		case "[Peer]PublicKey":
			plan.GatewayPublicKey = value
		case "[Peer]Endpoint":
			plan.Endpoint, err = netip.ParseAddrPort(value)
		case "[Peer]AllowedIPs":
			for _, value := range strings.Split(value, ",") {
				var route netip.Prefix
				route, err = netip.ParsePrefix(strings.TrimSpace(value))
				if err != nil {
					return plan, "", ErrConflict
				}
				if !route.Addr().Is4() || !route.Addr().IsPrivate() || route.Bits() < 8 || route != route.Masked() {
					return plan, "", ErrDisabled
				}
				plan.Routes = append(plan.Routes, route)
			}
		case "[Peer]PersistentKeepalive":
			plan.KeepaliveSeconds, err = strconv.Atoi(value)
		default:
			return plan, "", ErrConflict
		}
		if err != nil {
			return plan, "", ErrConflict
		}
	}
	if plan.Address != netip.PrefixFrom(target.Address, 32) || len(plan.Routes) == 0 || len(plan.Routes) > 32 || !plan.Endpoint.IsValid() || !plan.Endpoint.Addr().Is4() {
		return plan, "", ErrConflict
	}
	slices.SortFunc(plan.Routes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return plan, private, nil
}
func networkPlanHash(plan networkWirePlan) string {
	raw, _ := json.Marshal(plan)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
