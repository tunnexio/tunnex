package ipsec

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
)

// DNSRuntimeTransport is a composition-root bridge: it binds no listener and
// grants no authority. An unconstructed, unsupported or inactive controller
// always refuses. Atomic attachment handles runtime opt-in discovered later.
type DNSRuntimeTransport struct {
	controller atomic.Pointer[RuntimeController]
}

func (t *DNSRuntimeTransport) Attach(c *RuntimeController) {
	if t != nil {
		t.controller.Store(c)
	}
}
func (t *DNSRuntimeTransport) ExchangeDNS(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, payload []byte) ([]byte, error) {
	if t == nil {
		return nil, ErrRuntimeController
	}
	c := t.controller.Load()
	if c == nil {
		return nil, ErrRuntimeController
	}
	return c.exchangeResolverDNS(ctx, config, endpoint, payload)
}

func (t *DNSRuntimeTransport) ValidateDNSPath(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint) error {
	if t == nil {
		return ErrRuntimeController
	}
	c := t.controller.Load()
	if c == nil {
		return ErrRuntimeController
	}
	_, err := c.proveResolverDNS(ctx, config, endpoint)
	return err
}

type runtimeDNSProof struct {
	DeliveryID           uuid.UUID
	Identity             PermitLeaseIdentity
	Binding              DNSResolverBinding
	Source               netip.Addr
	Resolver             netip.Addr
	Slot                 uint8
	InterfaceIndex       int
	SourceInterfaceIndex int
	Namespace            string
	epoch                *runtimeDNSEpoch
	authority            *PermitLeaseAuthority
}

func (c *RuntimeController) exchangeResolverDNS(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection := uuid.Nil
	if config.IPsecPath != nil {
		connection, _ = uuid.Parse(config.IPsecPath.ConnectionID)
	}
	return exchangeResolverDNSObserved(ctx, config, endpoint, payload, c.proveResolverDNS, fqdnrpc.ExchangeBoundSocket, func(stage string, started time.Time, refused bool) {
		c.emitRuntimeDiagnostic(ctx, "dns_exchange", stage, connection, started, refused)
	})
}

// The composition is private and preserves the existing two native proofs and
// socket sequence. Diagnostics carry fixed phases and timing only.
func exchangeResolverDNSObserved(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, payload []byte, prove func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint) (runtimeDNSProof, error), exchange func(context.Context, fqdnrpc.ResolverEndpoint, netip.Addr, []byte) ([]byte, error), emit func(string, time.Time, bool)) ([]byte, error) {
	started := time.Now()
	proof, err := prove(ctx, config, endpoint)
	emit("dns_proof_before", started, err != nil)
	if err != nil {
		return nil, ErrRuntimeController
	}
	started = time.Now()
	response, err := exchange(ctx, endpoint, proof.Source, payload)
	emit("dns_socket", started, err != nil)
	if err != nil {
		return nil, ErrRuntimeController
	}
	started = time.Now()
	after, err := prove(ctx, config, endpoint)
	refused := err != nil || !sameResolverDNSProof(after, proof) || ctx.Err() != nil
	emit("dns_proof_after", started, refused)
	if refused {
		return nil, ErrRuntimeController
	}
	return response, nil
}

func sameResolverDNSProof(a, b runtimeDNSProof) bool {
	current, original := a.authority, b.authority
	a.authority, b.authority = nil, nil
	if a != b || current == nil || original == nil || b.epoch == nil || b.epoch.revoked.Load() {
		return false
	}
	if _, err := original.RemainingForApply(b.Identity, time.Second); err != nil {
		return false
	}
	_, err := current.RemainingForApply(a.Identity, time.Second)
	return err == nil && !b.epoch.revoked.Load()
}

// proveResolverDNS is read-only. All packet authority remains in the existing
// independent kernel lease sets; a DNS observation never extends their TTL.
func (c *RuntimeController) proveResolverDNS(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint) (runtimeDNSProof, error) {
	fail := func() (runtimeDNSProof, error) { return runtimeDNSProof{}, ErrRuntimeController }
	if c == nil || config.IPsecPath == nil || !fqdnrpc.ValidResolverConfig(config) || endpoint.Port != 53 || endpoint.Transport != "udp" && endpoint.Transport != "tcp" {
		return fail()
	}
	listed := false
	for _, e := range config.Endpoints {
		if e.Address == endpoint.Address && e.Port == 53 {
			listed = true
		}
	}
	if !listed {
		return fail()
	}
	conn, ce := uuid.Parse(config.IPsecPath.ConnectionID)
	cfg, ge := uuid.Parse(config.ID)
	profile, pe := uuid.Parse(config.ProfileID)
	source, se := netip.ParseAddr(config.IPsecPath.SourceAddress)
	resolver, re := netip.ParseAddr(endpoint.Address)
	if ce != nil || ge != nil || pe != nil || se != nil || re != nil || !source.Is4() || !resolver.Is4() {
		return fail()
	}
	binding := DNSResolverBinding{cfg, config.Version, profile, conn, config.IPsecPath.ConfigurationRevision}
	if !binding.valid() {
		return fail()
	}
	// Only immutable owner-selected inputs are loaded here. The serial owner may
	// be blocked on unrelated IO; no global mutex or journal mutex is acquired.
	view := c.dnsView.Load()
	if view == nil || ctx.Err() != nil {
		return fail()
	}
	owner, ok := view.entries[conn]
	if !ok || owner.epoch.revoked.Load() || !view.observer.qualification.current() || view.observer.controller.config.DaemonAlive == nil || !view.observer.controller.config.DaemonAlive() {
		return fail()
	}
	a := owner.active
	if a.Authority == nil || a.Entry.Phase != RuntimeApplied || a.Identity.Binding.OrgID != view.observer.controller.config.OrgID || a.Identity.Binding.GatewayID != view.observer.controller.config.GatewayID || a.Identity.Binding.ConnectionID != conn || a.Identity.Binding.ConfigurationRevision != binding.ConfigurationRevision {
		return fail()
	}
	protocol := GuardUDP
	if endpoint.Transport == "tcp" {
		protocol = GuardTCP
	}
	authorized := false
	for _, g := range a.Grants {
		if g.DNSResolver == binding && g.HostOrigin && !g.FQDNManaged && g.Source == netip.PrefixFrom(source, 32) && g.Destination == netip.PrefixFrom(resolver, 32) && g.Protocol == protocol && g.PortLow == 53 && g.PortHigh == 53 {
			authorized = true
		}
	}
	if !authorized {
		return fail()
	}
	if _, err := a.Authority.RemainingForApply(a.Identity, time.Second); err != nil {
		return fail()
	}
	if view.observer.controller.proveCurrent(ctx, a.Entry, a.Environment) != nil {
		return fail()
	}
	slot := dnsResolverSlot(a.Entry, resolver)
	if slot < 1 || slot > 2 {
		return fail()
	}
	index := a.Entry.Observed[slot-1].InterfaceIndex
	revalidationUsed := false
	if index <= 0 {
		return fail()
	}
	if permitted, fullRead := view.resolverGuardPermitsRead(ctx, a.Entry, index, a.Entry.Engines[slot-1].ReqID); !permitted {
		if !fullRead || c.revalidateDNSGuardSnapshotDigest(ctx, conn, owner, view, a.Entry, index, a.Entry.Engines[slot-1].ReqID) == "" {
			return fail()
		}
		revalidationUsed = true
	}
	before, err := view.observer.source(source, a.Environment.LocalIngressIndices)
	if err != nil {
		return fail()
	}
	raw, err := view.observer.route(ctx, view.observer.controller.config.IPPath, "-j", "-4", "route", "get", resolver.String(), "from", source.String())
	if err != nil || !dnsResolverRouteMatches(raw, a.Entry.Observed[slot-1].InterfaceName, source, resolver) {
		return fail()
	}
	after, err := view.observer.source(source, a.Environment.LocalIngressIndices)
	if err != nil || before != after || ctx.Err() != nil || !view.observer.qualification.current() || !view.observer.controller.config.DaemonAlive() {
		return fail()
	}
	if _, err := a.Authority.RemainingForApply(a.Identity, time.Second); err != nil {
		return fail()
	}
	if _, ok := c.currentDNSOwnerEntry(conn, owner); !ok {
		return fail()
	}
	latest := c.dnsView.Load()
	if latest == nil {
		return fail()
	}
	// Initial and final reads share one supersession retry. Both the original
	// owner/authority and the current native template must remain unchanged.
	checkedDigest := latest.guard.Digest
	if latest.guard.Digest != view.guard.Digest {
		permitted, fullRead := latest.resolverGuardPermitsRead(ctx, a.Entry, index, a.Entry.Engines[slot-1].ReqID)
		current := c.dnsView.Load()
		if !permitted || current == nil || current.guard.Digest != checkedDigest {
			if revalidationUsed || !permitted && !fullRead {
				return fail()
			}
			checkedDigest = c.revalidateDNSGuardSnapshotDigest(ctx, conn, owner, latest, a.Entry, index, a.Entry.Engines[slot-1].ReqID)
			if checkedDigest == "" {
				return fail()
			}
			revalidationUsed = true
		}
	}
	if _, ok := c.currentDNSOwnerEntry(conn, owner); !ok || ctx.Err() != nil {
		return fail()
	}
	current := c.dnsView.Load()
	if current == nil || current.guard.Digest != checkedDigest {
		return fail()
	}
	return runtimeDNSProof{DeliveryID: a.Entry.DeliveryID, Identity: a.Identity, Binding: binding, Source: source, Resolver: resolver, Slot: slot, InterfaceIndex: index, SourceInterfaceIndex: before, Namespace: a.Entry.Allocation.Namespace, epoch: owner.epoch, authority: a.Authority}, nil
}

func (c *RuntimeController) lockDNSController(ctx context.Context) bool {
	for ctx.Err() == nil {
		if c.mu.TryLock() {
			return true
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	return false
}

func dnsResolverSlot(entry RuntimeJournalEntry, resolver netip.Addr) uint8 {
	if entry.ContractVersion != 3 {
		return selectedRuntimeSlot(entry)
	}
	if entry.BGPRoutes == nil || entry.BGPRoutes.Stage != "completed" || entry.BGPRoutes.Withdrawal || !validBGPRoutes(entry) {
		return 0
	}
	slot := uint8(0)
	longest := -1
	for _, r := range entry.BGPRoutes.Owned {
		if r.Prefix.Contains(resolver) && r.Prefix.Bits() > longest {
			longest = r.Prefix.Bits()
			slot = r.Slot
		}
	}
	return slot
}

func observeDNSSource(source netip.Addr, allowed []int) (int, error) {
	links, err := net.Interfaces()
	if err != nil {
		return 0, ErrRuntimeController
	}
	found := 0
	for _, link := range links {
		// An explicitly configured private /32 may be assigned to loopback by
		// the operator. It is still observed in this exact namespace; the
		// material admission separately confines it to approved local prefixes.
		// No address is created or adopted from a DNS request.
		approved := link.Flags&net.FlagLoopback != 0
		for _, i := range allowed {
			if i == link.Index {
				approved = true
			}
		}
		if !approved || link.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			return 0, ErrRuntimeController
		}
		for _, address := range addresses {
			p, err := netip.ParsePrefix(address.String())
			if err == nil && p.Addr().Unmap() == source {
				if found != 0 {
					return 0, ErrRuntimeController
				}
				found = link.Index
			}
		}
	}
	if found == 0 {
		return 0, ErrRuntimeController
	}
	return found, nil
}

func dnsResolverRouteMatches(raw []byte, wantInterface string, source, resolver netip.Addr) bool {
	rows, ok := kernelObjects(raw)
	if !ok || len(rows) != 1 {
		return false
	}
	row := rows[0]
	dev, ok := kernelString(row, "dev")
	if !ok || dev != wantInterface {
		return false
	}
	if destination, ok := kernelString(row, "dst"); !ok || destination != resolver.String() {
		return false
	}
	if _, gateway := row["gateway"]; gateway {
		return false
	}
	if table, exists := row["table"]; exists {
		if string(table) != "254" && string(table) != "\"main\"" {
			return false
		}
	}
	if _, exists := row["from"]; exists {
		value, ok := kernelString(row, "from")
		if !ok || value != source.String() {
			return false
		}
	} else {
		return false
	}
	if preferred, exists := row["prefsrc"]; exists {
		var value string
		if json.Unmarshal(preferred, &value) != nil || value != source.String() {
			return false
		}
	}
	return true
}

func (v *runtimeDNSOwnerView) resolverGuardPermits(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32) bool {
	permitted, _ := v.resolverGuardPermitsRead(ctx, entry, index, reqid)
	return permitted
}

func (v *runtimeDNSOwnerView) resolverGuardPermitsRead(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32) (bool, bool) {
	if v == nil || v.observer.guardReader == nil {
		return false, false
	}
	g := v.guard
	if g.Namespace != entry.Allocation.Namespace {
		return false, false
	}
	objects, ok := normalizedGuardObjects([]byte(g.ExpectedJSON))
	if !ok {
		return false, false
	}
	required := map[string]string{guardLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardReplyLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardSALeaseName(entry.Allocation.ConnectionID): strconv.FormatUint(uint64(reqid), 10)}
	for _, object := range objects {
		fields, ok := object.(map[string]any)
		if !ok {
			return false, false
		}
		set, ok := fields["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := set["name"].(string)
		want, needed := required[name]
		if !needed {
			continue
		}
		members, ok := set["elem"].([]any)
		if !ok {
			return false, false
		}
		found := false
		for _, m := range members {
			member, ok := m.(map[string]any)
			if !ok {
				return false, false
			}
			element, ok := member["elem"].(map[string]any)
			if !ok {
				return false, false
			}
			value, ok := element["val"].(json.Number)
			if !ok {
				return false, false
			}
			if value.String() == want {
				found = true
			}
		}
		if !found {
			return false, false
		}
		delete(required, name)
	}
	if len(required) != 0 {
		return false, false
	}
	return v.observer.guardReader.checkConnection(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}, entry.Allocation.ConnectionID) == nil, true
}

// Retry only a different independently published immutable guard, once. The
// caller retains its original owner epoch and lease; no authority is renewed.
func (c *RuntimeController) revalidateDNSGuardSnapshotDigest(ctx context.Context, connection uuid.UUID, owner runtimeDNSOwnerEntry, previous *runtimeDNSOwnerView, entry RuntimeJournalEntry, index int, reqid uint32) string {
	if c == nil || previous == nil || ctx.Err() != nil {
		return ""
	}
	latest := c.dnsView.Load()
	if latest == nil || latest.guard.Digest == previous.guard.Digest {
		return ""
	}
	if _, ok := c.currentDNSOwnerEntry(connection, owner); !ok {
		return ""
	}
	if !latest.resolverGuardPermits(ctx, entry, index, reqid) {
		return ""
	}
	current := c.dnsView.Load()
	if current == nil || current.guard.Digest != latest.guard.Digest {
		return ""
	}
	if _, ok := c.currentDNSOwnerEntry(connection, owner); !ok || ctx.Err() != nil {
		return ""
	}
	return latest.guard.Digest
}
