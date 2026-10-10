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

func (c *RuntimeController) exchangeResolverDNS(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, payload []byte) (response []byte, resultErr error) {
	stage, started := "dns_before_proof", time.Now()
	if c != nil && c.config.DNSReadTiming {
		defer func() { fqdnrpc.RecordLookupExchange(ctx, resultErr == nil) }()
	}
	connection := uuid.Nil
	if config.IPsecPath != nil {
		connection, _ = uuid.Parse(config.IPsecPath.ConnectionID)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var socketTiming runtimeDNSReadTiming
	defer func() {
		c.emitDNSRuntimeDiagnostic(ctx, "dns_exchange", stage, connection, started, resultErr != nil, socketTiming)
	}()
	var proofStarted time.Time
	if c.config.DNSReadTiming {
		proofStarted = time.Now()
	}
	proof, err := c.proveResolverDNSStage(ctx, config, endpoint, "dns_before_proof")
	if c.config.DNSReadTiming {
		fqdnrpc.RecordLookupPhase(ctx, "before", time.Since(proofStarted), err == nil)
	}
	if err != nil {
		return nil, ErrRuntimeController
	}
	stage = "dns_socket_udp"
	if endpoint.Transport == "tcp" {
		stage = "dns_socket_tcp"
	}
	response, err = fqdnrpc.ExchangeBoundSocketObserved(ctx, endpoint, proof.Source, payload, func(outcome fqdnrpc.SocketOutcome) {
		if c.config.DNSReadTiming {
			fqdnrpc.RecordLookupPhase(ctx, "socket", outcome.Elapsed, outcome.Stage == fqdnrpc.SocketComplete && !outcome.Failed)
			socketTiming.SocketMillis = outcome.Elapsed.Milliseconds()
			switch outcome.Stage {
			case fqdnrpc.SocketInput, fqdnrpc.SocketDial, fqdnrpc.SocketWrite, fqdnrpc.SocketBody, fqdnrpc.SocketLength, fqdnrpc.SocketComplete:
				socketTiming.SocketStage = string(outcome.Stage)
			}
		}
		if endpoint.Transport != "tcp" {
			return
		}
		switch outcome.Stage {
		case fqdnrpc.SocketInput:
			stage = "dns_socket_tcp_input"
		case fqdnrpc.SocketDial:
			stage = "dns_socket_tcp_dial"
		case fqdnrpc.SocketWrite:
			stage = "dns_socket_tcp_write"
		case fqdnrpc.SocketLength:
			stage = "dns_socket_tcp_length"
		case fqdnrpc.SocketBody:
			stage = "dns_socket_tcp_body"
		case fqdnrpc.SocketComplete:
			stage = "dns_socket_tcp_complete"
		}
	})
	if err != nil {
		return nil, ErrRuntimeController
	}
	stage = "dns_after_proof"
	if c.config.DNSReadTiming {
		proofStarted = time.Now()
	}
	after, err := c.proveResolverDNSStage(ctx, config, endpoint, "dns_after_proof")
	if c.config.DNSReadTiming {
		fqdnrpc.RecordLookupPhase(ctx, "after", time.Since(proofStarted), err == nil)
	}
	if err != nil {
		return nil, ErrRuntimeController
	}
	stage = "dns_after_binding"
	if !sameResolverDNSProof(after, proof) || ctx.Err() != nil {
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
	return c.proveResolverDNSStage(ctx, config, endpoint, "dns_proof")
}
func (c *RuntimeController) proveResolverDNSStage(ctx context.Context, config fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, operation string) (result runtimeDNSProof, resultErr error) {
	stage, started := "dns_input", time.Now()
	connection := uuid.Nil
	var guardTiming runtimeDNSReadTiming
	var observeGuard func(guardReadTiming)
	var observeRevalidation func(string)
	var observeNative func(string)
	var observeNativeTiming func(runtimeNativePhaseTiming)
	if c != nil && c.config.DNSReadTiming {
		observeNativeTiming = func(phases runtimeNativePhaseTiming) { guardTiming.Native = phases }
		observeNative = func(reason string) { guardTiming.NativeFailureClass = reason }
		observeRevalidation = func(reason string) { guardTiming.GuardRevalidation = reason }
		observeGuard = func(t guardReadTiming) {
			guardTiming.GuardBracketCount++
			guardTiming.GuardCommandMillis = t.CommandMillis
			guardTiming.GuardVerificationMillis = t.VerificationMillis
			guardTiming.GuardFailureClass = t.FailureClass
		}
	}
	defer func() {
		c.emitDNSRuntimeDiagnostic(ctx, operation, stage, connection, started, resultErr != nil, guardTiming)
	}()
	fail := func() (runtimeDNSProof, error) { return runtimeDNSProof{}, ErrRuntimeController }
	if c == nil || config.IPsecPath == nil || !fqdnrpc.ValidResolverConfig(config) || endpoint.Port != 53 || endpoint.Transport != "udp" && endpoint.Transport != "tcp" {
		return fail()
	}
	stage = "dns_endpoint"
	listed := false
	for _, e := range config.Endpoints {
		if e.Address == endpoint.Address && e.Port == 53 {
			listed = true
		}
	}
	if !listed {
		return fail()
	}
	stage = "dns_binding"
	conn, ce := uuid.Parse(config.IPsecPath.ConnectionID)
	connection = conn
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
	stage = "dns_owner"
	view := c.dnsView.Load()
	if view == nil || ctx.Err() != nil {
		return fail()
	}
	owner, ok := view.entries[conn]
	if !ok || owner.epoch.revoked.Load() || !view.observer.qualification.current() || view.observer.controller.config.DaemonAlive == nil || !view.observer.controller.config.DaemonAlive() {
		return fail()
	}
	stage = "dns_authority"
	a := owner.active
	if a.Authority == nil || a.Entry.Phase != RuntimeApplied || a.Identity.Binding.OrgID != view.observer.controller.config.OrgID || a.Identity.Binding.GatewayID != view.observer.controller.config.GatewayID || a.Identity.Binding.ConnectionID != conn || a.Identity.Binding.ConfigurationRevision != binding.ConfigurationRevision {
		return fail()
	}
	protocol := GuardUDP
	if endpoint.Transport == "tcp" {
		protocol = GuardTCP
	}
	stage = "dns_grant"
	authorized := false
	for _, g := range a.Grants {
		if g.DNSResolver == binding && g.HostOrigin && !g.FQDNManaged && g.Source == netip.PrefixFrom(source, 32) && g.Destination == netip.PrefixFrom(resolver, 32) && g.Protocol == protocol && g.PortLow == 53 && g.PortHigh == 53 {
			authorized = true
		}
	}
	if !authorized {
		return fail()
	}
	stage = "dns_original_lease"
	if _, err := a.Authority.RemainingForApply(a.Identity, time.Second); err != nil {
		return fail()
	}
	stage = "dns_native_proof"
	if view.observer.controller.proveCurrentTimed(ctx, a.Entry, a.Environment, observeNative, observeNativeTiming) != nil {
		return fail()
	}
	stage = "dns_route_slot"
	slot := dnsResolverSlot(a.Entry, resolver)
	if slot < 1 || slot > 2 {
		return fail()
	}
	stage = "dns_guard"
	revalidationUsed := false
	index := a.Entry.Observed[slot-1].InterfaceIndex
	if index <= 0 {
		return fail()
	}
	if permitted, guardStage := view.resolverGuardPermitsStageObserved(ctx, a.Entry, index, a.Entry.Engines[slot-1].ReqID, observeGuard); !permitted {
		stage = guardStage
		// A committed renewal may supersede this loaded template. Try exactly one
		// current immutable template, retaining the original owner/lease/epoch.
		if guardStage != "dns_guard_full_read" || c.revalidateDNSGuardSnapshotDigestReason(ctx, conn, owner, view, a.Entry, index, a.Entry.Engines[slot-1].ReqID, observeGuard, observeRevalidation) == "" {
			return fail()
		}
		revalidationUsed = true
	}
	stage = "dns_source_before"
	before, err := view.observer.source(source, a.Environment.LocalIngressIndices)
	if err != nil {
		return fail()
	}
	stage = "dns_route"
	raw, err := view.observer.route(ctx, view.observer.controller.config.IPPath, "-j", "-4", "route", "get", resolver.String(), "from", source.String())
	if err != nil || !dnsResolverRouteMatches(raw, a.Entry.Observed[slot-1].InterfaceName, source, resolver) {
		return fail()
	}
	stage = "dns_source_after"
	after, err := view.observer.source(source, a.Environment.LocalIngressIndices)
	if err != nil || before != after || ctx.Err() != nil || !view.observer.qualification.current() || !view.observer.controller.config.DaemonAlive() {
		return fail()
	}
	stage = "dns_current_lease"
	if _, err := a.Authority.RemainingForApply(a.Identity, time.Second); err != nil {
		return fail()
	}
	stage = "dns_epoch"
	if _, ok := c.currentDNSOwnerEntry(conn, owner); !ok {
		return fail()
	}
	stage = "dns_latest_guard"
	latest := c.dnsView.Load()
	if latest == nil {
		return fail()
	}
	// The final read must bind a stable published template. The entire proof
	// shares one supersession retry, including the earlier native guard read.
	checkedDigest := latest.guard.Digest
	if latest.guard.Digest != view.guard.Digest {
		permitted, guardStage := latest.resolverGuardPermitsStageObserved(ctx, a.Entry, index, a.Entry.Engines[slot-1].ReqID, observeGuard)
		current := c.dnsView.Load()
		stable := current != nil && current.guard.Digest == checkedDigest
		if !permitted || !stable {
			stage = "dns_latest_guard_stability"
			if !permitted {
				stage = "dns_latest_" + guardStage[len("dns_"):]
			}
			if revalidationUsed || !permitted && guardStage != "dns_guard_full_read" {
				return fail()
			}
			checkedDigest = c.revalidateDNSGuardSnapshotDigestReason(ctx, conn, owner, latest, a.Entry, index, a.Entry.Engines[slot-1].ReqID, observeGuard, observeRevalidation)
			if checkedDigest == "" {
				return fail()
			}
			revalidationUsed = true
		}
	}
	stage = "dns_epoch"
	if _, ok := c.currentDNSOwnerEntry(conn, owner); !ok || ctx.Err() != nil {
		return fail()
	}
	stage = "dns_latest_guard_stability"
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
	permitted, _ := v.resolverGuardPermitsStage(ctx, entry, index, reqid)
	return permitted
}
func (v *runtimeDNSOwnerView) resolverGuardPermitsStage(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32) (bool, string) {
	return v.resolverGuardPermitsStageObserved(ctx, entry, index, reqid, nil)
}
func (v *runtimeDNSOwnerView) resolverGuardPermitsStageObserved(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32, observe func(guardReadTiming)) (bool, string) {
	stage := "dns_guard_template"
	if v == nil || v.observer.guardReader == nil {
		return false, stage
	}
	g := v.guard
	if g.Namespace != entry.Allocation.Namespace {
		return false, stage
	}
	objects, ok := normalizedGuardObjects([]byte(g.ExpectedJSON))
	if !ok {
		return false, stage
	}
	stage = "dns_guard_required"
	required := map[string]string{guardLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardReplyLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardSALeaseName(entry.Allocation.ConnectionID): strconv.FormatUint(uint64(reqid), 10)}
	for _, object := range objects {
		fields, ok := object.(map[string]any)
		if !ok {
			return false, stage
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
			return false, stage
		}
		found := false
		for _, m := range members {
			member, ok := m.(map[string]any)
			if !ok {
				return false, stage
			}
			element, ok := member["elem"].(map[string]any)
			if !ok {
				return false, stage
			}
			value, ok := element["val"].(json.Number)
			if !ok {
				return false, stage
			}
			if value.String() == want {
				found = true
			}
		}
		if !found {
			return false, stage
		}
		delete(required, name)
	}
	if len(required) != 0 {
		return false, stage
	}
	return v.observer.guardReader.checkConnectionSnapshotObserved(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}, entry.Allocation.ConnectionID, guardExpectedSnapshot{raw: g.ExpectedJSON, objects: objects}, observe) == nil, "dns_guard_full_read"
}

// revalidateDNSGuardSnapshot retries only an independently published newer
// template once. It cannot manufacture a grant, change owner epoch, extend
// original/current authority, or continue through another digest change.
func (c *RuntimeController) revalidateDNSGuardSnapshot(ctx context.Context, connection uuid.UUID, owner runtimeDNSOwnerEntry, previous *runtimeDNSOwnerView, entry RuntimeJournalEntry, index int, reqid uint32) bool {
	return c.revalidateDNSGuardSnapshotDigest(ctx, connection, owner, previous, entry, index, reqid) != ""
}

func (c *RuntimeController) revalidateDNSGuardSnapshotDigest(ctx context.Context, connection uuid.UUID, owner runtimeDNSOwnerEntry, previous *runtimeDNSOwnerView, entry RuntimeJournalEntry, index int, reqid uint32) string {
	return c.revalidateDNSGuardSnapshotDigestObserved(ctx, connection, owner, previous, entry, index, reqid, nil)
}
func (c *RuntimeController) revalidateDNSGuardSnapshotDigestObserved(ctx context.Context, connection uuid.UUID, owner runtimeDNSOwnerEntry, previous *runtimeDNSOwnerView, entry RuntimeJournalEntry, index int, reqid uint32, observe func(guardReadTiming)) string {
	return c.revalidateDNSGuardSnapshotDigestReason(ctx, connection, owner, previous, entry, index, reqid, observe, nil)
}

func (c *RuntimeController) revalidateDNSGuardSnapshotDigestReason(ctx context.Context, connection uuid.UUID, owner runtimeDNSOwnerEntry, previous *runtimeDNSOwnerView, entry RuntimeJournalEntry, index int, reqid uint32, observe func(guardReadTiming), reason func(string)) string {
	mark := func(value string) {
		if reason != nil {
			reason(value)
		}
	}
	if c == nil || previous == nil || ctx.Err() != nil {
		mark("input_refused")
		if ctx.Err() != nil {
			mark("context_inactive")
		}
		return ""
	}
	latest := c.dnsView.Load()
	if latest == nil {
		mark("latest_absent")
		return ""
	}
	if latest.guard.Digest == previous.guard.Digest {
		if !c.awaitDNSPublication(ctx, previous) {
			mark("latest_unchanged")
			if ctx.Err() != nil {
				mark("context_inactive")
			}
			return ""
		}
		latest = c.dnsView.Load()
		if latest == nil {
			mark("latest_absent")
			return ""
		}
		if latest.guard.Digest == previous.guard.Digest {
			mark("latest_unchanged")
			return ""
		}
	}
	if _, ok := c.currentDNSOwnerEntry(connection, owner); !ok {
		mark("owner_entry_refused")
		return ""
	}
	if permitted, _ := latest.resolverGuardPermitsStageObserved(ctx, entry, index, reqid, observe); !permitted {
		mark("latest_guard_refused")
		if ctx.Err() != nil {
			mark("context_inactive")
		}
		return ""
	}
	current := c.dnsView.Load()
	if current == nil || current.guard.Digest != latest.guard.Digest {
		mark("digest_changed_again")
		return ""
	}
	if _, ok := c.currentDNSOwnerEntry(connection, owner); !ok || ctx.Err() != nil {
		mark("final_owner_entry_refused")
		if ctx.Err() != nil {
			mark("context_inactive")
		}
		return ""
	}
	mark("accepted")
	return latest.guard.Digest
}
