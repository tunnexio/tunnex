package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func sharedReaderPhase() string {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		for _, name := range []string{"refreshIPsecActiveRecoveryLocked", "installActiveCandidates", "maintenanceCurrentWithNativeProof"} {
			if strings.Contains(frame.Function, name) {
				return name
			}
		}
		if !more {
			break
		}
	}
	return "other"
}

type sharedStaticObservation interface {
	observeAndProveRecoveryWithReaders(context.Context, RuntimeJournalEntry, RuntimeEnvironment, runtimeStatusReaders) ([2]string, error)
}

type sharedIndependentNativeReaders interface {
	proveRuntimeWithIndependentReaders(context.Context, RuntimeJournalEntry, RuntimeEnvironment, runtimeStatusReaders) error
	observeAndProveRecoveryWithIndependentReaders(context.Context, RuntimeJournalEntry, RuntimeEnvironment, runtimeStatusReaders) ([2]string, error)
}

// Exercise the production decoders and read command/request shapes. Each
// complete pass has six VICI requests, two kernel commands and two key-free
// XFRM commands; the unchanged 100ms primitive charge makes a pair cost 2s.
func sharedParsedReaders(t *testing.T, d DaemonInventory, k KernelInventory, x XFRMInventory, charge func(string), alive func() bool) runtimeStatusReaders {
	t.Helper()
	events := []viciMessage{}
	for index, sa := range d.SAs {
		children := viciMessage{}
		for j, child := range sa.Children {
			local, remote := []string{}, []string{}
			for _, p := range child.LocalPrefixes {
				local = append(local, p.String())
			}
			for _, p := range child.RemotePrefixes {
				remote = append(remote, p.String())
			}
			children[fmt.Sprintf("child-%d", j+1)] = viciSection(viciMessage{
				"name": viciText(child.Name), "uniqueid": viciText(strconv.Itoa(index*2 + j + 1)), "reqid": viciText(strconv.FormatUint(uint64(child.ReqID), 10)),
				"state": viciText("INSTALLED"), "mode": viciText("TUNNEL"), "protocol": viciText("ESP"),
				"if-id-in": viciText(fmt.Sprintf("%08x", child.IfIDIn)), "if-id-out": viciText(fmt.Sprintf("%08x", child.IfIDOut)),
				"spi-in": viciText(fmt.Sprintf("%08x", child.SPIIn)), "spi-out": viciText(fmt.Sprintf("%08x", child.SPIOut)),
				"local-ts": viciList(local...), "remote-ts": viciList(remote...), "encr-alg": viciText("AES_CBC"),
				"encr-keysize": viciText("256"), "integ-alg": viciText("HMAC_SHA2_256_128"), "bytes-in": viciText("0"), "bytes-out": viciText("0"),
			})
		}
		events = append(events, viciMessage{sa.Name: viciSection(viciMessage{"uniqueid": viciText(strconv.Itoa(index + 1)), "version": viciText("2"), "state": viciText("ESTABLISHED"), "local-host": viciText(sa.LocalAddress.String()), "remote-host": viciText(sa.RemoteAddress.String()), "child-sas": viciSection(children)})})
	}
	mutations := 0
	daemon := daemonInventoryStub(events, viciMessage{}, &mutations)
	request := daemon.request
	daemon.request = func(ctx context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		charge("vici_" + command)
		return request(ctx, command, event, m)
	}
	// The same immutable read-only request fixture uses the production
	// trusted-client factory when present; legacy sources remain serial.
	if factory, ok := any(daemon).(interface{ independentReadClient() *DaemonClient }); ok {
		daemon = factory.independentReadClient()
	}
	links, routes := []map[string]any{}, []map[string]any{}
	names := map[int]string{}
	for _, link := range k.Links {
		flags := []string{}
		if link.Up {
			flags = append(flags, "UP")
		}
		names[link.Index] = link.Name
		links = append(links, map[string]any{"ifindex": link.Index, "ifname": link.Name, "flags": flags, "linkinfo": map[string]any{"info_kind": "xfrm", "info_data": map[string]any{"if_id": fmt.Sprintf("0x%x", link.XFRMID)}}})
	}
	for _, route := range k.Routes {
		routes = append(routes, map[string]any{"type": strconv.Itoa(int(route.Kind)), "dst": route.Destination.String(), "dev": names[route.OutputInterface], "table": strconv.FormatUint(uint64(route.Table), 10), "protocol": strconv.Itoa(int(route.Protocol)), "scope": strconv.Itoa(int(route.Scope)), "metric": route.Metric, "flags": []string{}})
	}
	linkJSON, _ := json.Marshal(links)
	routeJSON, _ := json.Marshal(routes)
	kr := &KernelReader{namespace: func() (string, error) { return k.Namespace, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j -d link show":
			charge("kernel_links")
			return linkJSON, nil
		case "-j -d -N -4 route show table all":
			charge("kernel_routes")
			return routeJSON, nil
		default:
			t.Fatal("unexpected kernel mutation command", args)
			return nil, ErrKernelRead
		}
	}}
	var states, policies strings.Builder
	for _, s := range x.States {
		fmt.Fprintf(&states, "src %s dst %s\n proto esp spi 0x%x reqid %d mode tunnel\n replay-window 32 flag af-unspec\n auth-trunc hmac(sha256) <<Keys hidden>> 128\n enc cbc(aes) <<Keys hidden>>\n anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000\n if_id 0x%x\n", s.Source, s.Destination, s.SPI, s.ReqID, s.IfID)
	}
	for i, p := range x.Policies {
		fmt.Fprintf(&policies, "src %s dst %s\n dir %s priority %d ptype main\n tmpl src %s dst %s\n proto esp reqid %d mode tunnel\n if_id 0x%x\n", p.Source, p.Destination, p.Direction, 10000+i, p.TemplateSource, p.TemplateDestination, p.ReqID, p.IfID)
	}
	xr := &XFRMReader{namespace: func() (string, error) { return x.Namespace, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "xfrm state list nokeys":
			charge("xfrm_nokeys")
			return []byte(states.String()), nil
		case "xfrm policy list nosock":
			charge("xfrm_nosock")
			return []byte(policies.String()), nil
		default:
			t.Fatal("unexpected XFRM command", args)
			return nil, ErrXFRMRead
		}
	}}
	if _, err := ParseXFRMInventory(x.Namespace, []byte(states.String()), []byte(policies.String())); err != nil {
		t.Fatal("synthetic complete XFRM encoding invalid", err, len(x.States), len(x.Policies))
	}
	t.Cleanup(func() {
		if mutations != 0 {
			t.Error("daemon fixture mutated native state")
		}
	})
	return runtimeStatusReaders{daemon: daemon.Inspect, kernel: kr.Read, xfrm: xr.Read, alive: alive}
}

// Construct complete independent inventories for the canonical owned entry.
// This is the same structure used by runtimeProofFixture, including the actual
// selected route. A configured spare may be absent without fabricating UP.
func sharedStaticInventories(e RuntimeJournalEntry, absentSlot int) (DaemonInventory, KernelInventory, XFRMInventory) {
	d := DaemonInventory{}
	k := KernelInventory{Namespace: e.Allocation.Namespace}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	for i, t := range e.Engines {
		own := e.Observed[i]
		k.Links = append(k.Links, KernelLink{Name: own.InterfaceName, Index: own.InterfaceIndex, XFRMID: own.XFRMID, Up: i+1 != absentSlot})
		if i+1 == absentSlot {
			continue
		}
		child := DaemonChild{Name: engineName(t), UniqueID: uint64(i + 1), ReqID: t.ReqID, IfIDIn: t.XFRMID, IfIDOut: t.XFRMID, SPIIn: t.ReqID, SPIOut: ^t.ReqID, Installed: true, LocalPrefixes: engineTransportPrefixes(t, true), RemotePrefixes: engineTransportPrefixes(t, false)}
		d.SAs = append(d.SAs, DaemonIKE{Name: engineName(t), UniqueID: uint64(i + 1), Established: true, LocalAddress: t.LocalAddress, RemoteAddress: t.RemoteAddress, Children: []DaemonChild{child}})
		x.States = append(x.States, XFRMState{Source: t.LocalAddress, Destination: t.RemoteAddress, SPI: child.SPIOut, ReqID: t.ReqID, IfID: t.XFRMID}, XFRMState{Source: t.RemoteAddress, Destination: t.LocalAddress, SPI: child.SPIIn, ReqID: t.ReqID, IfID: t.XFRMID})
		for _, l := range engineTransportPrefixes(t, true) {
			for _, r := range engineTransportPrefixes(t, false) {
				for _, dir := range []string{"in", "fwd", "out"} {
					p := XFRMPolicy{Source: r, Destination: l, Direction: dir, ReqID: t.ReqID, IfID: t.XFRMID, TemplateSource: t.RemoteAddress, TemplateDestination: t.LocalAddress}
					if dir == "out" {
						p.Source, p.Destination, p.TemplateSource, p.TemplateDestination = l, r, t.LocalAddress, t.RemoteAddress
					}
					x.Policies = append(x.Policies, p)
				}
			}
		}
	}
	slot := selectedRuntimeSlot(e)
	if slot == 0 {
		if e.BGPRoutes != nil {
			for _, route := range e.BGPRoutes.Owned {
				k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: route.Prefix, Table: route.Table, Protocol: uint8(route.Protocol), Metric: route.Metric, OutputInterface: route.InterfaceIndex}})
			}
		}
		return d, k, x
	}
	for _, r := range e.Engines[0].RemotePrefixes {
		k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: r, Table: 254, Protocol: 242, Metric: 50000 + uint32(slot), OutputInterface: e.Observed[slot-1].InterfaceIndex}})
	}
	return d, k, x
}

// Every actual primitive reader has the same modeled cost on both sources.
// Six reads make one two-pass observation cost 2s. The 37.199s cloud diagnostic
// is only an aggregate comparison; this is not its measured call allocation.
func TestSharedStaticNativeReader35SecondContinuity(t *testing.T) {
	r, target := maintainedMissingStandby(t, 2)
	materials := maintenanceMaterials(r)
	sort.Slice(materials, func(i, j int) bool {
		return materials[i].Manifest.ConnectionID.String() < materials[j].Manifest.ConnectionID.String()
	})
	earliest := time.Duration(1<<63 - 1)
	for _, end := range r.installed {
		if end < earliest {
			earliest = end
		}
	}
	if earliest-*r.now < 35*time.Second {
		t.Fatal("genuine native deadline too short")
	}
	r.charge("forward_to_35s", earliest-*r.now-35*time.Second)
	start := *r.now
	r.charged = map[string]time.Duration{}
	old := map[*PermitLeaseAuthority]time.Duration{}
	for _, a := range r.c.active {
		old[a.Authority] = a.Authority.deadline
	}
	reads := map[string]int{}
	phaseReads := map[string]int{}
	phaseCosts := map[string]time.Duration{}
	var ioClock sync.Mutex
	wallStart := time.Now()
	lastWritten := start
	offset := time.Duration(0)
	syncIOClock := func() {
		offset += *r.now - lastWritten
		*r.now = start + time.Since(wallStart) + offset
		lastWritten = *r.now
	}
	lapse := false
	check := func() {
		if !allPriorityMembersLive(r) {
			lapse = true
		}
	}
	readers := func(e RuntimeJournalEntry) runtimeStatusReaders {
		absent := 0
		if e.Allocation.ConnectionID == target {
			absent = 1
		}
		d, k, x := sharedStaticInventories(e, absent)
		// Include all five owners in every complete namespace inventory.
		for _, other := range r.entries {
			if other.Allocation.ConnectionID == e.Allocation.ConnectionID {
				continue
			}
			missing := 0
			if other.Allocation.ConnectionID == target {
				missing = 1
			}
			od, ok, ox := sharedStaticInventories(other, missing)
			d.SAs = append(d.SAs, od.SAs...)
			k.Links = append(k.Links, ok.Links...)
			k.Routes = append(k.Routes, ok.Routes...)
			x.States = append(x.States, ox.States...)
			x.Policies = append(x.Policies, ox.Policies...)
		}
		if runtimeInventoryMatches(e, d, k, x) != nil {
			t.Fatal("complete fixture does not satisfy mandatory ownership proof", e.Allocation.ConnectionID)
		}
		phase := sharedReaderPhase()
		charge := func(name string) {
			// Every original primitive still incurs the SAME 100ms bounded
			// latency. Only independent reader overlap changes critical path.
			time.Sleep(100 * time.Millisecond)
			ioClock.Lock()
			syncIOClock()
			phaseReads[phase]++
			phaseCosts[phase] += 100 * time.Millisecond
			reads[name]++
			r.charged["actual_"+name+"_reader"] += 100 * time.Millisecond
			check()
			ioClock.Unlock()
		}
		return sharedParsedReaders(t, d, k, x, charge, r.c.config.DaemonAlive)
	}
	// Model the actual bounded operation through its reader seam. Existing
	// production test overrides remain untouched; no evidence is retained past
	// this exact context/entry/environment or into another callback/transaction.
	var pending *struct {
		ctx   context.Context
		entry RuntimeJournalEntry
		env   RuntimeEnvironment
		err   error
	}
	ordinaryProof := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		if e.ContractVersion != 2 {
			return ordinaryProof(ctx, e, env)
		}
		if pending != nil {
			p := pending
			pending = nil
			if p.ctx == ctx && reflect.DeepEqual(p.entry, e) && reflect.DeepEqual(p.env, env) {
				return p.err
			}
		}
		if independent, ok := any(r.c).(sharedIndependentNativeReaders); ok {
			return independent.proveRuntimeWithIndependentReaders(ctx, e, env, readers(e))
		}
		return r.c.proveRuntimeWithReaders(ctx, e, env, readers(e))
	}
	ordinaryStatus := r.c.recoveryObserve
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		if e.ContractVersion != 2 {
			return ordinaryStatus(ctx, e)
		}
		pending = nil
		if shared, ok := any(r.c).(sharedStaticObservation); ok {
			env := r.c.active[e.Allocation.ConnectionID].Environment
			var statuses [2]string
			var err error
			if independent, ok := any(r.c).(sharedIndependentNativeReaders); ok {
				statuses, err = independent.observeAndProveRecoveryWithIndependentReaders(ctx, e, env, readers(e))
			} else {
				statuses, err = shared.observeAndProveRecoveryWithReaders(ctx, e, env, readers(e))
			}
			pending = &struct {
				ctx   context.Context
				entry RuntimeJournalEntry
				env   RuntimeEnvironment
				err   error
			}{ctx, e, env, err}
			return statuses
		}
		return runtimeObservedStatuses(ctx, e, readers(e))
	}
	commits, callbacks, beforeCallbacks := 0, 0, 0
	firstCommit := time.Duration(0)
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		positive := false
		for _, g := range in.Connections {
			positive = positive || !g.PrefixOnly
		}
		if positive {
			ioClock.Lock()
			syncIOClock()
			check()
			ioClock.Unlock()
			if commits == 0 {
				firstCommit = *r.now - start
				beforeCallbacks = callbacks
			}
		}
		out, err := replace(ctx, in)
		if positive && err == nil {
			commits++
		}
		return out, err
	}
	pulse := func(context.Context, RuntimeRecoveryHeartbeat) error { callbacks++; pending = nil; check(); return nil }
	r.phase = "maintenance"
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { pending = nil; check(); return nil }, pulse)
	r.phase = ""
	ioClock.Lock()
	syncIOClock()
	check()
	ioClock.Unlock()
	for a, d := range old {
		if a.deadline != d {
			t.Fatal("original CP deadline extended")
		}
	}
	t.Logf("MODELED actual delayed readers serialpair=2s original5sreserve commit<30s unchanged primitivecost=%s nativeheadroom35s observedOuter37.199s firstCommit=%s elapsed=%s commits=%d callbacksBefore=%d callbacks=%d readers=%v all15Live=%t lapse=%t phaseReads=%v phaseCosts=%v costs=%v err=%v", 100*time.Millisecond, firstCommit, *r.now-start, commits, beforeCallbacks, callbacks, reads, allPriorityMembersLive(r), lapse, phaseReads, phaseCosts, r.charged, err)
	if err != nil || commits != 1 || beforeCallbacks == 0 || lapse || !allPriorityMembersLive(r) || firstCommit >= 30*time.Second {
		t.Fatal("actual-reader finite continuity failed")
	}
}

func TestSharedStaticNativeReaderRejectsUnsafeEvidence(t *testing.T) {
	for _, kind := range []string{"healthy", "spare_down", "selected_down", "before_unknown", "after_unknown", "status_change", "xfrm_change", "kernel_change", "environment_change", "read_error", "canceled", "daemon_dead"} {
		t.Run(kind, func(t *testing.T) {
			shared, ok := any(&RuntimeController{}).(sharedStaticObservation)
			if !ok {
				t.Skip("baseline has no shared-reader operation; its continuity regression remains strict")
			}
			_ = shared
			e, d, k, x := runtimeProofFixture()
			e.ContractVersion = 2
			e.Phase = RuntimeApplied
			e.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, Stage: "completed"}
			env := RuntimeEnvironment{Namespace: e.Allocation.Namespace}
			alive := kind != "daemon_dead"
			c := &RuntimeController{config: RuntimeControllerConfig{Environment: &mtuEnvironmentFixture{env: env}, DaemonAlive: func() bool { return alive }}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dc, kc, xc := 0, 0, 0
			readers := runtimeStatusReaders{alive: c.config.DaemonAlive}
			readers.daemon = func(context.Context) (DaemonInventory, error) {
				dc++
				out := d
				out.SAs = append([]DaemonIKE(nil), d.SAs...)
				if kind == "spare_down" {
					out.SAs = out.SAs[:1]
				}
				if kind == "selected_down" {
					out.SAs = out.SAs[1:]
				}
				if kind == "status_change" && dc == 2 {
					out.SAs = out.SAs[:1]
				}
				return out, nil
			}
			readers.kernel = func(context.Context) (KernelInventory, error) {
				kc++
				out := k
				out.Links = append([]KernelLink(nil), k.Links...)
				if kind == "kernel_change" && kc == 2 {
					out.Links[0].Up = false
				}
				return out, nil
			}
			readers.xfrm = func(context.Context) (XFRMInventory, error) {
				xc++
				out := x
				out.States = append([]XFRMState(nil), x.States...)
				if kind == "spare_down" {
					out.States = out.States[:2]
				}
				if kind == "selected_down" {
					out.States = out.States[2:]
				}
				if kind == "before_unknown" && xc == 1 || kind == "after_unknown" && xc == 2 {
					out.States[0].SPI++
				}
				if kind == "xfrm_change" && xc == 2 {
					out.States = append(out.States, XFRMState{ReqID: e.Engines[0].ReqID, IfID: e.Engines[0].XFRMID})
				}
				if kind == "environment_change" && xc == 1 {
					c.config.Environment = &mtuEnvironmentFixture{env: RuntimeEnvironment{Namespace: "net:[9999]"}}
				}
				if kind == "canceled" {
					cancel()
				}
				if kind == "read_error" {
					return out, fmt.Errorf("private synthetic read refusal")
				}
				return out, nil
			}
			got, err := any(c).(sharedStaticObservation).observeAndProveRecoveryWithReaders(ctx, e, env, readers)
			switch kind {
			case "healthy":
				if err != nil || got != [2]string{"up", "up"} || dc != 2 || kc != 2 || xc != 2 {
					t.Fatal("healthy whole pair not proved", got, err, dc, kc, xc)
				}
			case "spare_down":
				if err != nil || got != [2]string{"up", "down"} {
					t.Fatal("legitimate absent spare refused", got, err)
				}
			case "selected_down":
				if err != nil || got != [2]string{"down", "up"} {
					t.Fatal("selected down advice requires an UP ownership proof", got, err)
				}
			default:
				if err == nil || got != [2]string{"unknown", "unknown"} || dc > 2 || kc > 2 || xc > 2 {
					t.Fatal("unsafe evidence became healthy or was retried", got, err, dc, kc, xc)
				}
			}
		})
	}
}
