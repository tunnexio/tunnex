package dnsforward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// LANListener is an administrator's explicit DNS-only ingress authorization.
// It is separate from WireGuard profile entitlements and application access.
type LANListener struct {
	Address          string
	Interface        string
	AllowedSources   []string
	DefaultUpstreams []string
}
type lanBindKey struct {
	address netip.Addr
	iface   string
}
type compiledLANListener struct {
	key              lanBindKey
	sources          []netip.Prefix
	defaultUpstreams []netip.Addr
	defaultError     string
}
type lanBinding struct {
	udp    udpListener
	tcp    net.Listener
	cancel context.CancelFunc
	done   chan struct{}
}

func compileLANListener(in LANListener) *compiledLANListener {
	address, err := netip.ParseAddr(in.Address)
	if err != nil || !address.Is4() || !address.IsPrivate() || in.Interface == "" || len(in.Interface) > 15 || len(in.AllowedSources) == 0 || len(in.AllowedSources) > 32 {
		return nil
	}
	for _, c := range in.Interface {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
			return nil
		}
	}
	out := &compiledLANListener{key: lanBindKey{address, in.Interface}}
	for _, raw := range in.AllowedSources {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p != p.Masked() || p.Bits() == 0 {
			return nil
		}
		// A private starting address is insufficient if the CIDR extends into WAN.
		last := p.Addr().As4()
		first := p.Addr().As4()
		bits := p.Bits()
		for i := bits; i < 32; i++ {
			last[i/8] |= 1 << uint(7-i%8)
		}
		if !netip.AddrFrom4(first).IsPrivate() || !netip.AddrFrom4(last).IsPrivate() {
			return nil
		}
		out.sources = append(out.sources, p)
	}
	out.defaultUpstreams, out.defaultError = compileLANDefaultUpstreams(in.DefaultUpstreams)
	return out
}

func ownedLANAddress(key lanBindKey) error {
	iface, err := net.InterfaceByName(key.iface)
	if err != nil {
		return fmt.Errorf("LAN interface is unavailable: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("LAN interface is not an active non-loopback interface")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("cannot inspect LAN interface: %w", err)
	}
	for _, raw := range addresses {
		p, err := netip.ParsePrefix(raw.String())
		if err == nil && p.Addr().Unmap() == key.address {
			return nil
		}
	}
	return fmt.Errorf("configured DNS address is not owned by the selected LAN interface")
}

func (f *Forwarder) handleLAN(query []byte, source netip.Addr, transport string, scope lanBindKey) []byte {
	if !f.allow(source) {
		return nil
	}
	var parser dnsmessage.Parser
	hdr, err := parser.Start(query)
	if err != nil || hdr.Response {
		return nil
	}
	q, err := parser.Question()
	if err != nil {
		return refuse(hdr.ID, query)
	}
	if _, err = parser.Question(); err != dnsmessage.ErrSectionDone || hdr.OpCode != 0 {
		return refuse(hdr.ID, query)
	}
	response, handled := f.answerScopedResolverProfile(hdr.ID, query, q, source, transport, &scope)
	if !handled {
		return f.answerLANDefault(hdr.ID, query, q, source, transport, scope)
	}
	return response
}

// reconcileLANBinds runs only on the existing serialized dataplane command lane.
// Both transports must bind before either serves; existing host DNS is never
// replaced or configured. Multiple profiles share one socket pair per scope.
func (f *Forwarder) reconcileLANBinds(wgIface string) {
	wanted := map[lanBindKey]bool{}
	profiles := f.profiles.Load()
	for _, p := range profiles.entries {
		if p.valid && p.lan != nil {
			wanted[p.lan.key] = true
		}
	}
	f.lanErrors = map[lanBindKey]string{}
	for key, b := range f.lanListeners {
		select {
		case <-b.done:
			b.cancel()
			delete(f.lanListeners, key)
		default:
		}
	}
	for key := range wanted {
		check := f.lanOwned
		if check == nil {
			check = ownedLANAddress
		}
		var err error
		if key.iface == wgIface {
			err = fmt.Errorf("LAN listener cannot use the WireGuard interface")
		} else {
			err = check(key)
		}
		if err != nil {
			f.lanErrors[key] = err.Error()
			delete(wanted, key)
		} else if _, _, _, defaultErr := f.lanDefaults(profiles, key); defaultErr != "" {
			// Retain private DNS on this socket; public forwarding is independently disabled.
			f.lanErrors[key] = "LAN default DNS disabled: " + defaultErr
		}
	}
	for key, b := range f.lanListeners {
		if !wanted[key] {
			b.cancel()
			_ = b.udp.Close()
			_ = b.tcp.Close()
			delete(f.lanListeners, key)
		}
	}
	for key := range wanted {
		if f.lanListeners[key] != nil {
			continue
		}
		listenUDP := f.lanListenUDP
		if listenUDP == nil {
			listenUDP = listenUDPOnInterface
		}
		listenTCP := f.lanListenTCP
		if listenTCP == nil {
			listenTCP = listenTCPOnInterface
		}
		udp, err := listenUDP(key.address, key.iface)
		if err != nil {
			f.lanErrors[key] = "UDP port 53 unavailable: " + err.Error()
			continue
		}
		tcp, err := listenTCP(key.address, key.iface)
		if err != nil {
			_ = udp.Close()
			f.lanErrors[key] = "TCP port 53 unavailable: " + err.Error()
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		b := &lanBinding{udp: udp, tcp: tcp, cancel: cancel, done: make(chan struct{})}
		f.lanListeners[key] = b
		f.listenerWG.Add(1)
		go func(key lanBindKey, b *lanBinding) {
			defer f.listenerWG.Done()
			defer close(b.done)
			var wg sync.WaitGroup
			closePair := func() { b.cancel(); _ = b.udp.Close(); _ = b.tcp.Close() }
			handler := func(query []byte, source netip.Addr, transport string) []byte {
				return f.handleLAN(query, source, transport, key)
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer closePair(); f.serveTCPWithHandler(ctx, b.tcp, handler) }()
			f.serveConnWithHandler(ctx, b.udp, handler)
			closePair()
			wg.Wait()
		}(key, b)
	}
	if f.log != nil {
		for key, err := range f.lanErrors {
			f.log.Warn("dns_lan_listener_unavailable", "address", key.address.String(), "interface", key.iface, "error", err)
		}
	}
}

func (f *Forwarder) closeLANBinds() {
	for key, b := range f.lanListeners {
		b.cancel()
		_ = b.udp.Close()
		_ = b.tcp.Close()
		delete(f.lanListeners, key)
	}
}

// LANListenerState is actual local socket readiness, not proof of upstream DNS
// or application reachability. Configuration and bind conflicts stay distinct.
type LANListenerState struct {
	Address    string   `json:"address"`
	Interface  string   `json:"interface"`
	Ready      bool     `json:"ready"`
	Error      string   `json:"error"`
	ProfileIDs []string `json:"profile_ids"`
}

func (f *Forwarder) AppliedLANListeners() []LANListenerState {
	f.bindMu.Lock()
	defer f.bindMu.Unlock()
	var out []LANListenerState
	for key, b := range f.lanListeners {
		select {
		case <-b.done:
			out = append(out, LANListenerState{Address: key.address.String(), Interface: key.iface, Error: "listener closed"})
		default:
			out = append(out, LANListenerState{Address: key.address.String(), Interface: key.iface, Ready: f.lanErrors[key] == "", Error: f.lanErrors[key]})
		}
	}
	for key, err := range f.lanErrors {
		if f.lanListeners[key] != nil {
			continue
		}
		out = append(out, LANListenerState{Address: key.address.String(), Interface: key.iface, Error: err})
	}
	for i := range out {
		out[i].ProfileIDs = []string{}
		for _, profile := range f.profiles.Load().entries {
			if profile.valid && profile.lan != nil && profile.lan.key.address.String() == out[i].Address && profile.lan.key.iface == out[i].Interface {
				out[i].ProfileIDs = append(out[i].ProfileIDs, profile.config.ProfileID)
			}
		}
		sort.Strings(out[i].ProfileIDs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address+out[i].Interface < out[j].Address+out[j].Interface })
	return out
}
