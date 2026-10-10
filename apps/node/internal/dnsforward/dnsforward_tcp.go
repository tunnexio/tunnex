package dnsforward

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type dnsTCPBind struct {
	listener net.Listener
	cancel   context.CancelFunc
}

func (f *Forwarder) reconcileTCPBinds(source func(string) ([]netip.Addr, error), iface string) {
	addresses, err := source(iface)
	if err != nil && !errors.Is(err, errWGIfaceNotFound) {
		return
	}
	want := map[netip.Addr]bool{}
	for _, address := range addresses {
		want[address] = true
	}
	f.listenerMu.Lock()
	for address, b := range f.tcpListeners {
		if !want[address] {
			b.cancel()
			_ = b.listener.Close()
			delete(f.tcpListeners, address)
		}
	}
	for address := range want {
		if f.tcpListeners[address] != nil {
			continue
		}
		listen := f.listenTCP
		if listen == nil {
			listen = func(address netip.Addr) (net.Listener, error) { return listenTCPOnInterface(address, iface) }
		}
		listener, err := listen(address)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		binding := &dnsTCPBind{listener, cancel}
		f.tcpListeners[address] = binding
		f.listenerWG.Add(1)
		go func(address netip.Addr, b *dnsTCPBind) {
			defer f.listenerWG.Done()
			defer b.cancel()
			defer b.listener.Close()
			defer func() {
				f.listenerMu.Lock()
				if f.tcpListeners[address] == b {
					delete(f.tcpListeners, address)
				}
				f.listenerMu.Unlock()
			}()
			f.serveTCP(ctx, b.listener)
		}(address, binding)
	}
	f.listenerMu.Unlock()
}

func (f *Forwarder) closeTCPBinds() {
	f.listenerMu.Lock()
	defer f.listenerMu.Unlock()
	for address, b := range f.tcpListeners {
		b.cancel()
		_ = b.listener.Close()
		delete(f.tcpListeners, address)
	}
}

// TCP uses exactly the same interface-derived bind scope and per-source
// entitlement/rate limiter as UDP. Sessions have bounded concurrency, idle
// duration, frame size and query count. Withdrawal closes accepted sessions.
func (f *Forwarder) serveTCP(ctx context.Context, listener net.Listener) {
	var handlers sync.WaitGroup
	defer handlers.Wait()
	slots := make(chan struct{}, 64)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		handlers.Add(1)
		go func(conn net.Conn) {
			defer handlers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			f.serveTCPConn(ctx, conn)
		}(conn)
	}
}

func (f *Forwarder) serveTCPConn(ctx context.Context, conn net.Conn) {
	source, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	for queries := 0; queries < 32; queries++ {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		response := f.handle(query, source.Addr().Unmap())
		if len(response) < 12 || len(response) > 65535 {
			return
		}
		frame := make([]byte, len(response)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(response)))
		copy(frame[2:], response)
		for len(frame) > 0 {
			written, err := conn.Write(frame)
			if err != nil || written == 0 {
				return
			}
			frame = frame[written:]
		}
	}
}

// AppliedResolverListeners reports native successful binds separately; it
// never claims that an upstream resolver or application is reachable.
func (f *Forwarder) AppliedResolverListeners() (udp, tcp []string) {
	f.listenerMu.Lock()
	defer f.listenerMu.Unlock()
	for address := range f.listeners {
		udp = append(udp, address.String())
	}
	for address := range f.tcpListeners {
		tcp = append(tcp, address.String())
	}
	sort.Strings(udp)
	sort.Strings(tcp)
	return udp, tcp
}
