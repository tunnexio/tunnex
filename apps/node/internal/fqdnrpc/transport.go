package fqdnrpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func validIPsecPath(path IPsecPath) bool {
	ip, err := netip.ParseAddr(path.SourceAddress)
	return isUUID(path.ConnectionID) && path.ConnectionID != "00000000-0000-0000-0000-000000000000" && path.ConfigurationRevision > 0 && err == nil && ip.Is4() && ip.String() == path.SourceAddress && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// ValidResolverConfig is shared by the gateway split-DNS table and brokered
// policy resolver. Validation cannot manufacture an IPsec transport permit.
func ValidResolverConfig(config ResolverConfig) bool { return validResolverConfig(config) }

// ExchangeDNS forwards an unchanged client packet only through this immutable
// profile. A UDP TC answer is retried against the SAME endpoint over TCP; no
// resolver selection or public/system fallback occurs in this helper.
func ExchangeDNS(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
	return exchangeConfiguredDNS(ctx, transport, config, endpoint, "", payload)
}

// ExchangeProxyDNS preserves the downstream transport. UDP relays a validated
// TC answer for the client to retry; TCP makes one TCP exchange. UDP retains a
// configured TCP endpoint. The original endpoint must exactly belong to this
// immutable profile before deriving its
// transport. BoundTransport still independently authorizes the derived protocol.
func ExchangeProxyDNS(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, downstream string, payload []byte) ([]byte, error) {
	if downstream != "udp" && downstream != "tcp" {
		return nil, errResolverConfig
	}
	return exchangeConfiguredDNS(ctx, transport, config, endpoint, downstream, payload)
}

func exchangeConfiguredDNS(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, downstream string, payload []byte) ([]byte, error) {
	if !validResolverConfig(config) || len(payload) < 12 || len(payload) > 65535 {
		return nil, errResolverConfig
	}
	listed := false
	for _, e := range config.Endpoints {
		if e == endpoint {
			listed = true
			break
		}
	}
	if !listed || config.IPsecPath != nil && transport == nil {
		return nil, errResolverConfig
	}
	if transport == nil {
		transport = configlessTransport{}
	}
	if downstream == "tcp" {
		endpoint.Transport = "tcp"
	}
	return exchangeDNSPacketMode(ctx, transport, config, endpoint, payload, downstream == "")
}

func exchangeDNSPacket(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
	return exchangeDNSPacketMode(ctx, transport, config, endpoint, payload, true)
}

func exchangeDNSPacketMode(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, payload []byte, complete bool) ([]byte, error) {
	var query dnsmessage.Message
	if query.Unpack(payload) != nil || query.Response || len(query.Questions) != 1 || query.OpCode != 0 {
		return nil, errResolverConfig
	}
	resp, err := transport.ExchangeDNS(ctx, config, endpoint, payload)
	if err != nil {
		return nil, err
	}
	var answer dnsmessage.Message
	if answer.Unpack(resp) != nil || !answer.Response || answer.ID != query.ID || answer.OpCode != query.OpCode || len(answer.Questions) != 1 || answer.Questions[0] != query.Questions[0] {
		return nil, errResolverConfig
	}
	if answer.Truncated && endpoint.Transport == "udp" && complete {
		tcp := endpoint
		tcp.Transport = "tcp"
		resp, err = transport.ExchangeDNS(ctx, config, tcp, payload)
		if err != nil {
			return nil, err
		}
		answer = dnsmessage.Message{}
		if answer.Unpack(resp) != nil || !answer.Response || answer.ID != query.ID || answer.Truncated || answer.OpCode != query.OpCode || len(answer.Questions) != 1 || answer.Questions[0] != query.Questions[0] {
			return nil, errResolverConfig
		}
	}
	if answer.Truncated && (complete || endpoint.Transport == "tcp") {
		return nil, errResolverConfig
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return resp, nil
}

type configlessTransport struct{}

func (configlessTransport) ExchangeDNS(ctx context.Context, config ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
	if config.IPsecPath != nil {
		return nil, errResolverConfig
	}
	return ExchangeBoundSocket(ctx, endpoint, netip.Addr{}, payload)
}

// ExchangeBoundSocket sends one raw DNS packet with the explicit source when
// supplied. Callers with an IPsec path must independently prove its authority
// and native source/route before invoking this low-level socket operation.
type SocketStage string

const (
	SocketInput    SocketStage = "input"
	SocketDial     SocketStage = "dial"
	SocketWrite    SocketStage = "write"
	SocketLength   SocketStage = "length"
	SocketBody     SocketStage = "body"
	SocketComplete SocketStage = "complete"
)

// SocketOutcome contains no endpoint, packet or underlying error information.
type SocketOutcome struct {
	Stage   SocketStage
	Failed  bool
	Elapsed time.Duration
}

func ExchangeBoundSocket(ctx context.Context, endpoint ResolverEndpoint, source netip.Addr, payload []byte) ([]byte, error) {
	return ExchangeBoundSocketObserved(ctx, endpoint, source, payload, nil)
}

// ExchangeBoundSocketObserved invokes the per-call observer synchronously once.
func ExchangeBoundSocketObserved(ctx context.Context, endpoint ResolverEndpoint, source netip.Addr, payload []byte, observe func(SocketOutcome)) (response []byte, resultErr error) {
	stage, started := SocketInput, time.Now()
	defer func() {
		if observe != nil {
			observe(SocketOutcome{Stage: stage, Failed: resultErr != nil, Elapsed: time.Since(started)})
		}
	}()
	if len(payload) < 12 || len(payload) > 65535 || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") {
		return nil, errResolverConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	if source.IsValid() {
		if !source.Is4() {
			return nil, errResolverConfig
		}
		if endpoint.Transport == "udp" {
			dialer.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
		} else {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
		}
	}
	stage = SocketDial
	c, err := dialer.DialContext(ctx, endpoint.Transport, net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port)))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stage = SocketWrite
	if endpoint.Transport == "udp" {
		if _, err = c.Write(payload); err != nil {
			return nil, err
		}
		b := make([]byte, 65535)
		stage = SocketBody
		n, err := c.Read(b)
		if err != nil {
			return nil, err
		}
		stage = SocketComplete
		return b[:n], nil
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	for len(frame) > 0 {
		n, err := c.Write(frame)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	stage = SocketLength
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 {
		return nil, fmt.Errorf("invalid DNS TCP frame")
	}
	stage = SocketBody
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	stage = SocketComplete
	return resp, nil
}
