package fqdnrpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func concurrentResolverConfig(count int) ResolverConfig {
	config := ResolverConfig{ID: "66666666-6666-6666-6666-666666666666", Version: 4, ProfileID: "77777777-7777-7777-7777-777777777777", MatchedSuffix: "example.test"}
	for i := 0; i < count; i++ {
		config.Endpoints = append(config.Endpoints, ResolverEndpoint{Address: fmt.Sprintf("10.20.0.%d", 53+i), Port: 53, Transport: "udp"})
	}
	return config
}
func resolvedA(name string, ttl int) []Record {
	return []Record{{Name: name, Type: RecordA, Address: "10.20.0.8", TTLSeconds: ttl}}
}

func TestDirectResolverParallelEndpointProofBudgetPreservesDeadline(t *testing.T) {
	config := concurrentResolverConfig(4)
	ctx, cancel := context.WithTimeout(t.Context(), 2400*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var calls atomic.Int32
	resolver := DirectResolver{exchange: func(queryCtx context.Context, _ ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		if got, ok := queryCtx.Deadline(); !ok || !got.Equal(deadline) {
			t.Error("original deadline changed")
			return nil, errResolverConfig
		}
		calls.Add(1)
		// Every query still pays both full independent 400ms proof observations.
		for range 2 {
			timer := time.NewTimer(400 * time.Millisecond)
			select {
			case <-timer.C:
			case <-queryCtx.Done():
				timer.Stop()
				return nil, queryCtx.Err()
			}
		}
		if typ == RecordA {
			return resolvedA(name, 30), nil
		}
		return nil, nil
	}}
	start := time.Now()
	records, err := resolver.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
	if err != nil || len(records) != 1 || calls.Load() != 8 || ctx.Err() != nil {
		t.Fatalf("complete endpoint consensus err=%v records=%d calls=%d context=%v", err, len(records), calls.Load(), ctx.Err())
	}
	if time.Since(start) >= 2400*time.Millisecond {
		t.Fatal("original budget exceeded")
	}
}

func TestDirectResolverEndpointWorkersBoundedAndInputsCloned(t *testing.T) {
	config := concurrentResolverConfig(8)
	types := []RecordType{RecordA}
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	var mu sync.Mutex
	var addresses []string
	resolver := DirectResolver{exchange: func(ctx context.Context, endpoint ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); current > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, current) {
				break
			}
		}
		mu.Lock()
		addresses = append(addresses, endpoint.Address)
		mu.Unlock()
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if typ != RecordA {
			t.Error("caller mutation changed cloned types")
			return nil, errResolverConfig
		}
		return resolvedA(name, 30), nil
	}}
	done := make(chan error, 1)
	go func() { _, err := resolver.ResolveBound(t.Context(), "api.example.test", types, config); done <- err }()
	for range 4 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("four workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four workflows running")
	default:
	}
	// ResolveBound cloned before any exchange starts; modify only original inputs.
	for i := range config.Endpoints {
		config.Endpoints[i].Address = "10.99.0.1"
	}
	types[0] = RecordAAAA
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 4 || active.Load() != 0 || len(addresses) != 8 {
		t.Fatalf("bound/drain max=%d active=%d endpoints=%d", maximum.Load(), active.Load(), len(addresses))
	}
	for _, address := range addresses {
		if address == "10.99.0.1" {
			t.Fatal("caller mutation changed cloned endpoints")
		}
	}
}

func TestDirectResolverCanceledWorkersAllDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{}, 4)
	var finished atomic.Int32
	resolver := DirectResolver{exchange: func(ctx context.Context, _ ResolverEndpoint, _ string, _ RecordType) ([]Record, error) {
		started <- struct{}{}
		<-ctx.Done()
		finished.Add(1)
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		records, err := resolver.ResolveBound(ctx, "api.example.test", []RecordType{RecordA}, concurrentResolverConfig(8))
		if len(records) != 0 {
			done <- errors.New("partial success")
			return
		}
		done <- err
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errResolverConfig) || finished.Load() != 4 {
			t.Fatalf("cancellation err=%v drained=%d", err, finished.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("workers did not drain")
	}
}

func TestDirectResolverConfiguredOrderWinsOverCompletionOrder(t *testing.T) {
	for _, nxFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(nxFirst), func(t *testing.T) {
			config := concurrentResolverConfig(3)
			resolver := DirectResolver{exchange: func(ctx context.Context, endpoint ResolverEndpoint, name string, _ RecordType) ([]Record, error) {
				if endpoint == config.Endpoints[0] {
					select {
					case <-time.After(40 * time.Millisecond):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return resolvedA(name, 30), nil
				}
				nx := endpoint == config.Endpoints[2]
				if nxFirst {
					nx = endpoint == config.Endpoints[1]
				}
				if nx {
					return nil, resolverStatusError{status: StatusNXDomain}
				}
				records := resolvedA(name, 30)
				records[0].Address = "10.20.0.9"
				return records, nil
			}}
			records, err := resolver.ResolveBound(t.Context(), "api.example.test", []RecordType{RecordA}, config)
			if len(records) != 0 {
				t.Fatal("partial consensus")
			}
			var status resolverStatusError
			if nxFirst {
				if !errors.As(err, &status) || status.status != StatusNXDomain {
					t.Fatalf("configured NXDOMAIN precedence lost: %v", err)
				}
			} else if !errors.Is(err, errResolverConfig) {
				t.Fatalf("configured disagreement precedence lost: %v", err)
			}
		})
	}
}

func TestDirectResolverParallelCNAMEKeepsTypesSequentialAndTTLConservative(t *testing.T) {
	config := concurrentResolverConfig(4)
	var mu sync.Mutex
	calls := map[ResolverEndpoint][]RecordType{}
	resolver := DirectResolver{exchange: func(_ context.Context, endpoint ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		mu.Lock()
		calls[endpoint] = append(calls[endpoint], typ)
		mu.Unlock()
		ttl := 30
		if endpoint == config.Endpoints[3] {
			ttl = 7
		}
		if name == "api.example.test" {
			return []Record{{Name: name, Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: ttl}}, nil
		}
		if typ == RecordAAAA {
			return nil, nil
		}
		return resolvedA(name, ttl), nil
	}}
	records, err := resolver.ResolveBound(t.Context(), "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
	if err != nil || len(records) != 2 {
		t.Fatalf("CNAME/A consensus %v records%d", err, len(records))
	}
	for _, record := range records {
		if record.TTLSeconds != 7 {
			t.Fatal("did not use all-endpoint minimum TTL")
		}
	}
	for _, endpoint := range config.Endpoints {
		got := calls[endpoint]
		if len(got) != 4 || got[0] != RecordA || got[1] != RecordAAAA || got[2] != RecordA || got[3] != RecordAAAA {
			t.Fatalf("types/CNAME became parallel or explicit CNAME queried: %v", got)
		}
	}
	for _, loop := range []bool{false, true} {
		resolver.exchange = func(_ context.Context, _ ResolverEndpoint, name string, _ RecordType) ([]Record, error) {
			target := name
			if !loop {
				target = "x." + name
			}
			return []Record{{Name: name, Type: RecordCNAME, Target: target, TTLSeconds: 30}}, nil
		}
		if records, err := resolver.ResolveBound(t.Context(), "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config); !errors.Is(err, errResolverConfig) || len(records) != 0 {
			t.Fatalf("CNAME loop/depth refused: %v", err)
		}
	}
}

func TestDirectResolverParallelClonesIPsecPath(t *testing.T) {
	config := concurrentResolverConfig(2)
	config.IPsecPath = &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 3, SourceAddress: "10.10.0.1"}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	observations := make(chan string, 4)
	transport := packetTransport(func(ctx context.Context, bound ResolverConfig, _ ResolverEndpoint, payload []byte) ([]byte, error) {
		observations <- bound.IPsecPath.SourceAddress
		var message dnsmessage.Message
		if err := message.Unpack(payload); err != nil {
			return nil, err
		}
		if message.Questions[0].Type == dnsmessage.TypeA {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 20, 0, 8}}}}
		}
		message.Response = true
		return message.Pack()
	})
	resolver := DirectResolver{Transport: transport}
	done := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveBound(t.Context(), "api.example.test", []RecordType{RecordA, RecordAAAA}, config)
		done <- err
	}()
	for range 1 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("endpoints did not start")
		}
	}
	config.IPsecPath.SourceAddress = "10.99.0.1"
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if got := <-observations; got != "10.10.0.1" {
			t.Fatal("caller mutation changed copied IPsec path")
		}
	}
}

func TestDirectResolverIPsecTwoWaveProofBudgetPreservesDeadline(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			config := concurrentResolverConfig(count)
			config.IPsecPath = &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 3, SourceAddress: "10.10.0.1"}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			var calls, proofs, active, maximum atomic.Int32
			var mu sync.Mutex
			seen := map[ResolverEndpoint][]RecordType{}
			resolver := DirectResolver{Transport: concurrentIPsecTransport(func(queryCtx context.Context, endpoint ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
				if got, ok := queryCtx.Deadline(); !ok || !got.Equal(deadline) {
					t.Error("original deadline changed")
					return nil, errResolverConfig
				}
				calls.Add(1)
				current := active.Add(1)
				defer active.Add(-1)
				for old := maximum.Load(); current > old; old = maximum.Load() {
					if maximum.CompareAndSwap(old, current) {
						break
					}
				}
				mu.Lock()
				seen[endpoint] = append(seen[endpoint], typ)
				mu.Unlock()
				// Every exchange still pays TWO complete independent 400ms proofs.
				// This is a scheduling fixture, not a claim about live proof latency.
				for range 2 {
					proofs.Add(1)
					timer := time.NewTimer(400 * time.Millisecond)
					select {
					case <-timer.C:
					case <-queryCtx.Done():
						timer.Stop()
						return nil, queryCtx.Err()
					}
				}
				if typ == RecordA {
					ttl := 30
					for i, e := range config.Endpoints {
						if e == endpoint {
							ttl -= i
						}
					}
					return resolvedA(name, ttl), nil
				}
				return nil, nil
			})}
			start := time.Now()
			records, err := resolver.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
			if err != nil || len(records) != 1 || records[0].TTLSeconds != 31-count || calls.Load() != int32(2*count) || proofs.Load() != int32(4*count) || maximum.Load() != int32(count/2) || active.Load() != 0 || ctx.Err() != nil {
				t.Fatalf("complete minimum-TTL endpoint consensus err=%v records=%v calls=%d proofs=%d context=%v", err, records, calls.Load(), proofs.Load(), ctx.Err())
			}
			for _, endpoint := range config.Endpoints {
				if got := seen[endpoint]; len(got) != 2 || got[0] != RecordA || got[1] != RecordAAAA {
					t.Fatalf("endpoint types missing or reordered: %v", got)
				}
			}
			if time.Since(start) >= 5*time.Second {
				t.Fatal("original budget exceeded")
			}
		})
	}
}

// Packet fixture exercises the declared IPsec transport dispatch, not the plain resolver injection.
func concurrentIPsecTransport(exchange func(context.Context, ResolverEndpoint, string, RecordType) ([]Record, error)) packetTransport {
	return packetTransport(func(ctx context.Context, _ ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
		var message dnsmessage.Message
		if message.Unpack(payload) != nil || len(message.Questions) != 1 {
			return nil, errResolverConfig
		}
		q := message.Questions[0]
		typ := RecordA
		if q.Type == dnsmessage.TypeAAAA {
			typ = RecordAAAA
		} else if q.Type != dnsmessage.TypeA {
			return nil, errResolverConfig
		}
		name := strings.TrimSuffix(q.Name.String(), ".")
		records, err := exchange(ctx, endpoint, name, typ)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			address, err := netip.ParseAddr(r.Address)
			if err != nil || r.Type != RecordA {
				return nil, errResolverConfig
			}
			message.Answers = append(message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: uint32(r.TTLSeconds)}, Body: &dnsmessage.AResource{A: address.As4()}})
		}
		message.Response = true
		return message.Pack()
	})
}
