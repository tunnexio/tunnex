package fqdnrpc

import (
	"context"
	"sync"
	"testing"
)

func TestCNAMEWireAnswerAvoidsOnlyAlreadyAnsweredA(t *testing.T) {
	var mu sync.Mutex
	calls := map[string][]string{}
	d := DirectResolver{exchange: func(_ context.Context, e ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		mu.Lock()
		calls[e.Transport] = append(calls[e.Transport], name+"|"+string(typ))
		mu.Unlock()
		var out []Record
		if name == "alias.example.test" {
			out = append(out, Record{Name: name, Type: RecordCNAME, Target: "app.example.test", TTLSeconds: 30})
		}
		if typ == RecordA {
			out = append(out, Record{Name: "app.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30})
		}
		return out, nil
	}}
	c := ResolverConfig{ID: "01a12793-bb1b-7da4-927b-78c5363c9ad1", ProfileID: "459d6c22-a2ad-4fae-a795-8690e9091d66", Version: 2, Endpoints: []ResolverEndpoint{{Address: "10.81.0.2", Port: 53, Transport: "tcp"}, {Address: "10.81.0.2", Port: 53, Transport: "udp"}}}
	records, err := d.ResolveBound(context.Background(), "alias.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%v", records)
	}
	expected := []string{"alias.example.test|A", "alias.example.test|AAAA", "app.example.test|AAAA"}
	for _, transport := range []string{"tcp", "udp"} {
		if len(calls[transport]) != 3 {
			t.Fatal(calls)
		}
		for i, name := range expected {
			if calls[transport][i] != name {
				t.Fatal(calls)
			}
		}
	}
}

func TestTerminalWireAnswerStrict(t *testing.T) {
	good := []Record{{Name: "alias.example.test", Type: RecordCNAME, Target: "app.example.test", TTLSeconds: 30}, {Name: "app.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}}
	if name, _, ok := terminalWireAnswer("alias.example.test", RecordA, good); !ok || name != "app.example.test" {
		t.Fatal("complete chain refused")
	}
	for _, records := range [][]Record{
		good[:1],
		{good[0], {Name: "foreign.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}},
		{good[0], {Name: "app.example.test", Type: RecordA, Address: "bad", TTLSeconds: 30}},
		{good[0], {Name: "app.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 0}},
		{good[0], {Name: "app.example.test", Type: RecordCNAME, Target: "alias.example.test", TTLSeconds: 30}},
		{good[0], {Name: "alias.example.test", Type: RecordCNAME, Target: "other.example.test", TTLSeconds: 30}, good[1]},
		{good[0], {Name: "app.example.test", Type: RecordAAAA, Address: "fd00::1", TTLSeconds: 30}},
	} {
		if _, _, ok := terminalWireAnswer("alias.example.test", RecordA, records); ok {
			t.Fatalf("incomplete or malformed wire reused: %+v", records)
		}
	}
	chain := []Record{good[0], {Name: "app.example.test", Type: RecordCNAME, Target: "terminal.example.test", TTLSeconds: 30}, {Name: "terminal.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}}
	if name, _, ok := terminalWireAnswer("alias.example.test", RecordA, chain); !ok || name != "terminal.example.test" {
		t.Fatal("complete multi chain refused")
	}
}

func TestWireReuseEndpointIsolationAndRefusals(t *testing.T) {
	for _, mode := range []string{"incomplete", "disagreement", "negative", "unknown", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			targetA := map[string]int{}
			d := DirectResolver{exchange: func(_ context.Context, e ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
				if name == "app.example.test" && typ == RecordA {
					mu.Lock()
					targetA[e.Transport]++
					mu.Unlock()
				}
				cname := Record{Name: "alias.example.test", Type: RecordCNAME, Target: "app.example.test", TTLSeconds: 30}
				addr := Record{Name: "app.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}
				if e.Transport == "udp" {
					switch mode {
					case "negative":
						return nil, resolverStatusError{status: StatusNXDomain}
					case "unknown":
						return []Record{{Name: name, Type: RecordType("UNKNOWN"), TTLSeconds: 30}}, nil
					case "cycle":
						return []Record{cname, {Name: "app.example.test", Type: RecordCNAME, Target: "alias.example.test", TTLSeconds: 30}}, nil
					case "disagreement":
						addr.Address = "10.81.0.11"
					}
				}
				if name == "alias.example.test" {
					if typ == RecordA && !(e.Transport == "udp" && mode == "incomplete") {
						return []Record{cname, addr}, nil
					}
					return []Record{cname}, nil
				}
				if typ == RecordA {
					return []Record{addr}, nil
				}
				return nil, nil
			}}
			config := ResolverConfig{ID: "01a12793-bb1b-7da4-927b-78c5363c9ad1", ProfileID: "459d6c22-a2ad-4fae-a795-8690e9091d66", Version: 2, Endpoints: []ResolverEndpoint{{Address: "10.81.0.2", Port: 53, Transport: "tcp"}, {Address: "10.81.0.2", Port: 53, Transport: "udp"}}}
			_, err := d.ResolveBound(context.Background(), "alias.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
			if mode == "incomplete" {
				if err != nil || targetA["udp"] != 1 || targetA["tcp"] != 0 {
					t.Fatalf("endpoint borrow or refusal: calls=%v err=%v", targetA, err)
				}
			} else if err == nil {
				t.Fatal("refusal lost")
			}
		})
	}
}
