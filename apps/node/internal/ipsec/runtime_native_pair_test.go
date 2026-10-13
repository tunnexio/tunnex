package ipsec

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNativeIndependentReadersOverlapAndJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := make(chan string, 2)
	release := make(chan struct{})
	done := make(chan struct{})
	r := runtimeStatusReaders{independent: true}
	check := func(child context.Context, name string) {
		a, aok := ctx.Deadline()
		b, bok := child.Deadline()
		if !aok || !bok || a != b {
			t.Error("caller deadline changed")
		}
		started <- name
		select {
		case <-release:
		case <-child.Done():
			t.Error("unexpected cancellation")
		}
	}
	r.daemon = func(c context.Context) (DaemonInventory, error) {
		check(c, "daemon")
		return DaemonInventory{Version: "one"}, nil
	}
	r.kernel = func(c context.Context) (KernelInventory, error) {
		check(c, "kernel")
		return KernelInventory{Namespace: "net:[42]"}, nil
	}
	go func() {
		d, k, de, ke := runtimeNativeDaemonKernel(ctx, r)
		if de != nil || ke != nil || d.Version != "one" || k.Namespace != "net:[42]" {
			t.Error("joined results lost")
		}
		close(done)
	}()
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case n := <-started:
			seen[n] = true
		case <-ctx.Done():
			t.Fatal("independent reader did not overlap")
		}
	}
	if len(seen) != 2 {
		t.Fatal("same reader ran twice")
	}
	select {
	case <-done:
		t.Fatal("returned before both readers completed")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("did not join")
	}
}

func TestNativeIndependentReaderErrorCancelsAndJoinsSibling(t *testing.T) {
	for _, failure := range []string{"daemon", "kernel", "parent"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			began := make(chan string, 2)
			fail := make(chan struct{})
			canceled := make(chan struct{}, 2)
			unwind := make(chan struct{})
			done := make(chan struct{})
			read := func(c context.Context, n string) error {
				began <- n
				if n == failure {
					<-fail
					return ErrRuntimeController
				}
				<-c.Done()
				canceled <- struct{}{}
				<-unwind
				return c.Err()
			}
			r := runtimeStatusReaders{independent: true, daemon: func(c context.Context) (DaemonInventory, error) { return DaemonInventory{}, read(c, "daemon") }, kernel: func(c context.Context) (KernelInventory, error) { return KernelInventory{}, read(c, "kernel") }}
			go func() {
				_, _, de, ke := runtimeNativeDaemonKernel(ctx, r)
				if de == nil && ke == nil {
					t.Error("failure promoted")
				}
				close(done)
			}()
			for i := 0; i < 2; i++ {
				select {
				case <-began:
				case <-time.After(time.Second):
					t.Fatal("reader not started")
				}
			}
			if failure == "parent" {
				cancel()
			} else {
				close(fail)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("sibling not canceled")
			}
			select {
			case <-done:
				t.Fatal("returned with reader still unwinding")
			default:
			}
			close(unwind)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("join did not finish")
			}
		})
	}
}

func TestNativeInjectedReadersKeepSerialCallerContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var order []string
	r := runtimeStatusReaders{daemon: func(c context.Context) (DaemonInventory, error) {
		if c != ctx {
			t.Error("injected context changed")
		}
		order = append(order, "daemon")
		return DaemonInventory{}, nil
	}, kernel: func(c context.Context) (KernelInventory, error) {
		if c != ctx {
			t.Error("injected context changed")
		}
		order = append(order, "kernel")
		return KernelInventory{}, nil
	}}
	_, _, de, ke := runtimeNativeDaemonKernel(ctx, r)
	if de != nil || ke != nil || !reflect.DeepEqual(order, []string{"daemon", "kernel"}) {
		t.Fatal("injected order changed", order)
	}
}

func TestNativeIndependentProofKeepsLegEnvironmentBrackets(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	env := RuntimeEnvironment{Namespace: e.Allocation.Namespace}
	var mu sync.Mutex
	var events []string
	mark := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	legs := []chan struct{}{make(chan struct{}), make(chan struct{})}
	started := make(chan string, 4)
	dc, kc, xc := 0, 0, 0
	c := &RuntimeController{config: RuntimeControllerConfig{Environment: &nativeBracketEnvironment{env: env, mark: mark}, DaemonAlive: func() bool { return true }}}
	r := runtimeStatusReaders{daemon: func(ctx context.Context) (DaemonInventory, error) {
		i := dc
		dc++
		mark("daemon")
		started <- "daemon"
		select {
		case <-legs[i]:
		case <-ctx.Done():
			return DaemonInventory{}, ctx.Err()
		}
		return d, nil
	}, kernel: func(ctx context.Context) (KernelInventory, error) {
		i := kc
		kc++
		mark("kernel")
		started <- "kernel"
		select {
		case <-legs[i]:
		case <-ctx.Done():
			return KernelInventory{}, ctx.Err()
		}
		return k, nil
	}, xfrm: func(context.Context) (XFRMInventory, error) { xc++; mark("xfrm"); return x, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.proveRuntimeWithIndependentReaders(ctx, e, env, r) }()
	for leg := 0; leg < 2; leg++ {
		for j := 0; j < 2; j++ {
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("leg did not overlap")
			}
		}
		mu.Lock()
		snapshot := append([]string(nil), events...)
		mu.Unlock()
		if leg == 0 {
			if xc != 1 || len(snapshot) != 3 {
				t.Fatal("environment or AFTER crossed unfinished BEFORE", snapshot)
			}
		} else {
			if xc != 2 || len(snapshot) != 7 || snapshot[3] != "environment" || snapshot[4] != "xfrm" {
				t.Fatal("AFTER bracket changed", snapshot)
			}
		}
		close(legs[leg])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("proof did not finish")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 7 || events[0] != "xfrm" {
		t.Fatal("reader count changed", events)
	}
}

type nativeBracketEnvironment struct {
	env  RuntimeEnvironment
	mark func(string)
}

func (e *nativeBracketEnvironment) Observe(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error) {
	e.mark("environment")
	return e.env, nil
}
func (e *nativeBracketEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }
