package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvironmentNFTDoesNotOccupyIPWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var entered, finished atomic.Int32
	both := make(chan struct{})
	release := make(chan struct{})
	done := make(chan bool, 1)
	nft := func(c context.Context) ([]byte, error) {
		select {
		case <-both:
			return []byte(`{}`), nil
		case <-c.Done():
			return nil, c.Err()
		}
	}
	ip := func(c context.Context, _ ...string) ([]byte, error) {
		if entered.Add(1) == 2 {
			close(both)
		}
		select {
		case <-release:
			finished.Add(1)
			return []byte(`[]`), nil
		case <-c.Done():
			return nil, c.Err()
		}
	}
	go func() { _, ok := runtimeReadEnvironmentSnapshot(ctx, ip, nft, [2]EngineTunnel{}); done <- ok }()
	select {
	case <-both:
	case <-time.After(100 * time.Millisecond):
		cancel()
		close(release)
		<-done
		t.Fatal("NFT occupied IP worker")
	}
	select {
	case <-done:
		t.Fatal("returned before drain")
	default:
	}
	close(release)
	if !<-done || finished.Load() != int32(4+engineTunnelCount([2]EngineTunnel{})) {
		t.Fatal("incomplete census drain")
	}
}
func TestEnvironmentNFTFailureDrainsIPBranch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	var calls, finished atomic.Int32
	nft := func(c context.Context) ([]byte, error) {
		select {
		case <-entered:
			return nil, errors.New("fixture")
		case <-c.Done():
			return nil, c.Err()
		}
	}
	ip := func(c context.Context, _ ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-c.Done()
		finished.Add(1)
		return nil, c.Err()
	}
	_, ok := runtimeReadEnvironmentSnapshot(ctx, ip, nft, [2]EngineTunnel{})
	if ok || finished.Load() != calls.Load() {
		t.Fatal("failure not drained")
	}
}
func TestDockerDNSVersionAndListingIndependentBarrier(t *testing.T) {
	nft, err := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	listing, err := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "wrong_version", "invalid_listing", "read_failure", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			v := make(chan struct{})
			l := make(chan struct{})
			var done atomic.Int32
			run := func(c context.Context, _ string, args ...string) ([]byte, error) {
				defer done.Add(1)
				if args[0] == "-V" {
					close(v)
					select {
					case <-l:
					case <-c.Done():
						return nil, c.Err()
					}
					if kind == "wrong_version" {
						return []byte("legacy"), nil
					}
					return []byte("iptables-nft-save v1.8.10 (nf_tables)"), nil
				}
				close(l)
				select {
				case <-v:
				case <-c.Done():
					return nil, c.Err()
				}
				if kind == "read_failure" {
					return nil, errors.New("fixture")
				}
				if kind == "deadline" {
					<-c.Done()
					return nil, c.Err()
				}
				if kind == "invalid_listing" {
					return []byte("invalid"), nil
				}
				return listing, nil
			}
			ok := runtimeQualifiedHookCensusWithCommands(ctx, "/sbin/nft", nft, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, run)
			if ok != (kind == "valid") || done.Load() != 2 {
				t.Fatal("independent reads or validation lost", ok, done.Load())
			}
		})
	}
}
