//go:build linux

package ipsec

import (
	"context"
	"reflect"
	"testing"
)

// Genuine ordinary Apply -> denied transport -> fresh ordinary Apply; modeled
// native I/O only, not cloud packet or unmanaged daemon authority evidence.
func TestClassicDeniedTransportFreshApplyPreservesSession(t *testing.T) {
	for _, mode := range []string{"unchanged", "changed-key", "foreign-config", "expired-fresh-lease", "changed-delivery", "ha-first", "classic-first"} {
		t.Run(mode, func(t *testing.T) {
			testClassicApplyBoot(t, false, false, func(c *RuntimeController, m RuntimeMaterial, mutations *int) {
				entries, err := c.journal.Entries()
				if err != nil {
					t.Fatal(err)
				}
				before := c.active[m.Manifest.ConnectionID]
				count := *mutations
				base := c.config.Daemon.request
				c.config.Daemon.request = func(ctx context.Context, command, event string, v viciMessage) (viciMessage, []viciMessage, error) {
					if command == "get-conns" || command == "get-shared" {
						key := "conns"
						if command == "get-shared" {
							key = "keys"
						}
						names := []string{engineName(entries[0].Engines[0])}
						if mode == "foreign-config" {
							names = append(names, "foreign-unowned")
						}
						return viciMessage{key: viciList(names...)}, nil, nil
					}
					return base(ctx, command, event, v)
				}
				hints := c.rememberDeniedClassicTransports(entries)
				if len(hints) != 1 {
					t.Fatal("successful Apply identity not retained without authority")
				}
				c.active = nil
				if _, err = c.refuse(context.Background(), entries); err != nil {
					t.Fatal(err)
				}
				c.deniedClassicTransports = hints
				if mode == "ha-first" {
					ha := gcpMaterialFixture()
					cancelled, cancel := context.WithCancel(context.Background())
					cancel()
					if _, err := c.Apply(cancelled, ha); err == nil || len(c.deniedClassicTransports) != 1 || *mutations != count {
						t.Fatal("refused HA fallback erased sibling continuity or mutated daemon")
					}
				}
				switch mode {
				case "changed-key":
					m.Secrets[0].PSK = "a-different-valid-classic-key-value-32"
				case "expired-fresh-lease":
					c.client = &recoveryTestLease{ttl: 0}
				case "changed-delivery":
					m.Manifest.ConfigurationRevision++
					runtimeReseal(&m)
				}
				_, err = c.Apply(context.Background(), m)
				if mode == "unchanged" || mode == "ha-first" || mode == "classic-first" {
					after, ok := c.active[m.Manifest.ConnectionID]
					if err != nil || !ok || *mutations != count || after.Authority == before.Authority || !reflect.DeepEqual(after.Entry, before.Entry) {
						t.Fatalf("fresh Apply recreated transport or authority: err%v mutations%d->%d active%t", err, count, *mutations, ok)
					}
				}
				if mode == "foreign-config" || mode == "expired-fresh-lease" || mode == "changed-key" {
					if err == nil || len(c.active) != 0 || *mutations != count {
						t.Fatal("refused fresh proof renewed/mutated transport", mode, err)
					}
				}

				if mode == "changed-delivery" && err == nil {
					t.Fatal("changed immutable journal intent reused")
				}
				if mode == "classic-first" {
					ha := gcpMaterialFixture()
					cancelled, cancel := context.WithCancel(context.Background())
					cancel()
					if _, err := c.Apply(cancelled, ha); err == nil || *mutations != count {
						t.Fatal("refused HA fallback mutated established sibling")
					}
				}
				if len(c.deniedClassicTransports) != 0 {
					t.Fatal("continuity hint survived consumed attempt")
				}
			})
		})
	}
}
