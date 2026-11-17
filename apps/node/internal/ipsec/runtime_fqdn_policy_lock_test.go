package ipsec

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestUnchangedFQDNPolicyDoesNotWaitForRuntimeOwner(t *testing.T) {
	for _, additions := range []bool{false, true} {
		name := "unchanged"
		if additions {
			name = "additions-stay-pending"
		}
		t.Run(name, func(t *testing.T) {
			_, grant, policy := desktopStaticFQDNFixture(t)
			source := &RuntimeFQDNPolicySource{}
			source.CommittedPolicy(policy)
			before := source.view.Load()
			controller := &RuntimeController{started: true, active: map[uuid.UUID]runtimeActive{}}
			source.Attach(controller)
			pending := grant
			if additions {
				pending.PortLow, pending.PortHigh = grant.PortLow+1, grant.PortHigh+1
				entry := policy.Allow[0]
				entry.PortLow, entry.PortHigh = int(pending.PortLow), int(pending.PortHigh)
				policy.Allow = append(policy.Allow, entry)
			}

			// Simulate a slow serialized IPsec operation while the ordinary
			// reconciler needs to dispatch its following DNS refresh callback.
			controller.mu.Lock()
			done := make(chan error, 1)
			go func() { done <- source.BeforePolicy(context.Background(), policy) }()
			select {
			case err := <-done:
				controller.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				controller.mu.Unlock()
				<-done
				t.Fatal("unchanged FQDN authority waited on serial IPsec owner before DNS RPC dispatch")
			}

			if !reflect.DeepEqual(before, source.view.Load()) || !source.view.Load().matches(grant) {
				t.Fatal("unchanged committed authority changed")
			}
			expired := grant
			expired.FQDN.ExpiresAt = time.Now().Add(-time.Second)
			if source.view.Load().matches(expired) {
				t.Fatal("unchanged policy revived expired authority")
			}
			if additions {
				if source.view.Load().matches(pending) {
					t.Fatal("pending addition became authority before successful ordinary commit")
				}
				source.CommittedPolicy(policy)
				if !source.view.Load().matches(pending) {
					t.Fatal("successful ordinary commit did not admit the addition")
				}
			}
		})
	}
}

func TestChangedDesktopFQDNPolicyRetractsBeforeRuntimeOwnerWait(t *testing.T) {
	for name, change := range map[string]func(*nodepolicy.Compiled){
		"removed-grant":      func(p *nodepolicy.Compiled) { p.Allow = nil },
		"changed-generation": func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].Generation = strings.Repeat("b", 64) },
		"changed-path":       func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ApplicationIPsecPath.ConfigurationRevision++ },
		"changed-resolver": func(p *nodepolicy.Compiled) {
			p.DNSResolverProfiles[0].StaticRecords[0].Value = "replacement.example.net"
		},
		"disabled-policy": func(p *nodepolicy.Compiled) { p.Mode = nodepolicy.ModeOff },
	} {
		t.Run(name, func(t *testing.T) {
			_, grant, policy := desktopStaticFQDNFixture(t)
			source := &RuntimeFQDNPolicySource{}
			source.CommittedPolicy(policy)
			controller := &RuntimeController{started: true, active: map[uuid.UUID]runtimeActive{}}
			source.Attach(controller)
			change(policy)
			controller.mu.Lock()
			done := make(chan error, 1)
			go func() { done <- source.BeforePolicy(context.Background(), policy) }()
			deadline := time.After(time.Second)
			for source.view.Load().matches(grant) {
				select {
				case <-deadline:
					controller.mu.Unlock()
					<-done
					t.Fatal("runtime owner delayed permission retraction")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			select {
			case <-done:
				controller.mu.Unlock()
				t.Fatal("changed authority skipped serialized native withdrawal")
			default:
			}
			controller.mu.Unlock()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
