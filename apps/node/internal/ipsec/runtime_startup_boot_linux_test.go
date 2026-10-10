//go:build linux

package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
)

func TestBGPStartupBootChangeWithReusedNamespacePreservesDuties(t *testing.T) {
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []RuntimePhase{RuntimeApplied, RuntimeCleanupPending, RuntimeRetainedRefusal} {
		t.Run(string(phase), func(t *testing.T) {
			c, f, p, denied := bgpControllerFixture(t, true)
			entries, _ := c.journal.Entries()
			e := entries[0]
			e.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
			if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
				t.Fatal(err)
			}
			if phase != RuntimeApplied {
				e.Phase = RuntimeCleanupPending
				e.CleanupID = uuid.New()
				e.CleanupDesiredRevision = e.Engines[0].Binding.DesiredRevision + 1
				e.CoveredDeliveryRevision = e.Engines[0].Binding.DesiredRevision
				if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
					t.Fatal(err)
				}
				if phase == RuntimeRetainedRefusal {
					e.Phase = phase
					if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _ := c.journal.Entries()
			mutations := f.mutations
			c.started = false
			c.active = nil
			c.qualification = nil
			if e.Restoration.BootID == boot {
				t.Fatal("synthetic old boot unexpectedly current")
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			after, _ := c.journal.Entries()
			if !*denied || !c.started || p.closed || f.mutations != mutations || !reflect.DeepEqual(before, after) || c.Capability() != 0 {
				t.Fatal("old boot startup mutated duties or inferred authority")
			}
		})
	}
}
func TestBGPStartupSameBootStillCleansBeforeStarting(t *testing.T) {
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	c, f, p, denied := bgpControllerFixture(t, true)
	entries, _ := c.journal.Entries()
	e := entries[0]
	e.Restoration = &RuntimeRestoration{BootID: boot}
	if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	c.started = false
	c.active = nil
	c.qualification = nil
	mutations := f.mutations
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !*denied || !p.closed || f.mutations <= mutations || !c.started {
		t.Fatal("same boot cleanup obligation skipped")
	}
}
