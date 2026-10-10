package ipsec

import (
	"context"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func checkpointControllerProcess(t *testing.T, c *RuntimeController) RuntimeJournalEntry {
	t.Helper()
	entries, err := c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	identity := *processStateFixture(t).BGPProcess
	identity.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g1")
	identity.Namespace = e.Allocation.Namespace
	e.BGPProcess = &identity
	entries[0] = e
	if c.journal.Save(entries) != nil {
		t.Fatal("reserve fixture")
	}
	identity.Stage = "partial"
	identity.Children = append(identity.Children, bgpengine.ChildIdentity{Name: "zebra", PID: 111, StartTicks: 5, Executable: bgpengine.FileIdentity{Device: 1, Inode: 100, Mode: 0755}})
	e.BGPProcess = &identity
	entries[0] = e
	if c.journal.Save(entries) != nil {
		t.Fatal("partial fixture")
	}
	identity.Stage = "ready"
	identity.Children = append(identity.Children, bgpengine.ChildIdentity{Name: "bgpd", PID: 112, StartTicks: 6, Executable: bgpengine.FileIdentity{Device: 1, Inode: 101, Mode: 0755}})
	for i, name := range []string{"bgpd.pid", "zebra.pid", "bgpd.vty", "zebra.vty", "zserv.api"} {
		mode := os.FileMode(0600)
		if i >= 2 {
			mode |= os.ModeSocket
		}
		identity.Files = append(identity.Files, bgpengine.NamedFileIdentity{Name: name, File: bgpengine.FileIdentity{Device: 1, Inode: uint64(10 + i), Mode: uint32(mode)}})
	}
	sort.Slice(identity.Files, func(i, j int) bool { return identity.Files[i].Name < identity.Files[j].Name })
	e.BGPProcess = &identity
	entries[0] = e
	if c.journal.Save(entries) != nil {
		t.Fatal("ready fixture")
	}
	return e
}
func TestBGPControllerClosedSessionDurableCheckpoint(t *testing.T) {
	for _, mapAbsent := range []bool{false, true} {
		t.Run(map[bool]string{false: "tracked", true: "map-absent-retry"}[mapAbsent], func(t *testing.T) {
			c, _, p, _ := bgpControllerFixture(t, false)
			e := checkpointControllerProcess(t, c)
			c.active = nil
			entries, _ := c.journal.Entries()
			if c.installActive(context.Background(), entries) != nil {
				t.Fatal("deny fixture")
			}
			original := *e.BGPProcess
			if mapAbsent {
				delete(c.bgpProcesses, e.DeliveryID)
			}
			proved := 0
			c.bgpRecover = func(id bgpengine.ProcessIdentity) error {
				if !mapAbsent && !p.closed {
					t.Fatal("proof before child close")
				}
				if !reflect.DeepEqual(id, original) {
					t.Fatal("identity changed before proof")
				}
				proved++
				return nil
			}
			if c.finishKnownBGPSession(e) != nil {
				t.Fatal("known cleanup refused")
			}
			latest, _ := c.journal.Entries()
			want := original
			want.Stage = "cleaned"
			if proved != 1 || !reflect.DeepEqual(*latest[0].BGPProcess, want) || c.bgpProcesses[e.DeliveryID] != nil {
				t.Fatal("cleanup not durably checkpointed")
			}
		})
	}
}
func TestBGPControllerFailedProcessProofRetainsDuty(t *testing.T) {
	c, _, _, _ := bgpControllerFixture(t, false)
	e := checkpointControllerProcess(t, c)
	c.active = nil
	entries, _ := c.journal.Entries()
	if c.installActive(context.Background(), entries) != nil {
		t.Fatal("deny fixture")
	}
	c.bgpRecover = func(bgpengine.ProcessIdentity) error { return ErrRuntimeController }
	if c.finishKnownBGPSession(e) == nil {
		t.Fatal("unknown artifact proof admitted")
	}
	latest, _ := c.journal.Entries()
	if !reflect.DeepEqual(latest[0].BGPProcess, e.BGPProcess) || c.bgpProcesses[e.DeliveryID] == nil {
		t.Fatal("failed proof erased duty or handle")
	}
	c.bgpRecover = func(bgpengine.ProcessIdentity) error { return nil }
	if c.finishKnownBGPSession(e) != nil {
		t.Fatal("exact cleanup retry refused")
	}
}
func TestBGPControllerObservationLossCheckpointsBeforeHandleRemoval(t *testing.T) {
	c, f, p, _ := bgpControllerFixture(t, true)
	e := checkpointControllerProcess(t, c)
	active := c.active[e.Allocation.ConnectionID]
	active.Entry = e
	c.active[e.Allocation.ConnectionID] = active
	p.observationError = true
	c.bgpRecover = func(bgpengine.ProcessIdentity) error {
		if !p.closed {
			t.Fatal("proof before close")
		}
		if c.bgpProcesses[e.DeliveryID] == nil {
			t.Fatal("handle erased before durable proof")
		}
		return nil
	}
	entries, _ := c.journal.Entries()
	if c.reconcileActiveBGP(context.Background(), entries) != nil {
		t.Fatal("loss reconciliation")
	}
	latest, _ := c.journal.Entries()
	if latest[0].BGPProcess.Stage != "cleaned" || len(c.active) != 0 || c.bgpProcesses[e.DeliveryID] != nil || f.routes[0][e.Allocation.Tunnels[0].RemotePrefixes[0].String()] {
		t.Fatal("lost session retained durable-ready duty, route or authority")
	}
}
