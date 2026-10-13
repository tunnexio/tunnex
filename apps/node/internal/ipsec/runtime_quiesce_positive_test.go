package ipsec

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func azureWarmStopEntry(t *testing.T) RuntimeJournalEntry {
	e := azureCleanupEntryFixture(t)
	q := quiescedFixture(t)
	e.Phase = RuntimeApplied
	e.CleanupID = q.CleanupID
	e.CleanupDesiredRevision = 0
	e.CoveredDeliveryRevision = 0
	p := *q.BGPProcess
	p.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g1")
	p.Namespace = e.Allocation.Namespace
	e.BGPProcess = &p
	e.Restoration = q.Restoration
	e.BGPRoutes = q.BGPRoutes
	for i, a := range e.Allocation.Tunnels {
		e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
	}
	return e
}

func TestRuntimeQuiesceAzureNarrowOwnedWithdrawal(t *testing.T) {
	for _, bad := range []string{"", "foreign", "mixed", "duplicate", "reqid", "allocation", "namespace", "boot", "cleanup", "phase"} {
		t.Run(map[bool]string{true: "owned", false: bad}[bad == ""], func(t *testing.T) {
			e := azureWarmStopEntry(t)
			ns, boot := e.Allocation.Namespace, e.Restoration.BootID
			d, n := azureCleanupDaemonFixture(t, e, func(c viciMessage) {
				switch bad {
				case "foreign":
					c["remote-ts"] = viciList("203.0.113.0/24")
				case "mixed":
					c["local-ts"] = viciList("0.0.0.0/0", e.Allocation.Tunnels[0].InsideAddress.String())
				case "duplicate":
					c["local-ts"] = viciList(e.Allocation.Tunnels[0].InsideAddress.String(), e.Allocation.Tunnels[0].InsideAddress.String())
				case "reqid":
					c["reqid"] = viciText("999")
				}
			})
			switch bad {
			case "allocation":
				e.Allocation.Tunnels[0].XFRMID++
			case "namespace":
				ns = "net:[42]"
			case "boot":
				boot = "00000000-0000-4000-8000-000000000001"
			case "cleanup":
				e.CleanupDesiredRevision = 99
			case "phase":
				e.Phase = RuntimeCleanupPending
			}
			err := d.removeAzureQuiesceTunnel(t.Context(), e, 0, ns, boot)
			if bad == "" {
				if err != nil || *n != 2 {
					t.Fatal("exact narrow negative stop refused", err, *n)
				}
			} else if err == nil || *n != 0 {
				t.Fatal("foreign stop mutated", bad, *n)
			}
		})
	}
}

// A transaction model, not native qualification: command/FRR readers below are
// synthetic. The real controller, journal transitions, nonce authority, VICI
// requests, kernel writer and generation checkpoints are exercised end to end.
func TestRuntimeQuiesceDurableRestartFreshLeaseAndReadyGeneration(t *testing.T) {
	ctx := t.Context()
	c, f, p, denied := bgpControllerFixture(t, true)
	e := checkpointControllerProcess(t, c)
	e.Restoration = &RuntimeRestoration{BootID: e.BGPProcess.BootID, Retired: []RuntimeRetiredEpoch{}}
	if c.journal.Save([]RuntimeJournalEntry{e}) != nil {
		t.Fatal("boot checkpoint")
	}
	active := c.active[e.Allocation.ConnectionID]
	active.Entry = e
	c.active[e.Allocation.ConnectionID] = active
	env := active.Environment
	c.config.Environment = &mtuEnvironmentFixture{env: env}
	n := 0
	c.config.Daemon = daemonInventoryStub(nil, viciMessage{}, &n)
	c.bgpRecover = func(id bgpengine.ProcessIdentity) error {
		if !p.closed || !reflect.DeepEqual(id, *e.BGPProcess) {
			t.Fatal("close proof identity")
		}
		return nil
	}
	absentCount := 0
	absent := func(_ context.Context, entry RuntimeJournalEntry) error {
		absentCount++
		if !validQuiescedEntry(entry) || !f.deleted[0] || !f.deleted[1] || len(f.routes[0])+len(f.routes[1]) != 0 {
			return ErrRuntimeController
		}
		return nil
	}
	joined := false
	proof := quiesceProofInputs{boot: func() (string, error) { return e.Restoration.BootID, nil }, absent: absent, complete: func(ctx context.Context, entries []RuntimeJournalEntry, _ DaemonInventory, close func() error) error {
		if !*denied || !p.closed || close() != nil || ctx.Err() != nil {
			return ErrRuntimeController
		}
		return c.journal.Save(entries)
	}}
	if err := c.quiesce(ctx, func() error { joined = true; return nil }, proof); err != nil {
		t.Fatal("quiesce", err)
	}
	entries, _ := c.journal.Entries()
	if !joined || absentCount != 1 || entries[0].Phase != RuntimeQuiesced || entries[0].BGPProcess.Stage != "cleaned" {
		t.Fatal("durable stop missing")
	}
	original := entries[0]
	directory := c.journal.dir
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(directory, e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	restarted := &RuntimeController{journal: j, kernel: f.applier(), namespace: c.namespace, qualification: c.qualification, config: c.config, replace: c.replace, prove: c.prove, recoveryObserve: c.recoveryObserve}
	if err = restarted.Start(ctx); err != nil {
		t.Fatal("startup", err)
	}
	if len(restarted.active) != 0 {
		t.Fatal("startup manufactured authority")
	}
	// Extend the existing synthetic kernel command fixture to model new objects.
	baseRun := f.run
	restarted.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
		q := strings.Join(args, " ")
		if strings.HasPrefix(q, "link add name ") {
			for i, a := range f.p.Tunnels {
				if args[3] == a.Name {
					f.deleted[i] = false
					f.owned[i].InterfaceIndex = 20 + i
					return nil, nil
				}
			}
		}
		if strings.HasPrefix(q, "link set ") || strings.HasPrefix(q, "-4 addr add ") {
			return nil, nil
		}
		return baseRun(ctx, args...)
	}
	requests := 0
	restarted.client = maintenanceLeaseFunc(func(_ context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
		requests++
		if len(r.Nonce) != 64 {
			t.Fatal("not a fresh nonce")
		}
		return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}, nil
	})
	restarted.bgpStart = func(_ context.Context, current RuntimeJournalEntry, _ bgpengine.Config) (runtimeBGPSession, error) {
		old := *current.BGPProcess
		ready := *e.BGPProcess
		ready.Generation = 2
		ready.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g2")
		ready.DirectoryFile.Inode = 50
		for _, stage := range []string{"reserved", "partial", "ready"} {
			id := ready
			id.Stage = stage
			id.Files = append([]bgpengine.NamedFileIdentity(nil), ready.Files...)
			id.Children = append([]bgpengine.ChildIdentity(nil), ready.Children...)
			if stage != "ready" {
				id.Files = nil
				for _, file := range ready.Files {
					if strings.HasSuffix(file.Name, ".conf") || file.Name == "supervisor.lock" {
						id.Files = append(id.Files, file)
					}
				}
				id.Children = []bgpengine.ChildIdentity{}
				if stage == "partial" {
					id.Children = append(id.Children, ready.Children[0])
				}
			}
			next, _ := j.Entries()
			next[0].BGPProcess = &id
			if stage == "reserved" {
				next[0].BGPProcessRetired = append(next[0].BGPProcessRetired, old)
			}
			if err := j.Save(next); err != nil {
				return nil, fmt.Errorf("%s checkpoint: %w", stage, err)
			}
		}
		return &bgpSessionFixture{routes: []bgpengine.LearnedRoute{{Prefix: e.Allocation.Tunnels[0].RemotePrefixes[0], Slot: 1}}}, nil
	}
	entries, _ = j.Entries()

	m := bgpMaterialFixture()
	m.ID = e.DeliveryID
	m.DesiredRevision = e.Engines[0].Binding.DesiredRevision
	m.Manifest.OrgID = e.Engines[0].Binding.OrgID
	m.Manifest.NodeID = e.Engines[0].Binding.GatewayID
	m.Manifest.ConnectionID = e.Allocation.ConnectionID
	m.Manifest.SiteID = e.SiteID
	for i, tunnel := range e.Allocation.Tunnels {
		m.Manifest.Tunnels[i].ID = tunnel.TunnelID
		m.Manifest.Tunnels[i].LinkName = tunnel.Name
		m.Manifest.Tunnels[i].XFRMID = tunnel.XFRMID
		m.Manifest.Tunnels[i].ReqID = e.Engines[i].ReqID
		m.Secrets[i].TunnelID = tunnel.TunnelID
	}
	runtimeReseal(&m)
	if m.OwnershipDigest != e.OwnershipDigest {
		t.Fatal("fixture manifest differs from immutable journal")
	}

	ack, err := restarted.applyBGPProof(ctx, m, entries, 0, env, nil, func() bool { return true }, absent)
	if err != nil {
		t.Fatal("fresh restage", err)
	}
	final, _ := j.Entries()
	got := final[0]
	if ack.Result != "applied" || requests != 1 || absentCount != 2 || got.Phase != RuntimeApplied || got.BGPProcess.Stage != "ready" || got.BGPProcess.Generation != 2 || len(got.BGPProcessRetired) != 1 || !reflect.DeepEqual(got.BGPProcessRetired[0], *original.BGPProcess) || got.Observed[0].InterfaceIndex != 20 || got.Observed[1].InterfaceIndex != 21 || len(restarted.active) != 1 || len(got.BGPRoutes.Owned) != 1 {
		t.Fatal("restart did not preserve history and freshly restage")
	}
}
