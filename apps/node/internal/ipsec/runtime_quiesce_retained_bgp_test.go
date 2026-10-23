package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This is a native-I/O model: the finite authority, exact journal and controller
// ownership checks are real; process directories and route/VICI reads are modeled.
func quiescedRetainedRig(t *testing.T) (*RuntimeController, []RuntimeJournalEntry, quiescedRetainedBGPProof, *int, *int, *time.Duration) {
	t.Helper()
	c, _, _, _ := bgpControllerFixture(t, true)
	e := checkpointControllerProcess(t, c)
	for i := range e.Engines {
		e.Engines[i].Binding.DesiredRevision = 8
	}
	e.Restoration = &RuntimeRestoration{BootID: e.BGPProcess.BootID}
	var entries []RuntimeJournalEntry
	for _, revision := range []int64{2, 4, 6} {
		old := cloneRuntimeEntries([]RuntimeJournalEntry{e})[0]
		old.DeliveryID = uuid.New()
		old.Allocation.Generation = old.DeliveryID
		old.Phase = RuntimeRetainedRefusal
		old.CleanupID = uuid.New()
		old.CleanupDesiredRevision = revision + 1
		old.CoveredDeliveryRevision = revision
		for i := range old.Engines {
			old.Engines[i].Binding.DesiredRevision = revision
			old.Allocation.Tunnels[i].Alias = "tunnex-ipsec:" + old.DeliveryID.String() + ":" + old.Allocation.Tunnels[i].TunnelID.String()
		}
		old.BGPProcess.Stage = "cleaned"
		old.BGPProcess.Directory = filepath.Join(filepath.Dir(e.BGPProcess.Directory), "bgp-"+old.DeliveryID.String()+"-g1")
		old.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
		entries = append(entries, old)
	}
	entries = append(entries, e)
	c.journal.Close()
	dir := journalDir(t)
	payload := runtimeJournalPayload{Version: 12, OwnerID: c.config.GatewayID, Sequence: 1, Entries: entries}
	if !validJournalPayload(payload) {
		t.Fatal("invalid retained cohort fixture")
	}
	raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(dir, c.config.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	c.journal = j
	a := c.active[e.Allocation.ConnectionID]
	a.Entry = e
	a.Delivery.ID = e.DeliveryID
	a.Identity.Binding = e.Engines[0].Binding
	elapsed := time.Duration(0)
	a.Authority = NewPermitLeaseAuthority()
	a.Authority.elapsed = func() time.Duration { return elapsed }
	req, err := a.Authority.Begin(a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if a.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}) != nil {
		t.Fatal("authority")
	}
	c.active[e.Allocation.ConnectionID] = a
	reads, processes := 0, 0
	routeRaw := []byte(fmt.Sprintf(`[{"dst":%q,"dev":%q,"table":"254","protocol":"242","metric":50001,"scope":"253","type":"1","flags":[]},{"dst":%q,"dev":%q,"table":"254","protocol":"242","metric":50002,"scope":"253","type":"1","flags":[]}]`, e.Allocation.Tunnels[0].BGP.Peer.String(), e.Allocation.Tunnels[0].Name, e.Allocation.Tunnels[1].BGP.Peer.String(), e.Allocation.Tunnels[1].Name))
	proof := quiescedRetainedBGPProof{
		strict: func(_ context.Context, old RuntimeJournalEntry) error {
			if !azureBGPPeersAbsent(old, routeRaw) {
				return ErrRuntimeController
			}
			return nil
		},
		current: func(context.Context, runtimeActive) error { reads++; return nil },
		routes:  func(context.Context) ([]byte, error) { return routeRaw, nil },
		processes: func(_ context.Context, old RuntimeJournalEntry, boot, ns string) error {
			processes++
			if old.BGPProcess.Stage != "cleaned" || boot != old.Restoration.BootID || ns != old.Allocation.Namespace {
				return ErrRuntimeController
			}
			return nil
		},
		boot:   func() (string, error) { return e.Restoration.BootID, nil },
		daemon: func(context.Context) (DaemonInventory, error) { return DaemonInventory{}, nil },
	}
	return c, entries, proof, &reads, &processes, &elapsed
}

func TestQuiescedOtherOwnerRetainedBGPRecognizesExactLiveSuccessor(t *testing.T) {
	c, entries, proof, reads, processes, _ := quiescedRetainedRig(t)
	a := c.active[entries[0].Allocation.ConnectionID]
	deadline := a.Authority.deadline
	before := cloneRuntimeEntries(entries)
	if err := c.proveQuiescedRetainedBGP(context.Background(), entries, proof); err != nil {
		t.Fatalf("three cleaned predecessors rejected exact live successor peer routes: %v", err)
	}
	if *reads != 2 || *processes != 3 || a.Authority.deadline != deadline || !reflect.DeepEqual(entries, before) || !reflect.DeepEqual(c.active[a.Entry.Allocation.ConnectionID], a) {
		t.Fatal("cohort proof skipped old duties, repeated successor proof, or changed finite authority/history")
	}
}

func TestQuiescedRetainedBGPCohortRefusesAuthorityAndOwnershipDrift(t *testing.T) {
	for _, name := range []string{"expired-before", "expires-during-history", "deadline-changed", "journal-changed", "active-changed", "process-replaced", "process-stopped", "namespace-changed", "boot-changed", "old-process-survives", "qualification-fails", "qualification-fails-after", "canceled"} {
		t.Run(name, func(t *testing.T) {
			c, entries, proof, _, _, elapsed := quiescedRetainedRig(t)
			id := entries[0].Allocation.ConnectionID
			a := c.active[id]
			deadline := a.Authority.deadline
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before, _ := c.journal.Entries()
			oldProcess := proof.processes
			calls := 0
			proof.processes = func(ctx context.Context, e RuntimeJournalEntry, boot, ns string) error {
				if err := oldProcess(ctx, e, boot, ns); err != nil {
					return err
				}
				calls++
				if calls != 2 {
					return nil
				}
				switch name {
				case "expires-during-history":
					*elapsed = 56 * time.Second
				case "deadline-changed":
					a.Authority.deadline += time.Second
				case "journal-changed":
					entries[0].CoveredDeliveryRevision++
				case "active-changed":
					next := c.active[id]
					next.Identity.PolicyHash = "changed"
					c.active[id] = next
				case "process-replaced":
					c.bgpProcesses[a.Entry.DeliveryID] = &bgpSessionFixture{}
				case "process-stopped":
					c.bgpProcesses[a.Entry.DeliveryID].(*bgpSessionFixture).closed = true
				case "namespace-changed":
					c.namespace = func() (string, error) { return "net:[999]", nil }
				case "old-process-survives":
					return ErrRuntimeController
				case "canceled":
					cancel()
				}
				return nil
			}
			if name == "boot-changed" {
				proof.boot = func() (string, error) {
					if calls >= 2 {
						return uuid.NewString(), nil
					}
					return a.Entry.Restoration.BootID, nil
				}
			}
			if name == "expired-before" {
				*elapsed = 56 * time.Second
			}
			if name == "qualification-fails" {
				proof.current = func(context.Context, runtimeActive) error { return ErrRuntimeController }
			}
			if name == "qualification-fails-after" {
				n := 0
				proof.current = func(context.Context, runtimeActive) error {
					n++
					if n == 2 {
						return ErrRuntimeController
					}
					return nil
				}
			}
			if c.proveQuiescedRetainedBGP(ctx, entries, proof) == nil {
				t.Fatal("unsafe cohort accepted")
			}
			if name != "expired-before" && name != "qualification-fails" && calls < 2 {
				t.Fatal("hostile mutation boundary was not reached")
			}
			after, _ := c.journal.Entries()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("absence proof mutated journal")
			}
			if name != "deadline-changed" && a.Authority.deadline != deadline {
				t.Fatal("absence proof renewed authority")
			}
		})
	}
}

func TestQuiescedRetainedBGPRequiresExactCompletePeerRouteCensus(t *testing.T) {
	for _, name := range []string{"duplicate", "foreign-device", "wrong-table", "wrong-protocol", "wrong-metric", "wrong-scope", "wrong-type", "extra-gateway", "missing-peer", "malformed", "native-read-error", "unknown-destination"} {
		t.Run(name, func(t *testing.T) {
			c, entries, proof, _, _, _ := quiescedRetainedRig(t)
			raw, _ := proof.routes(context.Background())
			var rows []map[string]any
			if json.Unmarshal(raw, &rows) != nil {
				t.Fatal("fixture")
			}
			switch name {
			case "duplicate":
				rows = append(rows, rows[0])
			case "foreign-device":
				rows[0]["dev"] = "foreign0"
			case "wrong-table":
				rows[0]["table"] = "100"
			case "wrong-protocol":
				rows[0]["protocol"] = "4"
			case "wrong-metric":
				rows[0]["metric"] = 50002
			case "wrong-scope":
				rows[0]["scope"] = "0"
			case "wrong-type":
				rows[0]["type"] = "6"
			case "extra-gateway":
				rows[0]["gateway"] = "192.0.2.1"
			case "missing-peer":
				rows = rows[:1]
			case "unknown-destination":
				rows = append(rows, map[string]any{"dst": "unknown"})
			}
			raw, _ = json.Marshal(rows)
			if name == "malformed" {
				raw = []byte("{")
			}
			proof.routes = func(context.Context) ([]byte, error) {
				if name == "native-read-error" {
					return nil, ErrRuntimeController
				}
				return raw, nil
			}
			if c.proveQuiescedRetainedBGP(context.Background(), entries, proof) == nil {
				t.Fatal("foreign/partial peer census accepted")
			}
		})
	}
}

func TestQuiescedRetainedBGPOldDaemonNamesRemainObligations(t *testing.T) {
	for _, name := range []string{"connection", "shared-key", "ike", "child", "read-error"} {
		t.Run(name, func(t *testing.T) {
			c, entries, proof, _, _, _ := quiescedRetainedRig(t)
			old := engineName(entries[0].Engines[0])
			proof.daemon = func(context.Context) (DaemonInventory, error) {
				d := DaemonInventory{}
				switch name {
				case "connection":
					d.Connections = []string{old}
				case "shared-key":
					d.SharedKeys = []string{old}
				case "ike":
					d.SAs = []DaemonIKE{{Name: old}}
				case "child":
					d.SAs = []DaemonIKE{{Name: "current", Children: []DaemonChild{{Name: old}}}}
				case "read-error":
					return d, ErrRuntimeController
				}
				return d, nil
			}
			if c.proveQuiescedRetainedBGP(context.Background(), entries, proof) == nil {
				t.Fatal("old daemon duty ignored")
			}
		})
	}
}

func TestQuiescedRetainedBGPUnknownSuccessorKeepsStrictAbsence(t *testing.T) {
	for _, name := range []string{"missing-active", "wrong-binding", "wrong-site", "wrong-generation", "not-applied", "restoration-epoch", "not-cleaned", "not-newer", "different-peer", "non-aws"} {
		t.Run(name, func(t *testing.T) {
			c, entries, proof, _, _, _ := quiescedRetainedRig(t)
			id := entries[0].Allocation.ConnectionID
			a := cloneMaintenanceActive(c.active[id])
			switch name {
			case "missing-active":
				delete(c.active, id)
			case "wrong-binding":
				a.Entry.Engines[0].Binding.GatewayID = uuid.New()
			case "wrong-site":
				a.Entry.SiteID = uuid.New()
			case "wrong-generation":
				a.Entry.Allocation.Tunnels[0].XFRMID++
			case "not-applied":
				a.Entry.Phase = RuntimeApplying
			case "restoration-epoch":
				a.Entry.Restoration.Epoch++
			case "not-cleaned":
				entries[0].BGPProcess.Stage = "ready"
			case "not-newer":
				a.Entry.Engines[0].Binding.DesiredRevision = 2
			case "different-peer":
				a.Entry.BGP.LocalASN++
			case "non-aws":
				a.Entry.Allocation.ProfileID = GCPHABGPProfile
			}
			if name != "missing-active" {
				c.active[id] = a
			}
			strict := 0
			old := proof.strict
			proof.strict = func(ctx context.Context, e RuntimeJournalEntry) error { strict++; return old(ctx, e) }
			if c.proveQuiescedRetainedBGP(context.Background(), entries, proof) == nil || strict == 0 {
				t.Fatal("unknown successor escaped strict old-peer absence")
			}
		})
	}
}

func TestQuiescedRetainedBGPProductionBindingRequiresRealQualification(t *testing.T) {
	c, entries, _, _, _, _ := quiescedRetainedRig(t)
	// The private model cannot qualify production: no BGP preflight/native guard
	// or real daemon is attached. No injected current reader reaches this wrapper.
	if c.proveQuiescedRetainedBGPDuties(context.Background(), entries) == nil {
		t.Fatal("production accepted modeled qualification")
	}
}

func TestQuiescedReservationWithOtherOwnerSuccessorPreservesBothAuthorities(t *testing.T) {
	for _, mode := range []string{"success", "target-survivor", "target-lease-expired"} {
		t.Run(mode, func(t *testing.T) {
			c, entries, proof, _, _, _ := quiescedRetainedRig(t)
			a := c.active[entries[0].Allocation.ConnectionID]
			originalDeadline := a.Authority.deadline
			target := quiescedFixture(t)
			target.Phase = RuntimeQuiesced
			for i := range target.Engines {
				target.Engines[i].Binding.OrgID = c.config.OrgID
				target.Engines[i].Binding.GatewayID = c.config.GatewayID
			}
			entries = append(entries, target)
			c.journal.Close()
			dir := journalDir(t)
			payload := runtimeJournalPayload{Version: 12, OwnerID: c.config.GatewayID, Sequence: 1, Entries: entries}
			if !validJournalPayload(payload) {
				t.Fatal("invalid reservation fixture")
			}
			raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
			if err := os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			j, err := OpenRuntimeJournal(dir, c.config.GatewayID)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { j.Close() })
			c.journal = j
			identity := PermitLeaseIdentity{DeliveryID: target.DeliveryID, Binding: target.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash}
			authority := NewPermitLeaseAuthority()
			elapsed := time.Duration(0)
			authority.elapsed = func() time.Duration { return elapsed }
			req, err := authority.Begin(identity)
			if err != nil {
				t.Fatal(err)
			}
			if authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}) != nil {
				t.Fatal("target lease")
			}
			deadline := authority.deadline
			targetAbsent := false
			// Model only native I/O: the real reservation and cohort authority /
			// history checks run. The target's independent absence is not supplied
			// by the unrelated successor classification.
			absent := func(ctx context.Context, e RuntimeJournalEntry) error {
				if !reflect.DeepEqual(e, target) || c.proveQuiescedRetainedBGP(ctx, entries, proof) != nil {
					return ErrRuntimeController
				}
				targetAbsent = true
				if mode == "target-survivor" {
					return ErrRuntimeController
				}
				if mode == "target-lease-expired" {
					elapsed = 56 * time.Second
				}
				return nil
			}
			err = c.reserveQuiescedApplyProof(context.Background(), entries, len(entries)-1, authority, identity, absent)
			if !targetAbsent || (err == nil) != (mode == "success") {
				t.Fatal("target absence/fresh-authority boundary", err)
			}
			after, _ := j.Entries()
			if mode == "success" {
				if after[len(after)-1].Phase != RuntimeApplying || after[len(after)-1].Observed != ([2]Ownership{}) {
					t.Fatal("target reservation absent")
				}
			} else if after[len(after)-1].Phase != RuntimeQuiesced {
				t.Fatal("failed target gained reservation")
			}
			if !reflect.DeepEqual(after[:len(after)-1], entries[:len(entries)-1]) || !reflect.DeepEqual(c.active[a.Entry.Allocation.ConnectionID], a) || a.Authority.deadline != originalDeadline || authority.deadline != deadline {
				t.Fatal("reservation changed unrelated owner or renewed authority")
			}
		})
	}
}
