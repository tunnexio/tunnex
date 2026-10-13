package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAzureRecreatedCleanupUsesCompleteJournal(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "foreign-selector"}[foreign], func(t *testing.T) {
			_, first := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
			priors := []RuntimeJournalEntry{retainedAzure(first)}
			for len(priors) < 26 {
				_, next := azureRecreationMaterial(t, priors[:1], []string{"10.231.0.0/16"}, 8)
				priors = append(priors, retainedAzure(next))
			}
			m, e := azureRecreationMaterial(t, priors, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
			m.DesiredRevision = 4
			m.Manifest.DesiredRevision = 4
			runtimeReseal(&m)
			var err error
			e, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, e.Allocation.Namespace)
			if err != nil {
				t.Fatal(err)
			}
			j, openErr := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer j.Close()
			c := &RuntimeController{started: true, journal: j, qualification: testRuntimeQualification(e.Allocation.Namespace), config: RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, DaemonAlive: func() bool { return true }}}
			entries := []RuntimeJournalEntry{}
			// Persist every real journal transition; historical fields are never erased
			// from the complete context supplied to normal Cleanup.
			for _, old := range priors {
				cleanupID, rev, covered := old.CleanupID, old.CleanupDesiredRevision, old.CoveredDeliveryRevision
				old.Phase = RuntimeReserved
				old.CleanupID = uuid.Nil
				old.CleanupDesiredRevision = 0
				old.CoveredDeliveryRevision = 0
				entries = append(entries, old)
				if err = c.journal.Save(entries); err != nil {
					t.Fatal("reserve history", err)
				}
				i := len(entries) - 1
				entries[i].Phase = RuntimeCleanupPending
				entries[i].CleanupID = cleanupID
				entries[i].CleanupDesiredRevision = rev
				entries[i].CoveredDeliveryRevision = covered
				if err = c.journal.Save(entries); err != nil {
					t.Fatal("pending history", err)
				}
				entries[i].Phase = RuntimeRetainedRefusal
				if err = c.journal.Save(entries); err != nil {
					t.Fatal("retained history", err)
				}
			}
			entries = append(entries, e)
			if err = c.journal.Save(entries); err != nil {
				t.Fatal(err)
			}
			e.Phase = RuntimeApplying
			entries[len(entries)-1] = e
			if err = c.journal.Save(entries); err != nil {
				t.Fatal(err)
			}
			e.Phase = RuntimeCleanupPending
			e.CleanupID = uuid.New()
			e.CleanupDesiredRevision = 5
			e.CoveredDeliveryRevision = 4
			entries[len(entries)-1] = e
			if err = c.journal.Save(entries); err != nil {
				t.Fatal(err)
			}
			if e.AzureBGPRecreationVersion != 1 || len(e.RetainedGuardPredecessors) != 26 {
				t.Fatal("causal recreation fixture missing")
			}
			c.namespace = func() (string, error) { return e.Allocation.Namespace, nil }
			denied := false
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, connection := range in.Connections {
					if len(connection.Grants) != 0 {
						t.Fatal("cleanup gained authority")
					}
				}
				denied = true
				return RenderGuard(in)
			}
			daemon, mutations := azureCleanupDaemonFixture(t, e, func(child viciMessage) {
				if foreign {
					child["local-ts"] = viciList("203.0.113.0/24")
				}
			})
			base := daemon.request
			daemon.request = func(ctx context.Context, cmd, event string, msg viciMessage) (viciMessage, []viciMessage, error) {
				if cmd == "terminate" && !denied {
					t.Fatal("mutation before denial")
				}
				return base(ctx, cmd, event, msg)
			}
			c.config.Daemon = daemon
			c.config.Environment = &mtuEnvironmentFixture{}
			c.kernel = &KernelApplier{namespace: c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "xfrm") {
					return nil, nil
				}
				return []byte("[]"), nil
			}}
			cleanup := RuntimeCleanup{RuntimeDelivery: m.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
			cleanup.ID = e.CleanupID
			cleanup.Kind = "cleanup"
			cleanup.DesiredRevision = 5
			cleanup.CoversDeliveryRevision = 4
			raw, _ := json.Marshal(cleanup.Lineage)
			cleanup.OwnershipDigest = stringDigest(raw)
			ack, err := c.Cleanup(t.Context(), cleanup)
			if foreign {
				if err == nil || *mutations != 0 || !denied {
					t.Fatal("foreign recreated cleanup mutated")
				}
				return
			}
			if err != nil || *mutations != 2 || !ack.GuardRetained {
				t.Fatal("complete v11 recreated cleanup refused", err, *mutations)
			}
			final, _ := c.journal.Entries()
			if len(final) != 27 || final[26].Phase != RuntimeRetainedRefusal {
				t.Fatal("complete history lost")
			}
			for i := range priors {
				a, _ := json.Marshal(priors[i])
				b, _ := json.Marshal(final[i])
				if string(a) != string(b) {
					t.Fatal("historical predecessor mutated")
				}
			}
		})
	}
}

func TestAzureRecreatedCleanupRejectsIncompleteOrChangedContext(t *testing.T) {
	_, first := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	first = retainedAzure(first)
	_, current := azureRecreationMaterial(t, []RuntimeJournalEntry{first}, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
	current.Phase = RuntimeCleanupPending
	current.CleanupID = uuid.New()
	current.CleanupDesiredRevision = current.Engines[0].Binding.DesiredRevision + 1
	current.CoveredDeliveryRevision = current.Engines[0].Binding.DesiredRevision
	original := runtimeJournalPayload{Version: 11, OwnerID: first.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{first, current}}
	if !validJournalPayload(original) {
		t.Fatal("full predecessor context invalid")
	}
	for _, scenario := range []string{"legacy_detached", "version10", "missing_predecessor", "wrong_owner", "duplicate_delivery", "unknown_reference", "changed_cleanup", "stale_selected", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			p := cloneJournal(original)
			e := cloneJournal(original).Entries[1]
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "version10":
				p.Version = 10
			case "missing_predecessor":
				p.Entries = p.Entries[1:]
			case "wrong_owner":
				p.OwnerID = uuid.New()
			case "duplicate_delivery":
				p.Entries = append(p.Entries, p.Entries[1])
			case "unknown_reference":
				p.Entries[1].RetainedGuardPredecessors[0].DeliveryID = uuid.New()
			case "changed_cleanup":
				p.Entries[0].CleanupID = uuid.New()
			case "stale_selected":
				e.CleanupID = uuid.New()
			case "canceled":
				cancel()
			}
			daemon, n := azureCleanupDaemonFixture(t, e, nil)
			var err error
			if scenario == "legacy_detached" {
				err = daemon.removeAzureCleanupTunnel(ctx, e, 0, e.Allocation.Namespace)
			} else {
				err = daemon.removeAzureCleanupTunnelJournal(ctx, e, 0, e.Allocation.Namespace, p)
			}
			if err == nil || *n != 0 {
				t.Fatal("changed context allowed mutation", scenario, *n)
			}
		})
	}
}

func TestAzureCleanupSnapshotRejectsChangedPersistedJournal(t *testing.T) {
	for _, scenario := range []string{"valid", "bad_checksum", "valid_changed_payload"} {
		t.Run(scenario, func(t *testing.T) {
			e := azureCleanupEntryFixture(t)
			j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			reserved := e
			reserved.Phase = RuntimeReserved
			reserved.CleanupID = uuid.Nil
			reserved.CleanupDesiredRevision = 0
			reserved.CoveredDeliveryRevision = 0
			if j.Save([]RuntimeJournalEntry{reserved}) != nil || j.Save([]RuntimeJournalEntry{e}) != nil {
				t.Fatal("save cleanup fixture")
			}
			if scenario != "valid" {
				disk := cloneJournal(j.payload)
				checksum := journalChecksum(disk)
				if scenario == "bad_checksum" {
					checksum = strings.Repeat("0", 64)
				} else {
					disk.Sequence++
					checksum = journalChecksum(disk)
				}
				raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: disk, Checksum: checksum})
				if os.WriteFile(filepath.Join(j.dir, "journal.json"), raw, 0600) != nil {
					t.Fatal("disk fixture")
				}
			}
			snapshot, err := j.cleanupSnapshot()
			if scenario != "valid" {
				if err == nil {
					t.Fatal("changed disk authority admitted")
				}
				return
			}
			if err != nil || len(snapshot.Entries) != 1 {
				t.Fatal("real complete snapshot refused", err)
			}
			snapshot.Entries[0].CleanupDesiredRevision++
			unchanged, _ := j.Entries()
			if unchanged[0].CleanupDesiredRevision != e.CleanupDesiredRevision {
				t.Fatal("snapshot aliases journal")
			}
		})
	}
}
