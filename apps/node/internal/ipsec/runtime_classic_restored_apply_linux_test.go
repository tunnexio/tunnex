//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"testing"
)

// Modeled I/O, actual generic controller and kernel parser; no real-SA claim.
func TestClassicRestoredApplyUsesReservedGeneration(t *testing.T) {
	testClassicApplyBoot(t, true, false)
}
func TestClassicInitialApplyRecordsProvenCurrentBoot(t *testing.T) {
	testClassicApplyBoot(t, false, false)
}
func TestClassicInitialApplyRefusesChangedIndexBeforeBootBinding(t *testing.T) {
	testClassicApplyBoot(t, false, true)
}
func testClassicApplyBoot(t *testing.T, restored, changedIndex bool) {
	t.Helper()
	m := classicMaterialFixture()
	old, _, entryErr := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if entryErr != nil {
		t.Fatal(entryErr)
	}
	old.Observed[0] = Ownership{Namespace: old.Allocation.Namespace, InterfaceName: old.Allocation.Tunnels[0].Name, InterfaceIndex: 10, XFRMID: old.Allocation.Tunnels[0].XFRMID}
	j, err := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if restored {
		old = saveAppliedRestorationFixture(t, j, old)
	}
	next := old
	next.Observed = [2]Ownership{}
	if restored {
		next.Allocation.Generation = uuid.New()
	}
	next.Allocation.Tunnels[0].Alias = KernelTunnelAlias(next.Allocation.Generation, next.Allocation.Tunnels[0].TunnelID)
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	if restored {
		next.Restoration = &RuntimeRestoration{BootID: boot, Epoch: 1, Retired: []RuntimeRetiredEpoch{{Entry: flattenedRestorationEntry(old), NewBootID: boot, NewNamespace: next.Allocation.Namespace, NewGeneration: next.Allocation.Generation, Termination: "supervisor-confirmed-runtime-stop", EvidenceDigest: stringDigest([]byte("synthetic consumed receipt"))}}}
	}
	if restored {
		if err = j.Save([]RuntimeJournalEntry{next}); err != nil {
			t.Fatal(err)
		}
	}
	f := next.Allocation.Tunnels[0]
	nativeMutations := 0
	kernel := &KernelApplier{namespace: func() (string, error) { return next.Allocation.Namespace, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		q := strings.Join(args, " ")
		var out any
		switch {
		case strings.Contains(q, "link show"):
			index := 10
			saved, _ := j.Entries()
			if changedIndex && len(saved) == 1 && saved[0].Phase == RuntimeApplied {
				index = 11
			}
			out = []map[string]any{{"ifname": f.Name, "ifindex": index, "mtu": runtimeProfileMTU(next.Allocation.ProfileID), "ifalias": f.Alias, "flags": []string{"UP"}, "linkinfo": map[string]any{"info_kind": "xfrm", "info_data": map[string]any{"if_id": fmt.Sprintf("0x%x", f.XFRMID)}}}}
		case strings.Contains(q, "addr show"):
			out = []map[string]any{{"ifname": f.Name, "ifindex": 10, "addr_info": []map[string]any{{"family": "inet", "local": f.InsideAddress.Addr().String(), "prefixlen": f.InsideAddress.Bits()}}}}
		case strings.Contains(q, "-4 route show"):
			rows := []map[string]any{}
			for _, p := range f.RemotePrefixes {
				rows = append(rows, map[string]any{"flags": []string{}, "dst": p.String(), "dev": f.Name, "table": "254", "protocol": "242", "type": "1", "scope": "253", "metric": 50001})
			}
			out = rows
		case strings.HasPrefix(q, "-j"):
			return []byte(`[]`), nil
		case strings.HasPrefix(q, "xfrm "):
			return nil, nil
		default:
			nativeMutations++
			return nil, fmt.Errorf("unexpected mutation %s", q)
		}
		return json.Marshal(out)
	}}
	if _, err := kernel.snapshot(context.Background(), next.Allocation); err != nil {
		t.Fatal("modeled current kernel snapshot", err)
	}
	daemonMutations := 0
	env := RuntimeEnvironment{Namespace: next.Allocation.Namespace, LocalIngressIndices: []int{2}, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: next.Engines[0].LocalAddress}}}
	permits, proofs := 0, 0
	c := &RuntimeController{started: true, journal: j, kernel: kernel, qualification: testRuntimeQualification(next.Allocation.Namespace), client: &recoveryTestLease{ttl: 60000}, namespace: func() (string, error) { return next.Allocation.Namespace, nil }, config: RuntimeControllerConfig{Diagnostic: func(d RuntimeDiagnostic) { t.Log(d.Operation, d.Stage, d.Refused) }, OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, Environment: &mtuEnvironmentFixture{env: env}, Daemon: daemonInventoryStub(nil, viciMessage{}, &daemonMutations), DaemonAlive: func() bool { return true }}, recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", ""} }, prove: func(ctx context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
		proofs++
		if e.Allocation.Generation != next.Allocation.Generation || e.Allocation.Tunnels[0].Alias != f.Alias {
			return ErrRuntimeController
		}
		_, err := kernel.snapshot(ctx, e.Allocation)
		return err
	}, replace: func(_ context.Context, g GuardIntent) (GuardManifest, error) {
		for _, x := range g.Connections {
			if !x.PrefixOnly {
				permits++
				if x.TunnelCount != 1 || x.Tunnels[1] != (Ownership{}) {
					t.Fatal("inactive Classic permit")
				}
			}
		}
		return RenderGuard(g)
	}}
	ack, err := c.Apply(context.Background(), m)
	if changedIndex {
		saved, readErr := j.Entries()
		if err == nil || ack.DeliveryID != uuid.Nil || readErr != nil || len(saved) != 1 || saved[0].Restoration != nil || len(c.active) != 0 {
			t.Fatal("changed current index accepted or historical boot manufactured", err, readErr)
		}
		return
	}
	if err != nil || ack.DeliveryID != m.ID {
		t.Fatal("restored generic apply refused", err, nativeMutations, daemonMutations, permits, proofs)
	}
	if nativeMutations != 0 || daemonMutations == 0 || permits == 0 || proofs == 0 {
		t.Fatal("readback/permit path not exercised", nativeMutations, daemonMutations, permits, proofs)
	}
	entries, err := j.Entries()
	if err != nil || len(entries) != 1 || (restored && !reflect.DeepEqual(entries[0].Restoration, next.Restoration)) || entries[0].Allocation.Generation != next.Allocation.Generation || entries[0].Allocation.Tunnels[0].Alias != f.Alias || entries[0].Observed[1] != (Ownership{}) {
		t.Fatal("generation or retired duty changed", err)
	}
	if !restored {
		if entries[0].Restoration == nil || entries[0].Restoration.BootID != boot || entries[0].Restoration.Epoch != 0 || len(entries[0].Restoration.Retired) != 0 {
			t.Fatal("initial Classic applied acknowledgement omitted proven current boot")
		}
		if len(c.active) != 1 {
			t.Fatal("initial boot binding lost active lease")
		}
	}
}
