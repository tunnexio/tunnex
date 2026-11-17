package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The real canonical material, finite authority, guard renderer and journal are
// used here. Only FRR, WireGuard and kernel observations are synthetic.
func matrixConflictRig(t *testing.T, profile string, keepTransportOwner ...bool) (*renewalCycleRig, uuid.UUID, RuntimeMaterial, *bgpSessionFixture, *int) {
	t.Helper()
	r, originalID, process, originalKernel := desktopBGPRenewalRig(t, true)
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			t.Logf("diagnostic: %+v", d)
		}
	}
	var target RuntimeMaterial
	for _, m := range r.materials {
		if m.Manifest.ProfileID == profile && m.Manifest.ConnectionID != originalID {
			target = m
			break
		}
	}
	targetID := target.Manifest.ConnectionID
	if targetID == uuid.Nil || len(target.Policy.DesktopGrants) != 0 || len(r.c.active[targetID].FQDNLeaseDescriptors) != 0 {
		t.Fatal("missing ordinary unrelated target")
	}
	target.Policy.Grants = []RuntimeGrant{{Source: target.Manifest.LocalPrefixes[0], Destination: target.Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 443, PortHigh: 443, RuleID: uuid.NewString()}}
	runtimeReseal(&target)
	targetActive := r.c.active[targetID]
	_, targetGrants, parseErr := runtimeMaterialEntry(target, r.c.config.OrgID, r.c.config.GatewayID, targetActive.Environment.Namespace)
	if parseErr != nil {
		t.Fatal("target LAN grant material", parseErr)
	}
	targetActive.Grants = targetGrants
	targetActive.Environment.LocalIngressIndices = []int{2}
	r.c.active[targetID] = targetActive
	if targetActive.Entry.ContractVersion == 2 {
		r.c.recoveryPrepared[target.ID] = targetActive.Environment
	}
	r.c.config.Environment.(renewalCycleEnvironment)[targetID] = targetActive.Environment
	priorInterfaces := r.c.guard.reader.interfaces
	r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		links, err := priorInterfaces()
		return append(append([]GuardInterface(nil), links...), GuardInterface{Name: "ens4", Index: 2}), err
	}
	targetKernel := newRecoveryKernelFixture()
	targetKernel.p, targetKernel.owned = targetActive.Entry.Allocation, targetActive.Entry.Observed
	for i, tunnel := range targetKernel.p.Tunnels {
		targetKernel.routes[i] = map[string]bool{}
		if targetKernel.p.BGP {
			targetKernel.routes[i][netip.PrefixFrom(tunnel.BGP.Peer, 32).String()] = true
		}
	}
	if targetActive.Entry.BGPRoutes != nil {
		for _, route := range targetActive.Entry.BGPRoutes.Owned {
			targetKernel.routes[int(route.Slot)-1][route.Prefix.String()] = true
		}
	} else {
		for _, prefix := range targetKernel.p.Tunnels[0].RemotePrefixes {
			targetKernel.routes[0][prefix.String()] = true
		}
	}
	r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
		var joined []any
		for _, kernel := range []*recoveryKernelFixture{originalKernel, targetKernel} {
			raw, err := kernel.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			if len(raw) == 0 {
				continue
			}
			var rows []any
			if err := json.Unmarshal(raw, &rows); err != nil {
				return nil, err
			}
			joined = append(joined, rows...)
		}
		if len(joined) == 0 {
			return []byte("[]"), nil
		}
		return json.Marshal(joined)
	}}
	// The live regression has two admitted owners. Other canonical fixture
	// entries remain in the journal as denied transport, not active authority.
	retainedTransport := uuid.Nil
	if len(keepTransportOwner) == 1 && keepTransportOwner[0] {
		for id, owner := range r.c.active {
			if id != originalID && id != targetID && owner.Entry.ContractVersion == 3 {
				retainedTransport = id
				break
			}
		}
	}
	for id := range r.c.active {
		if id != originalID && id != targetID && id != retainedTransport {
			delete(r.c.active, id)
			delete(r.c.recoveryHistory, id)
		}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("initial target LAN grant", err)
	}
	targetNames := map[string]bool{}
	for _, name := range []string{guardLeaseName(targetID), guardReplyLeaseName(targetID), guardSALeaseName(targetID)} {
		targetNames[name] = true
	}
	if r.applicationDenied[originalID] || r.applicationDenied[targetID] || process.closed {
		t.Fatal("both application owners must start admitted")
	}
	// This is a native-kernel seam only. Production withdrawal must use the
	// real exact-owner RuntimeGuard transaction and verification machinery.
	flushes := 0
	r.c.guard.apply = func(_ context.Context, raw []byte) error {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			t.Fatal("invalid native transaction")
		}
		commands, ok := doc["nftables"].([]any)
		if !ok || len(commands) != 3 {
			t.Fatal("withdrawal is not exactly three target sets")
		}
		seen := map[string]bool{}
		for _, command := range commands {
			object := command.(map[string]any)
			if len(object) != 1 {
				t.Fatal("extra native mutation")
			}
			fields := object["flush"].(map[string]any)["set"].(map[string]any)
			name := fields["name"].(string)
			if fields["family"] != "inet" || fields["table"] != "tunnex_ipsec" || len(fields) != 3 || !targetNames[name] || seen[name] {
				t.Fatal("withdrawal escaped exact target ownership")
			}
			seen[name] = true
			r.installed[name] = 0
		}
		r.applicationDenied[targetID] = true
		flushes++
		return nil
	}
	if history := r.c.recoveryHistory[targetID]; history != nil {
		history.lastNow = *r.now
	}
	return r, originalID, target, process, &flushes
}

func TestMatrixScopedPolicyConflictPreservesUnrelatedBGP(t *testing.T) {
	for _, profile := range []string{"aws-bgp-ipv4-v1", "aws-static-ipv4-v1"} {
		t.Run(profile, func(t *testing.T) {
			r, originalID, target, process, flushes := matrixConflictRig(t, profile)
			original, targetID := r.c.active[originalID], target.Manifest.ConnectionID
			names := func(id uuid.UUID) []string {
				return []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)}
			}
			originalNative := map[string]time.Duration{}
			for _, n := range names(originalID) {
				originalNative[n] = r.installed[n]
				if r.installed[n] <= *r.now {
					t.Fatal("original native authority not independently live")
				}
			}
			if r.applicationDenied[originalID] || r.applicationDenied[targetID] || process.closed {
				t.Fatalf("fixture did not start with both owners admitted originalDenied=%v targetDenied=%v processClosed=%v", r.applicationDenied[originalID], r.applicationDenied[targetID], process.closed)
			}
			originalDeadline := original.Authority.deadline
			if _, err := original.Authority.RemainingForApply(original.Identity, 5*time.Second); err != nil {
				t.Fatal("original authority not independently current", err)
			}
			beforeTemplates, beforeSequence, err := r.c.journal.guardTemplates()
			if err != nil {
				t.Fatal(err)
			}

			calls := 0
			originalEpoch, targetEpoch := &runtimeDNSEpoch{}, &runtimeDNSEpoch{}
			r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, request RuntimeLeaseRequest) (RuntimeLease, error) {
				calls++
				if id != targetID || request.DeliveryID != target.ID || request.PolicyHash != target.Policy.Hash {
					t.Fatal("renewal conflict not bound to the exact target")
				}
				// Transition-only DNS owner epochs; actual DNS query proof remains
				// independently exercised by the DNS owner test suite.
				r.c.dnsView.Store(&runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{originalID: {active: original, epoch: originalEpoch}, targetID: {active: r.c.active[targetID], epoch: targetEpoch}}})
				return RuntimeLease{}, testLeaseFailure("http_409_conflict")
			})
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{target}, maintenanceAuthority(r), func() bool { return true })
			var aborted interface{ IPsecMaintenanceBatchAborted() bool }
			if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() {
				t.Error("missing scoped page-abort signal", err)
			}
			if !errors.Is(err, ErrRuntimeController) || len(result) != 0 || calls != 1 {
				t.Fatalf("conflicted batch was accepted or retried: err=%v results=%d calls=%d", err, len(result), calls)
			}
			if !r.applicationDenied[targetID] || r.c.active[targetID].Authority != nil {
				t.Error("revoked target kept application access or process-local authority")
			}
			current, ok := r.c.active[originalID]
			t.Logf("reproduction: original_present=%v original_process_closed=%v original_application_denied=%v target_denied=%v exact_target_flushes=%d", ok, process.closed, r.applicationDenied[originalID], r.applicationDenied[targetID], *flushes)
			if !ok || current.Authority != original.Authority || !reflect.DeepEqual(current.Entry, original.Entry) || !reflect.DeepEqual(current.Grants, original.Grants) {
				t.Error("unrelated original authority, route binding or grants changed after target-only CP conflict")
			}
			if process.closed || r.c.bgpProcesses[original.Entry.DeliveryID] != process {
				t.Error("target-only CP conflict closed unrelated original desktop-export BGP process")
			}
			if original.Authority.deadline != originalDeadline {
				t.Error("unrelated original permit deadline extended")
			}
			for name, before := range originalNative {
				if r.installed[name] != before {
					t.Errorf("unrelated native absolute deadline changed: %s before=%s after=%s", name, before, r.installed[name])
				}
			}
			afterTemplates, afterSequence, _ := r.c.journal.guardTemplates()
			if !reflect.DeepEqual(afterTemplates, beforeTemplates) || afterSequence != beforeSequence {
				t.Error("target-only withdrawal rewrote the shared guard journal/template")
			}
			view := r.c.dnsView.Load()
			if view == nil || len(view.entries) != 1 || view.entries[originalID].epoch != originalEpoch || originalEpoch.revoked.Load() || !targetEpoch.revoked.Load() {
				t.Error("target conflict withdrew unrelated DNS owner epoch or retained target DNS")
			}
			if *flushes != 1 {
				t.Errorf("exact target withdrawal count=%d want=1", *flushes)
			}

		})
	}
}
