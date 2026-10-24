package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func exactPageTestMaterials(t *testing.T, r *renewalCycleRig, client *fqdnCadenceSubsetClient, fresh bool) []RuntimeMaterial {
	t.Helper()
	out := []RuntimeMaterial{}
	if fresh {
		client.publishAt = *r.now
	}
	for _, m := range r.materials {
		if fresh && len(m.Policy.FQDNGrants) > 0 {
			m = client.materialAt(m.Manifest.ConnectionID, 1)
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var copy RuntimeMaterial
		if err = json.Unmarshal(raw, &copy); err != nil {
			t.Fatal(err)
		}
		out = append(out, copy)
	}
	return out
}

func TestExactPageRefreshReturnsOnlyRealCandidateReports(t *testing.T) {
	for _, ordinaryDue := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged-sibling-retained", true: "ordinary-due-in-same-commit"}[ordinaryDue], func(t *testing.T) {
			r, client := fqdnMultiOwnerCadenceRig(t)
			installFQDNCadenceStatusReaders(t, r, nil)
			materials := exactPageTestMaterials(t, r, client, true)
			old := assemblyClone(r.c.active)
			var ordinaryID uuid.UUID
			deadlines := map[*PermitLeaseAuthority]time.Duration{}
			for id, a := range old {
				deadlines[a.Authority] = a.Authority.deadline
				if len(a.FQDNLeaseDescriptors) == 0 {
					ordinaryID = id
					if ordinaryDue {
						delete(r.c.ordinaryNativeWindows, id)
					}
				}
			}
			reports := map[uuid.UUID]RuntimeStatusReport{}
			publish := func(ctx context.Context, d RuntimeDelivery, out RuntimeStatusReport) error {
				if ctx.Err() != nil || out.DeliveryID != d.ID || out.DesiredRevision != d.DesiredRevision || out.ConfigurationRevision != d.Manifest.ConfigurationRevision {
					t.Fatal("wrong candidate report binding")
				}
				if d.Manifest.BGP == nil && (out.RecoveryVersion == nil || *out.RecoveryVersion != 1 || out.SelectionSequence == nil || *out.SelectionSequence == 0) {
					t.Fatal("static report omitted real recovery envelope")
				}
				if out.Tunnels[0].Status != "up" || out.Tunnels[1].Status != "up" {
					t.Fatal("real native status producer not exercised", out.Tunnels)
				}
				reports[d.ID] = out
				return nil
			}
			results, handled, err := r.c.tryMaintainExactRuntimePage(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, publish)
			if err != nil || !handled || len(results) != len(materials) {
				t.Fatal("exact shared refresh failed", handled, err, len(results))
			}
			want := 2
			if ordinaryDue {
				want = 3
			}
			if len(reports) != want || client.requests < want {
				t.Fatal("missing real nonce/report", len(reports), client.requests)
			}
			for i, result := range results {
				m := materials[i]
				if m.Manifest.ConnectionID == ordinaryID && !ordinaryDue {
					if result.Retained == nil || !reflect.DeepEqual(*result.Retained, m.RuntimeDelivery) || result.Deferred != nil || result.Acknowledgement != (RuntimeAcknowledgement{}) || !reflect.DeepEqual(result.Report, RuntimeStatusReport{}) {
						t.Fatal("unchanged sibling falsely applied")
					}
					if !reflect.DeepEqual(r.c.active[ordinaryID], old[ordinaryID]) {
						t.Fatal("unchanged sibling authority changed")
					}
				} else {
					expected := RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}
					if result.Retained != nil || result.Deferred != nil || result.Acknowledgement != expected || !reflect.DeepEqual(result.Report, reports[m.ID]) {
						t.Fatal("updated owner lacks actual report/ACK or conflicts with retained")
					}
					if r.c.active[m.Manifest.ConnectionID].Authority == old[m.Manifest.ConnectionID].Authority {
						t.Fatal("candidate reused old authority")
					}
				}
			}
			for auth, end := range deadlines {
				if auth.deadline != end {
					t.Fatal("old absolute deadline extended")
				}
			}
		})
	}
}

func TestExactPageRefreshSemanticChangesStayOnNormalPath(t *testing.T) {
	for _, mode := range []string{"startup-gate", "partial", "duplicate", "foreign-delivery", "foreign-revision", "changed-IP", "changed-rule", "changed-key", "changed-provenance", "changed-ordinary", "changed-transport", "revoked", "active-journal-mismatch", "pending-desktop", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnMultiOwnerCadenceRig(t)
			materials := exactPageTestMaterials(t, r, client, true)
			target := 0
			for i, m := range materials {
				if len(m.Policy.FQDNGrants) > 0 {
					target = i
					break
				}
			}
			m := &materials[target]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "startup-gate":
				if err := os.WriteFile(filepath.Join(r.c.config.JournalDir, "restoration-startup-gate"), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				materials = materials[:len(materials)-1]
			case "duplicate":
				materials[len(materials)-1] = materials[0]
			case "foreign-delivery":
				m.ID = uuid.New()
			case "foreign-revision":
				m.DesiredRevision++
			case "changed-IP":
				m.Policy.FQDNGrants[0].Destination = "10.182.10.199/32"
			case "changed-rule":
				m.Policy.FQDNGrants[0].RuleID = uuid.NewString()
			case "changed-key":
				m.Policy.FQDNGrants[0].PublicKey = "changed-peer-key"
			case "changed-provenance":
				m.Policy.FQDNGrants[0].ResolverProfileID = uuid.NewString()
			case "changed-ordinary":
				m.Policy.Grants = append(m.Policy.Grants, RuntimeGrant{Source: m.Manifest.LocalPrefixes[0], Destination: m.Policy.FQDNGrants[0].Destination, Protocol: "tcp", PortLow: 81, PortHigh: 81, RuleID: uuid.NewString()})
			case "changed-transport":
				m.Manifest.RemotePrefixes = []string{"10.250.0.0/16"}
			case "revoked":
				m.Policy.FQDNGrants = nil
			case "active-journal-mismatch":
				a := r.c.active[m.Manifest.ConnectionID]
				a.Entry.Observed[0].InterfaceIndex++
				r.c.active[m.Manifest.ConnectionID] = a
			case "pending-desktop":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, errDesktopNATPending }
			case "canceled":
				cancel()
			}
			before := assemblyClone(r.c.active)
			journal, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
			if err != nil {
				t.Fatal(err)
			}
			replaced, published := 0, 0
			r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
				replaced++
				return GuardManifest{}, errors.New("must not replace")
			}
			results, handled, err := r.c.tryMaintainExactRuntimePage(ctx, materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil })
			after, readErr := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
			if err != nil || handled || len(results) != 0 || replaced != 0 || published != 0 || client.requests != 0 || !reflect.DeepEqual(before, r.c.active) || readErr != nil || !reflect.DeepEqual(journal, after) {
				t.Fatal("semantic change/partial page entered fast commit", handled, err, client.requests, replaced, published)
			}
		})
	}
}

func TestExactPageRefreshFailureAfterWorkCannotFallBackOrACK(t *testing.T) {
	for _, mode := range []string{"wrong-nonce", "publication-failed", "cancel-last-publication", "expiry-last-publication", "native-failure", "policy-retracted-after-first-publication", "stale-report-finite-authority"} {
		t.Run(mode, func(t *testing.T) {
			r, base := fqdnMultiOwnerCadenceRig(t)
			installFQDNCadenceStatusReaders(t, r, nil)
			materials := exactPageTestMaterials(t, r, base, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "wrong-nonce" {
				events := []string{}
				var target uuid.UUID
				for _, m := range materials {
					if len(m.Policy.FQDNGrants) > 0 {
						target = m.Manifest.ConnectionID
						break
					}
				}
				r.c.client = &assemblyRefreshClient{base: base, target: target, events: &events, lease: func(out *RuntimeLease) { out.Nonce = "wrong-nonce" }}
			}
			if mode == "native-failure" {
				r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					return errors.New("native proof failed")
				}
			}
			published := 0
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error {
				published++
				if mode == "policy-retracted-after-first-publication" && published == 1 {
					r.c.config.FQDNPolicy.CommittedPolicy(nil)
				}
				if mode == "publication-failed" {
					return errors.New("CP publication refused")
				}
				if published == 2 {
					if mode == "cancel-last-publication" {
						cancel()
					}
					if mode == "expiry-last-publication" {
						*r.now += time.Minute
					}
					if mode == "stale-report-finite-authority" {
						*r.now += 11 * time.Second
						for _, a := range r.c.active {
							if _, e := a.Authority.RemainingForApply(a.Identity, 5*time.Second); e != nil {
								t.Fatal("late report fixture lost ordinary authority", e)
							}
							for _, g := range a.Grants {
								if g.FQDN.Version == 2 {
									if _, e := a.Authority.RemainingFQDNForApply(a.Identity, guardFQDNGrantDigest(g), time.Millisecond); e != nil {
										t.Fatal("late report fixture lost finite FQDN authority", e)
									}
								}
							}
						}
					}
				}
				return nil
			}
			results, handled, err := r.c.tryMaintainExactRuntimePage(ctx, materials, maintenanceAuthority(r), func() bool { return true }, publish)
			if err == nil || !handled || len(results) != 0 || len(r.c.active) != 0 {
				t.Fatal("failed candidate work escaped ACK/fallback denial", handled, err, len(results), len(r.c.active))
			}
			if mode == "policy-retracted-after-first-publication" && published != 1 {
				t.Fatal("test did not retract between candidate reports", published)
			}
			if (mode == "cancel-last-publication" || mode == "expiry-last-publication" || mode == "stale-report-finite-authority") && published != 2 {
				t.Fatal("test did not reach final publication fence", published)
			}
		})
	}
}

func TestExactPageRefreshPostworkAbortClassifiesControlBoundary(t *testing.T) {
	r, base := fqdnMultiOwnerCadenceRig(t)
	materials := exactPageTestMaterials(t, r, base, true)
	var target uuid.UUID
	for _, m := range materials {
		if len(m.Policy.FQDNGrants) > 0 {
			target = m.Manifest.ConnectionID
			break
		}
	}
	events := []string{}
	r.c.client = &assemblyRefreshClient{base: base, target: target, events: &events, lease: func(out *RuntimeLease) { out.Nonce = "wrong-nonce" }}
	results, err := r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, nil, nil)
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || len(results) != 0 || base.requests == 0 {
		t.Fatal("postwork error permits control poll to replay stale Apply", err, base.requests)
	}
}

// Zero candidates may avoid a renewal transaction, but not any owner's fresh
// native eligibility or the complete final finite-authority/guard fence.
func TestExactPageRefreshZeroCandidatesRetainsOnlyAfterCompleteProof(t *testing.T) {
	for _, mode := range []string{"control", "native-unknown", "bgp-rib-changed", "final-fqdn-expiry", "final-ordinary-expiry", "final-cancel", "final-guard-drift", "final-owner-mutation"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnMultiOwnerCadenceRig(t)
			installFQDNCadenceStatusReaders(t, r, nil)
			materials := exactPageTestMaterials(t, r, client, false)
			before := assemblyClone(r.c.active)
			clocks := maps.Clone(r.c.recoveryReportClocks)
			journal, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var target uuid.UUID
			for id, a := range r.c.active {
				if a.Entry.ContractVersion == 2 {
					target = id
					break
				}
			}
			readers := *r.c.statusReaders
			if mode == "native-unknown" {
				r.c.statusReaders.xfrm = func(ctx context.Context) (XFRMInventory, error) {
					x, err := readers.xfrm(ctx)
					x = assemblySnapshotJSONClone(x)
					reqid := r.c.active[target].Entry.Engines[0].ReqID
					for i := range x.States {
						if x.States[i].ReqID == reqid {
							x.States[i].SPI++
							break
						}
					}
					return x, err
				}
			}
			proven := map[uuid.UUID]bool{}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				proven[e.Allocation.ConnectionID] = true
				if err := prove(ctx, e, env); err != nil {
					return err
				}
				if runtimeObservedStatuses(ctx, e, *r.c.statusReaders) != [2]string{"up", "up"} {
					return ErrRuntimeController
				}
				return nil
			}
			if mode == "bgp-rib-changed" {
				for _, a := range r.c.active {
					if a.Entry.ContractVersion == 3 {
						p := r.c.bgpProcesses[a.Entry.DeliveryID].(*bgpSessionFixture)
						p.routes = nil
						if !p.Alive() {
							t.Fatal("fixture must preserve live BGP process")
						}
					}
				}
			}
			finalReads := 0
			run := r.c.guard.reader.run
			r.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				raw, err := run(ctx, args...)
				if fqdnCadenceInCall(".retainedMaintenanceCurrent") {
					finalReads++
					switch mode {
					case "final-fqdn-expiry":
						*r.now += 24 * time.Second
					case "final-ordinary-expiry":
						*r.now += time.Minute
					case "final-cancel":
						cancel()
					case "final-guard-drift":
						return []byte(`{"nftables":[]}`), nil
					case "final-owner-mutation":
						a := r.c.active[target]
						a.Identity.PolicyHash = "changed"
						r.c.active[target] = a
					}
				}
				return raw, err
			}
			writes, published := 0, 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { writes++; return replace(ctx, in) }
			results, handled, err := r.c.tryMaintainExactRuntimePage(ctx, materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil })
			if client.requests != 0 || published != 0 {
				t.Fatal("zero-candidate page minted authority/report", client.requests, published)
			}
			if mode == "control" {
				if err != nil || !handled || len(results) != len(materials) || len(proven) != len(before) || finalReads != 1 || writes != 0 {
					t.Fatal("complete unchanged page was not independently validated", handled, err, len(results), len(proven), finalReads, writes)
				}
				for i, out := range results {
					if out.Retained == nil || !reflect.DeepEqual(*out.Retained, materials[i].RuntimeDelivery) || out.Deferred != nil || out.Acknowledgement != (RuntimeAcknowledgement{}) || !reflect.DeepEqual(out.Report, RuntimeStatusReport{}) {
						t.Fatal("retained page fabricated mutation/ACK/report")
					}
				}
				after, readErr := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
				if readErr != nil || !reflect.DeepEqual(journal, after) || !reflect.DeepEqual(before, r.c.active) || !reflect.DeepEqual(clocks, r.c.recoveryReportClocks) {
					t.Fatal("validation changed durable authority/native report time")
				}
			} else {
				var aborted interface{ IPsecMaintenanceBatchAborted() bool }
				if !handled || !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || len(results) != 0 || len(r.c.active) != 0 {
					t.Fatal("failed fresh proof falsely validated or allows Apply replay", handled, err, len(results))
				}
				if mode != "native-unknown" && mode != "bgp-rib-changed" && (finalReads != 1 || len(proven) != len(before)) {
					t.Fatal("test missed complete final I/O fence", finalReads, len(proven))
				}
			}
		})
	}
}
