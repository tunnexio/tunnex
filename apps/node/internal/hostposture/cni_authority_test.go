package hostposture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

func cniTestHeartbeat(now time.Time, sequence uint64) Heartbeat {
	return Heartbeat{SchemaVersion: 1, Contract: Contract, NodeName: "worker-a",
		ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ManagerBootID: "11111111111111111111111111111111",
		Sequence: sequence, State: HeartbeatActive, Owners: []Owner{testOwner()}, ObservedAt: now}
}

func cniTestJournal(t *testing.T, schema int, now time.Time) Journal {
	t.Helper()
	originals := desiredSysctls()
	for i := range originals {
		originals[i].Original = "0"
	}
	j, err := newJournal("worker-a", 7, originals, []Owner{testOwner()}, "tnx0123456789ab", now)
	if err != nil {
		t.Fatal(err)
	}
	j.SchemaVersion = schema
	j.Artifacts = fixedArtifactsForSchema(schema)
	j.Artifacts.WireGuard.IfIndex = 77
	if schema != LegacyJournalSchemaVersion {
		j.Artifacts.WireGuard.StagingName = "tnx0123456789ab"
		j.Artifacts.WireGuard.StagingIfIndex = 77
		j.Artifacts.WireGuard.Phase = WireGuardPhaseCommitted
	}
	j.State = StateActive
	return j
}

func saveCNITestPair(t *testing.T, store *Store, j Journal, h Heartbeat) CNIAuthority {
	t.Helper()
	authority, err := authorityForHeartbeat(h, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHeartbeat(h); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCNIAuthority(authority); err != nil {
		t.Fatal(err)
	}
	return authority
}

// These are the literal pre-v3 artifact field order and receipts, not a map
// regenerated using fixedArtifacts. Both historical schema encodings remain
// readable and re-encode byte-for-byte; an old strict decoder rejects v3.
func TestCNIJournalLegacyBytesAndClosedSchemaThree(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			wgExtra := ""
			if schema == 2 {
				wgExtra = `,"staging_name":"tnx0123456789ab","staging_ifindex":77,"phase":"committed"`
			}
			body := fmt.Sprintf(`{"schema_version":%d,"contract":"tunnex-host-posture/v1","node_name":"worker-a","epoch":7,"state":"active","sysctls":[{"key":"net/ipv4/ip_forward","original":"0","desired":"1"},{"key":"net/ipv4/conf/all/rp_filter","original":"0","desired":"0"},{"key":"net/ipv4/conf/default/rp_filter","original":"0","desired":"0"}],"owners":[{"uid":"11111111-2222-3333-4444-555555555555","namespace":"tunnex-system","name":"gw-a"}],"artifacts":{"wireguard":{"name":"wg0","alias":"tunnex-host-posture/v1","ifindex":77%s},"nftables":[{"family":"ip","name":"tunnex","marker_comment":"tunnex_host_posture_v1"},{"family":"ip6","name":"tunnex","marker_comment":"tunnex_host_posture_v1"}],"routes":{"interface":"wg0","protocol":"static","metric":8021,"rule_priority":100,"rule_lookup":"main"},"cni":{"family":"ip","table":"nat","chain":"IP-MASQ-AGENT","comments":["tunnex_k8s_ip_masq_bypass","tunnex_ha_cni_masq_bypass"]},"docker":{"family":"ip","table":"filter","chain":"DOCKER-USER","comment":"tunnex-site-fwd"}},"updated_at":"2026-09-05T00:00:00Z"}`, schema, wgExtra)
			var j Journal
			if err := json.Unmarshal([]byte(body), &j); err != nil {
				t.Fatal(err)
			}
			if err := j.validate("worker-a"); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(j)
			if err != nil || string(encoded) != body {
				t.Fatalf("legacy bytes changed: err=%v\ngot %s\nwant %s", err, encoded, body)
			}
			for _, extra := range []string{`null`, `{"family":"ip","table":"nat","chain":"AWS-SNAT-CHAIN-0","comments":["tunnex_k8s_aws_snat_bypass"]}`} {
				widened := strings.Replace(body, `"artifacts":{`, `"artifacts":{"aws_cni":`+extra+`,`, 1)
				if err := json.Unmarshal([]byte(widened), &j); err == nil {
					t.Fatal("legacy decoder accepted new receipt, including null")
				}
			}
		})
	}
	j := cniTestJournal(t, 3, time.Unix(1000, 0))
	for name, mutate := range map[string]func(*Journal){
		"missing AWS":     func(j *Journal) { j.Artifacts.AWSCNI = nil },
		"foreign chain":   func(j *Journal) { j.Artifacts.AWSCNI.Chain = "POSTROUTING" },
		"widened markers": func(j *Journal) { j.Artifacts.AWSCNI.Comments = append(j.Artifacts.AWSCNI.Comments, "foreign") },
		"unknown schema":  func(j *Journal) { j.SchemaVersion = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cniTestJournal(t, 3, time.Unix(1000, 0))
			mutate(&candidate)
			if err := candidate.validate("worker-a"); err == nil {
				t.Fatal("non-closed v3 receipt accepted")
			}
		})
	}
	encoded, _ := json.Marshal(j)
	// Old schema readers have no AWS field. Their strict decode must refuse the
	// new artifact before they can overwrite or clean anything.
	var old struct {
		WireGuard WireGuardReceipt  `json:"wireguard"`
		NFTables  []NFTTableReceipt `json:"nftables"`
		Routes    RouteReceipt      `json:"routes"`
		CNI       CNIReceipt        `json:"cni"`
		Docker    DockerReceipt     `json:"docker"`
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(top["artifacts"]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&old); err == nil {
		t.Fatal("strict old artifact reader accepted new schema")
	}
	legacy, _ := json.Marshal(fixedArtifacts())
	dec = json.NewDecoder(bytes.NewReader(legacy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&old); err != nil {
		t.Fatalf("historical reader does not accept original receipt: %v", err)
	}
}

func TestCNIHeartbeatJSONRemainsStrictOldContract(t *testing.T) {
	h := cniTestHeartbeat(time.Unix(1000, 0).UTC(), 4)
	got, err := json.Marshal(h)
	const want = `{"schema_version":1,"contract":"tunnex-host-posture/v1","node_name":"worker-a","manager_uid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","manager_boot_id":"11111111111111111111111111111111","sequence":4,"state":"active","owners":[{"uid":"11111111-2222-3333-4444-555555555555","namespace":"tunnex-system","name":"gw-a"}],"observed_at":"1970-01-01T00:16:40Z"}`
	if err != nil || string(got) != want {
		t.Fatalf("old heartbeat changed: %s err=%v", got, err)
	}
}

func TestCNIAuthorityRejectsForeignStalePartialAndWidenedRecords(t *testing.T) {
	now := time.Unix(1000, 0)
	h := cniTestHeartbeat(now, 4)
	base, err := authorityForHeartbeat(h, cniTestJournal(t, 3, now))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCNIAuthority(base, h, "worker-a", testOwner().UID, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*CNIAuthority, *Heartbeat){
		"foreign node":             func(a *CNIAuthority, _ *Heartbeat) { a.NodeName = "worker-b" },
		"foreign manager":          func(a *CNIAuthority, _ *Heartbeat) { a.ManagerUID = "foreign-manager" },
		"old boot":                 func(a *CNIAuthority, _ *Heartbeat) { a.ManagerBootID = strings.Repeat("2", 32) },
		"partial publication":      func(a *CNIAuthority, _ *Heartbeat) { a.Sequence-- },
		"zero epoch":               func(a *CNIAuthority, _ *Heartbeat) { a.Epoch = 0 },
		"unknown authority schema": func(a *CNIAuthority, _ *Heartbeat) { a.SchemaVersion++ },
		"unknown journal schema":   func(a *CNIAuthority, _ *Heartbeat) { a.JournalSchema = 4 },
		"legacy widened to AWS":    func(a *CNIAuthority, _ *Heartbeat) { a.JournalSchema = 2 },
		"unknown scope":            func(a *CNIAuthority, _ *Heartbeat) { a.Scope = "all" },
		"revoked":                  func(a *CNIAuthority, _ *Heartbeat) { a.State = CNIAuthorityRevoked },
		"timestamp mismatch":       func(a *CNIAuthority, _ *Heartbeat) { a.ObservedAt = now.Add(time.Second) },
		"stale": func(a *CNIAuthority, h *Heartbeat) {
			a.ObservedAt = now.Add(-HeartbeatFreshness - time.Second)
			h.ObservedAt = a.ObservedAt
		},
		"future": func(a *CNIAuthority, h *Heartbeat) {
			a.ObservedAt = now.Add(3 * time.Second)
			h.ObservedAt = a.ObservedAt
		},
		"owner absent":      func(_ *CNIAuthority, h *Heartbeat) { h.Owners = nil },
		"blocked heartbeat": func(_ *CNIAuthority, h *Heartbeat) { h.State = HeartbeatBlocked },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, heartbeat := base, h
			mutate(&a, &heartbeat)
			if err := validateCNIAuthority(a, heartbeat, "worker-a", testOwner().UID, now); err == nil {
				t.Fatal("invalid capability granted")
			}
		})
	}
}

func TestCNIAuthorityTwoProofsLegacyScopeAndReadOnlyStore(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			reader, err := OpenStore(store.dir)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1000, 0)
			j := cniTestJournal(t, schema, now)
			h := cniTestHeartbeat(now, 1)
			if err := store.SaveHeartbeat(h); err != nil {
				t.Fatal(err)
			}
			if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
				t.Fatal("old manager/missing public record admitted gateway")
			}
			saveCNITestPair(t, store, j, h)
			for i := 0; i < 2; i++ {
				if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
					t.Fatal("one or duplicate heartbeat admitted gateway")
				}
			}
			h.Sequence++
			saveCNITestPair(t, store, j, h)
			grant, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			release()
			release()
			want, _ := journalCNIScope(schema)
			if grant.Scope != want || !grant.NotAfter.Equal(h.ObservedAt.Add(HeartbeatFreshness)) {
				t.Fatalf("schema %d grant %+v, want scope %q and original heartbeat expiry", schema, grant, want)
			}
			if err := reader.RevokeCNIAuthority(); err == nil {
				t.Fatal("read-only gateway published authority")
			}
			if _, err := os.Stat(reader.JournalPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("gateway guard created a journal")
			}
			// Epoch changes require two new proofs even when heartbeat sequence
			// and manager boot continue monotonically.
			j.Epoch++
			h.Sequence++
			saveCNITestPair(t, store, j, h)
			if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
				t.Fatal("new epoch inherited old admission")
			}
			h.Sequence++
			saveCNITestPair(t, store, j, h)
			_, release, err = reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now)
			if err != nil {
				t.Fatal(err)
			}
			release()
			if err := store.RevokeCNIAuthority(); err != nil {
				t.Fatal(err)
			}
			if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
				t.Fatal("revoked grant remained cached")
			}
		})
	}
}

func TestWaitForCNIOwnerNeedsTwoCorrelatedAdvancingProofs(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenStore(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	j := cniTestJournal(t, 3, now)
	h := cniTestHeartbeat(now, 1)
	saveCNITestPair(t, store, j, h)
	sleeps := 0
	err = WaitForCNIOwner(t.Context(), reader, "worker-a", testOwner().UID, func() time.Time { return now }, func(context.Context, time.Duration) error {
		sleeps++
		if sleeps == 1 {
			return nil
		} // duplicate proof does not advance
		h.Sequence++
		saveCNITestPair(t, store, j, h)
		if sleeps > 3 {
			return fmt.Errorf("failed to admit advancing proof")
		}
		return nil
	})
	if err != nil || sleeps != 2 {
		t.Fatalf("wait=%v sleeps=%d", err, sleeps)
	}
}

func TestCNIAuthorityUnknownJSONFieldsAndOversizeRefuse(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"schema_version":1,"unknown":true}`, strings.Repeat(" ", maxHeartbeat+1)} {
		if err := os.WriteFile(store.CNIAuthorityPath(), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadCNIAuthority(); err == nil {
			t.Fatal("unbounded or unknown authority parsed")
		}
	}
}

func TestManagerCNIDurableGrantRevocationAndPublicationFailure(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.journal.SchemaVersion != 3 || store.journal.Artifacts.AWSCNI == nil || store.authority.Scope != k8snetprep.ScopeIPMasqAndAWS {
		t.Fatalf("new epoch did not acquire closed durable v3 authority: %+v", store.authority)
	}
	if err := validateCNIAuthority(store.authority, store.heartbeat, "worker-a", testOwner().UID, manager.now()); err != nil {
		t.Fatal(err)
	}
	store.revokeErr = errors.New("revocation disk fault")
	beforePrepare, beforeEnforce := kernel.prepare, kernel.enforce
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("revocation failure ignored")
	}
	if kernel.prepare != beforePrepare || kernel.enforce != beforeEnforce || store.lockHeld {
		t.Fatal("mutation or held lock after revocation failure")
	}
	store.revokeErr = nil
	store.authorityErr = errors.New("publication fault")
	// Retain the existing fake's explicit pre-mutation check while exercising
	// a complete new epoch's final-publication crash window.
	store.journal.State = StateRestored
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("publication failure ignored")
	}
	if store.authority.State != CNIAuthorityRevoked || store.journal.State != StateActive || store.lockHeld {
		t.Fatal("partial publication retained write authority")
	}
	store.authorityErr = nil
	source.owners = nil
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.authority.State != CNIAuthorityRevoked || store.journal.State != StateRestored {
		t.Fatal("cleanup did not remain revoked")
	}
}

func TestManagerLegacyEpochNeverWidensOrMigratesInPlace(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			j := cniTestJournal(t, schema, time.Unix(1234, 0))
			before, _ := json.Marshal(j)
			source := &fakeOwnerSource{owners: []Owner{testOwner()}}
			store := &fakePostureStore{journal: j, haveJournal: true}
			kernel := &fakeKernel{}
			manager := newTestManager(t, source, store, kernel)
			if err := manager.ReconcileOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(store.journal)
			if !bytes.Equal(before, after) || len(store.saveStates) != 0 || store.authority.JournalSchema != schema || store.authority.Scope != k8snetprep.ScopeIPMasqOnly {
				t.Fatalf("legacy active epoch migrated: authority=%+v before=%s after=%s", store.authority, before, after)
			}
			source.owners = nil
			if err := manager.ReconcileOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			if store.journal.SchemaVersion != schema || store.journal.Artifacts.AWSCNI != nil {
				t.Fatal("legacy cleanup widened receipt")
			}
			source.owners = []Owner{testOwner()}
			if err := manager.ReconcileOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			if store.journal.SchemaVersion != 3 || store.journal.Epoch != j.Epoch+1 || kernel.capture != 1 {
				t.Fatal("clean new epoch did not receive new baseline and schema")
			}
		})
	}
}

func TestManagerUnknownJournalAndAPIFaultCannotGrantCNIAuthority(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{journal: cniTestJournal(t, 3, time.Unix(1234, 0)), haveJournal: true}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	store.journal.SchemaVersion = 4
	before, _ := json.Marshal(store.journal)
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("unknown schema accepted")
	}
	after, _ := json.Marshal(store.journal)
	if !bytes.Equal(before, after) || kernel.prepare+kernel.enforce+kernel.restore+kernel.capture != 0 || store.authority.State != CNIAuthorityRevoked {
		t.Fatal("unknown journal caused mutation or grant")
	}
	store.journal.SchemaVersion = 3
	source.err = errors.New("unknown API owners")
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("API failure ignored")
	}
	if kernel.enforce != 1 || kernel.restore != 0 || store.heartbeat.State != HeartbeatBlocked || store.authority.State != CNIAuthorityRevoked {
		t.Fatal("API ambiguity changed conservative ownership policy")
	}
}
