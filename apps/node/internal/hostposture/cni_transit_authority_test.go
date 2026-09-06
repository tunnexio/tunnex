package hostposture

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

func TestCNITransitReceiptVersionBoundary(t *testing.T) {
	const oldReceipt = `{"family":"ip","table":"nat","chain":"AWS-SNAT-CHAIN-0","comments":["tunnex_k8s_aws_snat_bypass"]}`
	now := time.Unix(1000, 0)
	old := cniTestJournal(t, AWSJournalSchemaVersion, now)
	encoded, err := json.Marshal(old.Artifacts.AWSCNI)
	if err != nil || string(encoded) != oldReceipt {
		t.Fatalf("schema-3 AWS bytes changed: %s, %v", encoded, err)
	}
	before, _ := json.Marshal(old)
	var roundtrip Journal
	if err := json.Unmarshal(before, &roundtrip); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(roundtrip)
	if !bytes.Equal(before, after) || roundtrip.validate("worker-a") != nil {
		t.Fatal("schema-3 journal did not roundtrip unchanged")
	}
	current := cniTestJournal(t, JournalSchemaVersion, now)
	if err := current.validate("worker-a"); err != nil {
		t.Fatal(err)
	}
	grant, err := authorityForHeartbeat(cniTestHeartbeat(now, 1), current)
	if err != nil || grant.Scope != k8snetprep.ScopeIPMasqAndAWSTransit || grant.JournalSchema != 4 {
		t.Fatalf("new receipt did not authorize exact transit capability: %+v %v", grant, err)
	}
	for name, mutate := range map[string]func(*Journal){
		"missing transit":        func(j *Journal) { j.Artifacts.AWSCNI.Comments = j.Artifacts.AWSCNI.Comments[:1] },
		"foreign marker":         func(j *Journal) { j.Artifacts.AWSCNI.Comments[1] = "foreign" },
		"duplicate marker":       func(j *Journal) { j.Artifacts.AWSCNI.Comments[1] = k8snetprep.AWSOwnedRuleComment },
		"old schema new receipt": func(j *Journal) { j.SchemaVersion = AWSJournalSchemaVersion },
	} {
		t.Run(name, func(t *testing.T) {
			j := cniTestJournal(t, JournalSchemaVersion, now)
			mutate(&j)
			if _, err := authorityForHeartbeat(cniTestHeartbeat(now, 1), j); err == nil {
				t.Fatal("invalid transit receipt granted authority")
			}
		})
	}
}

func TestCNITransitScopeChangeNeedsFreshProofs(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	j := cniTestJournal(t, AWSJournalSchemaVersion, now)
	h := cniTestHeartbeat(now, 1)
	saveCNITestPair(t, store, j, h)
	if _, release, err := store.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
		t.Fatal("first old proof admitted")
	}
	h.Sequence++
	saveCNITestPair(t, store, j, h)
	grant, release, err := store.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if grant.Scope != k8snetprep.ScopeIPMasqAndAWS {
		t.Fatal("old journal gained transit authority")
	}
	j = cniTestJournal(t, JournalSchemaVersion, now)
	j.Epoch++
	h.Sequence++
	saveCNITestPair(t, store, j, h)
	if _, release, err := store.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
		t.Fatal("transit capability inherited old proof")
	}
	h.Sequence++
	saveCNITestPair(t, store, j, h)
	grant, release, err = store.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if grant.Scope != k8snetprep.ScopeIPMasqAndAWSTransit {
		t.Fatal("fresh schema-4 proofs failed to acquire transit capability")
	}
}
