package ipsec

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGuardWithdrawalAllowsOnlyExpiredOwnedMembers(t *testing.T) {
	m, e := RenderGuard(guardFixture())
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if e = json.Unmarshal([]byte(m.ExpectedJSON), &doc); e != nil {
		t.Fatal(e)
	}
	for _, v := range doc["nftables"].([]any) {
		if s, ok := v.(map[string]any)["set"].(map[string]any); ok {
			delete(s, "elem")
		}
	}
	expired, _ := json.Marshal(doc)
	if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), expired, nil) != nil {
		t.Fatal("expired owned membership refused for withdrawal")
	}
	if VerifyGuardReadback([]byte(m.ExpectedJSON), expired) == nil {
		t.Fatal("withdrawal verifier relaxed permit receipt")
	}
	doc["nftables"] = append(doc["nftables"].([]any), map[string]any{"rule": map[string]any{"family": "inet", "table": "tunnex_ipsec", "chain": "output_guard", "expr": []any{map[string]any{"accept": nil}}}})
	widened, _ := json.Marshal(doc)
	if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), widened, nil) == nil {
		t.Fatal("foreign rule accepted")
	}
	if VerifyGuardWithdrawal(expired, []byte(m.ExpectedJSON), nil) == nil {
		t.Fatal("extra member accepted")
	}
}

func TestRuntimeGuardRefusesForeignTableBeforeMutation(t *testing.T) {
	j, e := OpenRuntimeJournal(journalDir(t), guardFixture().OwnerID)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	calls := 0
	r := &GuardReader{namespace: func() (string, error) { return guardFixture().Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return nil, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`), nil
	}}
	a := &RuntimeGuard{journal: j, reader: r, apply: func(context.Context, []byte) error { calls++; return nil }}
	if _, e = a.Replace(context.Background(), guardFixture()); e == nil || calls != 0 {
		t.Fatal("unowned table flushed")
	}
}
