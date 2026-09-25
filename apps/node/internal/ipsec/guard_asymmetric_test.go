package ipsec

import (
	"strings"
	"testing"
	"time"
)

func TestGuardAsymmetricReplyAuthority(t *testing.T) {
	i := guardFixture()
	i.Connections[0].ReplyIngressIndices = []int{10, 11}
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.NFT, "meta iif 11 meta oif 2 ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 tcp sport 443 ct direction reply ct state established meta iif @reply_lease_") {
		t.Fatal("missing qualified asymmetric reply")
	}
	for _, line := range strings.Split(m.NFT, "\n") {
		if strings.Contains(line, "counter accept") && (strings.Contains(line, "meta oif 11") || (strings.Contains(line, "meta iif 11") && strings.Contains(line, "ct direction original"))) {
			t.Fatalf("backup authority widened: %s", line)
		}
	}
	if err := VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)); err != nil {
		t.Fatal(err)
	}
	i.Connections[0].PermitFor = time.Millisecond
	m, err = RenderGuard(i)
	if err != nil || strings.Contains(m.NFT, "counter accept") {
		t.Fatal("expired authority permits traffic", err)
	}
}
func TestGuardAsymmetricForeignReplyRefused(t *testing.T) {
	i := guardFixture()
	i.Connections[0].ReplyIngressIndices = []int{99}
	if _, err := RenderGuard(i); err == nil {
		t.Fatal("foreign ingress accepted")
	}
}
