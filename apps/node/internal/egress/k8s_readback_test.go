package egress

import (
	"reflect"
	"strings"
	"testing"
)

func TestK8sDNATReceiptBindsCompleteRuleAndParsesKernelListing(t *testing.T) {
	first := "ip daddr 100.64.0.5 tcp dport 443 dnat to 10.42.0.8:8443"
	second := "ip daddr 100.64.0.5 tcp dport 443 dnat to 10.42.0.9:8443"
	firstRendered := attachDNATReceipt("100.64.0.5", first)
	secondRendered := attachDNATReceipt("100.64.0.5", second)
	if firstRendered == secondRendered || !strings.Contains(firstRendered, `comment "tunnex_k8s_vip:`) {
		t.Fatalf("receipt does not bind target change: first=%q second=%q", firstRendered, secondRendered)
	}
	want := []string{dnatReceipt("100.64.0.5", first).Digest, dnatReceipt("100.64.0.5", second).Digest}
	if want[1] < want[0] {
		want[0], want[1] = want[1], want[0]
	}
	listing := "chain prerouting {\n  " + secondRendered + " # handle 4\n  " + firstRendered + " # handle 3\n}"
	got, err := parseK8sDNATReceipts(listing)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed receipts=%v want=%v err=%v", got, want, err)
	}
}

func TestK8sDNATReceiptParserRejectsDuplicateKernelReceipt(t *testing.T) {
	rendered := attachDNATReceipt("100.64.0.5", "ip daddr 100.64.0.5 tcp dport 443 dnat to 10.42.0.8:8443")
	if _, err := parseK8sDNATReceipts(rendered + "\n" + rendered); err == nil {
		t.Fatal("duplicate kernel receipt must fail readback")
	}
}

func TestK8sDNATReceiptParserRejectsAlteredRuleWithTrustedComment(t *testing.T) {
	rule := "ip daddr 100.64.0.5 tcp dport 443 dnat to 10.42.0.8:8443"
	rendered := attachDNATReceipt("100.64.0.5", rule)
	altered := strings.Replace(rendered, "10.42.0.8", "10.42.0.9", 1)
	if _, err := parseK8sDNATReceipts(altered); err == nil {
		t.Fatal("same trusted comment on altered live rule must fail readback")
	}
}

func TestK8sDNATReceiptParserRejectsMatchingDigestForUnknownSemantics(t *testing.T) {
	rule := "ip daddr 100.64.0.5 tcp dport 443 accept"
	rendered := attachDNATReceipt("100.64.0.5", rule)
	if _, err := parseK8sDNATReceipts(rendered); err == nil {
		t.Fatal("a matching digest must not authenticate an unknown rule shape")
	}
}

func TestK8sDNATReceiptParserAcceptsCanonicalBalancedRule(t *testing.T) {
	rule := "ip daddr 100.64.0.5 udp dport 53 dnat to jhash ip saddr . ip daddr mod 2 map { 0 : 10.42.0.8 . 5353, 1 : 10.42.0.9 . 5353 }"
	want := []string{dnatReceipt("100.64.0.5", rule).Digest}
	got, err := parseK8sDNATReceipts(attachDNATReceipt("100.64.0.5", rule))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("balanced receipt=%v want=%v err=%v", got, want, err)
	}
}

func TestParseInterfaceIPv4sAndIntersectExplicitOwnershipCandidates(t *testing.T) {
	listing := "7: wg0    inet 10.99.0.1/24 scope global wg0\\       valid_lft forever preferred_lft forever\n" +
		"7: wg0    inet 100.64.0.2/32 scope global secondary wg0\\       valid_lft forever preferred_lft forever\n" +
		"7: wg0    inet 100.64.0.3/32 scope global secondary wg0\\       valid_lft forever preferred_lft forever\n"
	observed, err := parseInterfaceIPv4s(listing)
	if err != nil {
		t.Fatal(err)
	}
	got, err := observedCandidates(observed, []string{"100.64.0.3", "100.64.0.9", "100.64.0.2"})
	if err != nil || !reflect.DeepEqual(got, []string{"100.64.0.2", "100.64.0.3"}) {
		t.Fatalf("observed candidates=%v err=%v", got, err)
	}
}

func TestParseInterfaceIPv4sFailsOnAmbiguousLine(t *testing.T) {
	if _, err := parseInterfaceIPv4s("7: wg0 garbage"); err == nil {
		t.Fatal("malformed kernel output must not become an empty readback")
	}
}

func TestParseOwnedDNSVIPsEnumeratesMarkerAndLegacySecondaryWithoutTouchingPrimary(t *testing.T) {
	listing := "7: wg0 inet 10.99.0.1/32 scope global wg0 valid_lft forever preferred_lft forever\n" +
		"7: wg0 inet 100.64.0.2/32 scope global secondary wg0:tnxk8s valid_lft forever preferred_lft forever\n" +
		"7: wg0 inet 100.64.0.3/32 scope global secondary wg0 valid_lft forever preferred_lft forever\n" +
		"7: wg0 inet 100.64.0.4/32 scope global wg0 valid_lft forever preferred_lft forever\n"
	got, err := parseOwnedDNSVIPs(listing, "wg0", []string{"100.64.0.4"})
	want := []string{"100.64.0.2", "100.64.0.3", "100.64.0.4"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("owned DNS VIPs=%v want=%v err=%v", got, want, err)
	}
}
