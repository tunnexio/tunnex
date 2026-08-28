package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestAcknowledgeKubernetesOwnershipBaseAuthorityPostsExactReceipt(t *testing.T) {
	want := reconcile.KubernetesOwnershipBaseAuthorityAck{
		WireVersion: 1, AuthorityRevision: 12, NodeID: "99999999-9999-9999-9999-999999999999",
		OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		BaseVersion: 17, BaseHash: strings.Repeat("a", 64), AuthorityDigest: strings.Repeat("b", 64), AppliedAt: "2026-08-28T10:11:12.000000345Z",
	}
	called := false
	client := &Client{base: "https://control.example", http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Method != http.MethodPost || request.URL.Path != "/agent/kubernetes-ownership-base-authority/ack" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		var got reconcile.KubernetesOwnershipBaseAuthorityAck
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("receipt=%+v want=%+v", got, want)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	if err := client.AcknowledgeKubernetesOwnershipBaseAuthority(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("ACK was not posted")
	}
}

func TestAcknowledgeKubernetesOwnershipBaseAuthorityRequiresNoContent(t *testing.T) {
	client := &Client{base: "https://control.example", http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})}}
	err := client.AcknowledgeKubernetesOwnershipBaseAuthority(context.Background(), reconcile.KubernetesOwnershipBaseAuthorityAck{})
	if err == nil || !strings.Contains(err.Error(), "status 200") {
		t.Fatalf("err=%v", err)
	}
}
