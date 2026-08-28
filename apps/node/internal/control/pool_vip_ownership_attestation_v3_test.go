package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

type fakeOwnershipApplyReadbackV3 struct {
	readback PoolVIPOwnershipManifestV3
	applies  int
	reads    int
}

func (f *fakeOwnershipApplyReadbackV3) ApplyPoolVIPOwnershipV3(context.Context, PoolVIPOwnershipDeliveryEnvelopeV3) error {
	f.applies++
	return nil
}

func (f *fakeOwnershipApplyReadbackV3) ReadPoolVIPOwnershipV3(context.Context, PoolVIPOwnershipDeliveryEnvelopeV3) (PoolVIPOwnershipManifestV3, error) {
	f.reads++
	return f.readback, nil
}

func TestPoolVIPOwnershipV3PersistsExactLeaseExpiryAndFullAppliedManifest(t *testing.T) {
	envelope := ownershipDeliveryV3(t)
	adapter := &fakeOwnershipApplyReadbackV3{readback: envelope.Manifest}
	state := &memoryOwnershipState{}
	attestor := NewPoolVIPOwnershipAttestorV3(adapter, state)
	attestor.now = func() time.Time { return envelope.ExpiresAt.Add(-time.Minute) }
	ack, err := attestor.PreparePoolVIPOwnershipDeliveryAckV3(t.Context(), envelope)
	if err != nil || adapter.applies != 1 || adapter.reads != 1 || state.stores != 1 {
		t.Fatalf("v3 apply/readback/persist ack=%+v err=%v apply=%d read=%d stores=%d", ack, err, adapter.applies, adapter.reads, state.stores)
	}
	if state.state.WireVersion != 3 || state.state.LeaseExpiresAt == nil || !state.state.LeaseExpiresAt.Equal(envelope.ExpiresAt) || state.state.AppliedManifest == nil ||
		len(state.state.AppliedManifest.WGPeers) == 0 || len(state.state.AppliedManifest.Routes) == 0 || len(state.state.AppliedManifest.Services) == 0 || state.state.AppliedManifest.DNSVIP == "" {
		t.Fatalf("durable v3 applied state lost expiry or dataplane manifest: %+v", state.state)
	}
	if err := ValidatePoolVIPOwnershipDeliveryAckV3(envelope, ack); err != nil {
		t.Fatalf("valid v3 ack: %v", err)
	}
}

func TestPoolVIPOwnershipV3FileStateRetainsExpiryAcrossRestart(t *testing.T) {
	envelope := ownershipDeliveryV3(t)
	path := t.TempDir() + "/ownership.json"
	adapter := &fakeOwnershipApplyReadbackV3{readback: envelope.Manifest}
	attestor := NewPoolVIPOwnershipAttestorV3(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path))
	attestor.now = func() time.Time { return envelope.ExpiresAt.Add(-time.Minute) }
	if _, err := attestor.PreparePoolVIPOwnershipDeliveryAckV3(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	file, err := NewFilePoolVIPOwnershipAppliedStateStore(path).read()
	if err != nil {
		t.Fatal(err)
	}
	stored := file.States[poolVIPOwnershipAttestationScopeV3(envelope)]
	if stored.WireVersion != 3 || stored.LeaseExpiresAt == nil || !stored.LeaseExpiresAt.Equal(envelope.ExpiresAt) || stored.AppliedManifest == nil || !stored.AppliedManifest.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatalf("restart state lost CP expiry binding: %+v", stored)
	}
	restarted := NewPoolVIPOwnershipAttestorV3(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path))
	restarted.now = attestor.now
	if _, err := restarted.PreparePoolVIPOwnershipDeliveryAckV3(t.Context(), envelope); err != nil || adapter.applies != 1 {
		t.Fatalf("restart retry must reuse exact persisted v3 proof: err=%v applies=%d", err, adapter.applies)
	}
}

func TestPoolVIPOwnershipV3FailsClosedOnExpiryAndPartialReadback(t *testing.T) {
	envelope := ownershipDeliveryV3(t)
	for name, mutate := range map[string]func(*PoolVIPOwnershipManifestV3){
		"WG peer": func(m *PoolVIPOwnershipManifestV3) {
			m.WGPeers[0].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"WG AllowedIPs": func(m *PoolVIPOwnershipManifestV3) { m.WGPeers[0].AllowedIPs[0] = "10.99.0.0/16" },
		"routes":        func(m *PoolVIPOwnershipManifestV3) { m.Routes[0] = "10.99.0.0/16" },
		"VIP DNAT":      func(m *PoolVIPOwnershipManifestV3) { m.Services[0].VIP = "100.64.0.99" },
		"service CIDR":  func(m *PoolVIPOwnershipManifestV3) { m.Services[0].ServiceCIDR = "10.97.0.0/16" },
		"DNS name":      func(m *PoolVIPOwnershipManifestV3) { m.Services[0].DNSName = "other.default.cluster.k8s.example" },
		"DNS":           func(m *PoolVIPOwnershipManifestV3) { m.DNSZone = "other.k8s.example" },
	} {
		t.Run(name, func(t *testing.T) {
			readback := cloneOwnershipManifestV3(envelope.Manifest)
			mutate(&readback)
			state := &memoryOwnershipState{}
			attestor := NewPoolVIPOwnershipAttestorV3(&fakeOwnershipApplyReadbackV3{readback: readback}, state)
			attestor.now = func() time.Time { return envelope.ExpiresAt.Add(-time.Minute) }
			if _, err := attestor.PreparePoolVIPOwnershipDeliveryAckV3(t.Context(), envelope); err == nil || state.stores != 0 {
				t.Fatalf("partial applied state must produce no durable ACK proof: err=%v stores=%d", err, state.stores)
			}
		})
	}
	state := &memoryOwnershipState{}
	attestor := NewPoolVIPOwnershipAttestorV3(&fakeOwnershipApplyReadbackV3{readback: envelope.Manifest}, state)
	attestor.now = func() time.Time { return envelope.ExpiresAt }
	if _, err := attestor.PreparePoolVIPOwnershipDeliveryAckV3(t.Context(), envelope); err == nil || state.stores != 0 {
		t.Fatalf("expired CP lease must not apply or persist: err=%v stores=%d", err, state.stores)
	}
}

func TestPoolVIPOwnershipV1V2CompatibilityDoesNotAuthorizeHandoff(t *testing.T) {
	if err := validPoolVIPOwnershipDeliveryEnvelope(ownershipDeliveryClientEnvelope()); err != nil {
		t.Fatalf("v1 compatibility regressed: %v", err)
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(ownershipDeliveryV2(t, "serving")); err != nil {
		t.Fatalf("v2 compatibility regressed: %v", err)
	}
	for _, capability := range []string{"1", "2", "03", "4"} {
		if PoolVIPOwnershipCapabilityAuthorizesHandoff(capability) {
			t.Fatalf("capability %q unexpectedly authorizes handoff", capability)
		}
	}
}

func TestClientPollPoolVIPOwnershipDeliveryV3UsesExactCapabilityAndFullManifest(t *testing.T) {
	ca := newTestCA(t)
	envelope := ownershipDeliveryV3(t)
	ackCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/pool-vip-ownership-delivery", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader); got != "3" {
			t.Errorf("v3 capability=%q", got)
		}
		_ = json.NewEncoder(w).Encode(envelope)
	})
	mux.HandleFunc("/agent/pool-vip-ownership-delivery/ack", func(w http.ResponseWriter, r *http.Request) {
		ackCalls++
		if got := r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader); got != "3" {
			t.Errorf("v3 ack capability=%q", got)
		}
		var ack PoolVIPOwnershipDeliveryAckV3
		if err := json.NewDecoder(r.Body).Decode(&ack); err != nil || ValidatePoolVIPOwnershipDeliveryAckV3(envelope, ack) != nil {
			t.Errorf("invalid v3 ack: %+v err=%v", ack, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	state := &memoryOwnershipState{}
	attestor := NewPoolVIPOwnershipAttestorV3(&fakeOwnershipApplyReadbackV3{readback: envelope.Manifest}, state)
	attestor.now = func() time.Time { return envelope.ExpiresAt.Add(-time.Minute) }
	client := ownershipDeliveryTestClient(t, ca, mux)
	if work, err := client.PollPoolVIPOwnershipDeliveryV3(t.Context(), attestor); err != nil || !work || ackCalls != 1 {
		t.Fatalf("v3 poll work=%v err=%v ack=%d", work, err, ackCalls)
	}
}

func ownershipDeliveryV3(t *testing.T) PoolVIPOwnershipDeliveryEnvelopeV3 {
	t.Helper()
	base := ownershipDeliveryClientEnvelope()
	base.Version = PoolVIPOwnershipDeliveryHandoffVersion
	expires := time.Date(2026, 8, 28, 12, 30, 0, 0, time.UTC)
	manifest := PoolVIPOwnershipManifestV3{Version: nodepolicy.PoolVIPOwnershipManifestVersion, OrgID: base.OrgID, SiteID: base.SiteID, ClusterID: base.ClusterID,
		PoolID: base.PoolID, ConnectorNodeID: base.ConnectorNodeID, Role: base.Role, PromotionGeneration: base.PromotionGeneration,
		ManifestRevision: base.ManifestRevision, LeaseEpoch: base.LeaseEpoch, LeaseExpiresAt: expires, DNSZone: "cluster.k8s.example", DNSVIP: "100.64.0.2",
		HandoffOwnerID: base.OperationID, RouteIntent: "serving", WGPeers: []PoolVIPOwnershipWGPeerV3{{PublicKey: "qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M=", AllowedIPs: []string{"10.44.0.0/16", "100.64.0.2/32"}}},
		Routes: []string{"10.44.0.0/16", "100.64.0.2/32"}, Services: []PoolVIPOwnershipServiceV3{{ServiceID: "00000000-0000-4000-8000-000000000020",
			VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", DNSName: "api.default.cluster.k8s.example", Protocol: "tcp", Port: 443}}}
	identity, err := nodepolicy.PoolVIPOwnershipManifestIdentity(manifest.policyManifest())
	if err != nil {
		t.Fatal(err)
	}
	base.ManifestIdentity = identity
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil {
		t.Fatal(err)
	}
	return PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: base, ExpiresAt: expires, Manifest: manifest,
		ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: poolVIPOwnershipManifestVIPMapDigestV3(manifest.policyManifest())}
}

func cloneOwnershipManifestV3(in PoolVIPOwnershipManifestV3) PoolVIPOwnershipManifestV3 {
	out := in
	out.WGPeers = make([]PoolVIPOwnershipWGPeerV3, len(in.WGPeers))
	for i, peer := range in.WGPeers {
		out.WGPeers[i] = PoolVIPOwnershipWGPeerV3{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)}
	}
	out.Routes = append([]string(nil), in.Routes...)
	out.Services = append([]PoolVIPOwnershipServiceV3(nil), in.Services...)
	return out
}

func ownershipDeliveryClientEnvelope() PoolVIPOwnershipDeliveryEnvelope {
	return PoolVIPOwnershipDeliveryEnvelope{
		Version: 1, OrgID: "00000000-0000-4000-8000-000000000001", SiteID: "019f6400-0000-4000-8000-000000000002",
		ClusterID: "00000000-0000-4000-8000-000000000003", PoolID: "00000000-0000-4000-8000-000000000004",
		ConnectorNodeID: "00000000-0000-4000-8000-000000000005", TargetNodeID: "00000000-0000-4000-8000-000000000006",
		OperationID: "00000000-0000-4000-8000-000000000007", ManifestIdentity: strings.Repeat("a", 64), Role: nodepolicy.PoolVIPOwnershipServing,
		PromotionGeneration: 7, ManifestRevision: 11, LeaseEpoch: 13, DeliveryPhase: "serve",
		DeliveryID: "00000000-0000-4000-8000-000000000008", DeliveryNonce: strings.Repeat("b", 64),
	}
}

func ownershipDeliveryTestClient(t *testing.T, ca *testCA, mux *http.ServeMux) *Client {
	t.Helper()
	serverKeyPEM, serverCSR, err := GenerateKeyAndCSR("tunnex-control")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(serverCSR)
	serverCertPEM, _ := ca.sign(t, block.Bytes, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair([]byte(serverCertPEM), serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	certPEM, keyPEM := ca.clientCert(t, "gw-1")
	client, err := NewClient(server.URL, "tunnex-control", "gw-1", certPEM, keyPEM, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
