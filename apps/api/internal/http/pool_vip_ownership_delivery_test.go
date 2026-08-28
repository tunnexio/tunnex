package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestPoolVIPOwnershipDeliveryNegotiatesExactV1AndBindsPrincipal(t *testing.T) {
	agent := ownershipDeliveryHTTPAgent()
	store := &ownershipDeliveryHTTPStore{envelope: ownershipDeliveryHTTPEnvelope(agent)}
	channel := &AgentChannel{ownershipDeliveryStore: store}

	t.Run("old agent has no capability and gets no envelope", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
		w := httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
		if w.Code != http.StatusNoContent || store.loadCalls != 0 {
			t.Fatalf("old agent response=%d loads=%d", w.Code, store.loadCalls)
		}
	})

	t.Run("new agent advertises exact v1", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
		r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "1")
		w := httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
		if w.Code != http.StatusOK || store.lastLoadAgent != agent {
			t.Fatalf("new agent response=%d agent=%+v", w.Code, store.lastLoadAgent)
		}
		var got nodes.PoolVIPOwnershipDeliveryEnvelope
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil || got != store.envelope {
			t.Fatalf("envelope=%+v err=%v", got, err)
		}
	})

	t.Run("capable agent gets no work without a durable store", func(t *testing.T) {
		channel.ownershipDeliveryStore = nil
		r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
		r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "1")
		w := httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
		if w.Code != http.StatusNoContent {
			t.Fatalf("unwired response=%d", w.Code)
		}
		channel.ownershipDeliveryStore = store
	})

	for name, header := range map[string][]string{
		"future":    {"4"},
		"ambiguous": {"1", "2"},
	} {
		t.Run(name+" capability is rejected", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
			for _, value := range header {
				r.Header.Add(poolVIPOwnershipDeliveryCapabilityHeader, value)
			}
			w := httptest.NewRecorder()
			channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("response=%d", w.Code)
			}
		})
	}

	for name, mutate := range map[string]func(*nodes.PoolVIPOwnershipDeliveryEnvelope){
		"node": func(envelope *nodes.PoolVIPOwnershipDeliveryEnvelope) { envelope.TargetNodeID = uuid.New().String() },
		"org":  func(envelope *nodes.PoolVIPOwnershipDeliveryEnvelope) { envelope.OrgID = uuid.New().String() },
	} {
		t.Run("store cannot cross authenticated "+name+" principal", func(t *testing.T) {
			wrong := store.envelope
			mutate(&wrong)
			channel.ownershipDeliveryStore = &ownershipDeliveryHTTPStore{envelope: wrong}
			r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
			r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "1")
			w := httptest.NewRecorder()
			channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("cross-principal response=%d", w.Code)
			}
			channel.ownershipDeliveryStore = store
		})
	}
}

func TestPoolVIPOwnershipDeliveryRoutesRequireMTLSPrincipal(t *testing.T) {
	channel := &AgentChannel{}
	for _, methodPath := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/agent/pool-vip-ownership-delivery"},
		{method: http.MethodPost, path: "/agent/pool-vip-ownership-delivery/ack"},
	} {
		t.Run(methodPath.method+" "+methodPath.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			channel.Handler().ServeHTTP(w, httptest.NewRequest(methodPath.method, methodPath.path, nil))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated route status=%d", w.Code)
			}
		})
	}
}

func TestPoolVIPOwnershipDeliveryAckIsStrictAndReplaySafe(t *testing.T) {
	agent := ownershipDeliveryHTTPAgent()
	store := &ownershipDeliveryHTTPStore{envelope: ownershipDeliveryHTTPEnvelope(agent)}
	channel := &AgentChannel{ownershipDeliveryStore: store}
	ack := ownershipDeliveryHTTPAck(store.envelope)

	post := func(body []byte, header string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
		if header != "" {
			r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, header)
		}
		w := httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryAckForAgent(w, r, agent)
		return w
	}

	validBody, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(validBody, "1"); w.Code != http.StatusNoContent || store.persistCalls != 1 {
		t.Fatalf("first acknowledgement response=%d persists=%d", w.Code, store.persistCalls)
	}
	if w := post(validBody, "1"); w.Code != http.StatusNoContent || store.persistCalls != 2 || !store.lastDuplicate {
		t.Fatalf("idempotent retry response=%d persists=%d duplicate=%v", w.Code, store.persistCalls, store.lastDuplicate)
	}
	if w := post(validBody, "2"); w.Code != http.StatusBadRequest || store.persistCalls != 2 {
		t.Fatalf("future capability response=%d persists=%d", w.Code, store.persistCalls)
	}
	if w := post([]byte(strings.TrimSuffix(string(validBody), "}")+`,"extra":true}`), "1"); w.Code != http.StatusBadRequest || store.persistCalls != 2 {
		t.Fatalf("unknown acknowledgement response=%d persists=%d", w.Code, store.persistCalls)
	}
	if w := post([]byte(strings.TrimSuffix(string(validBody), "}")+`,"version":2}`), "1"); w.Code != http.StatusBadRequest || store.persistCalls != 2 {
		t.Fatalf("duplicate acknowledgement key response=%d persists=%d", w.Code, store.persistCalls)
	}
	ack.Version = 2
	futureBody, _ := json.Marshal(ack)
	if w := post(futureBody, "1"); w.Code != http.StatusBadRequest || store.persistCalls != 2 {
		t.Fatalf("future acknowledgement response=%d persists=%d", w.Code, store.persistCalls)
	}

	wrongStore := &ownershipDeliveryHTTPStore{envelope: ownershipDeliveryHTTPEnvelope(nodes.PoolVIPOwnershipAgentIdentity{NodeID: uuid.New(), OrgID: agent.OrgID})}
	channel.ownershipDeliveryStore = wrongStore
	if w := post(validBody, "1"); w.Code != http.StatusBadRequest || wrongStore.persistCalls != 0 {
		t.Fatalf("cross-principal acknowledgement response=%d persists=%d", w.Code, wrongStore.persistCalls)
	}
}

func FuzzPoolVIPOwnershipDeliveryAckJSON(f *testing.F) {
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Add([]byte(`{"version":1,"unknown":true}`))
	f.Add([]byte(`{"version":18446744073709551616}`))
	f.Add([]byte(`{"version":1}{"version":1}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var ack nodes.PoolVIPOwnershipDeliveryAckV2
		_ = decodePoolVIPOwnershipDeliveryJSON(bytes.NewReader(body), &ack)
	})
}

func TestPoolVIPOwnershipDeliveryAckRejectsOversizedTrailingBodyBeforePersistence(t *testing.T) {
	agent := ownershipDeliveryHTTPAgent()
	store := &ownershipDeliveryHTTPStore{envelope: ownershipDeliveryHTTPEnvelope(agent)}
	channel := &AgentChannel{ownershipDeliveryStore: store}
	ack, err := json.Marshal(ownershipDeliveryHTTPAck(store.envelope))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "token=not-for-response gw.customer.example:51820"
	body := append(append([]byte{}, ack...), []byte(secret+strings.Repeat(" ", poolVIPOwnershipDeliveryJSONLimit))...)
	r := httptest.NewRequest(http.MethodPost, "/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
	r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "1")
	w := httptest.NewRecorder()
	channel.poolVIPOwnershipDeliveryAckForAgent(w, r, agent)
	if w.Code != http.StatusBadRequest || store.persistCalls != 0 {
		t.Fatalf("oversized acknowledgement status=%d persists=%d", w.Code, store.persistCalls)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("rejection leaked raw request diagnostic: %q", w.Body.String())
	}
}

func TestPoolVIPOwnershipDeliveryNegotiatesV2WithoutChangingV1(t *testing.T) {
	agent := ownershipDeliveryHTTPAgent()
	v1 := ownershipDeliveryHTTPEnvelope(agent)
	v2 := ownershipDeliveryHTTPEnvelopeV2(agent)
	store := &ownershipDeliveryHTTPV2Store{ownershipDeliveryHTTPStore: ownershipDeliveryHTTPStore{envelope: v1}, envelopeV2: v2}
	channel := &AgentChannel{ownershipDeliveryStore: store}

	get := func(version string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
		r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, version)
		w := httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
		return w
	}
	if w := get("1"); w.Code != http.StatusOK || store.loadCalls != 1 || store.v2Loads != 0 {
		t.Fatalf("v1 behavior changed: status=%d v1=%d v2=%d", w.Code, store.loadCalls, store.v2Loads)
	}
	w := get("2")
	if w.Code != http.StatusOK || store.v2Loads != 1 || store.loadCalls != 1 {
		t.Fatalf("v2 get status=%d v1=%d v2=%d", w.Code, store.loadCalls, store.v2Loads)
	}
	var got nodes.PoolVIPOwnershipDeliveryEnvelopeV2
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil || got.ExpectedRouteDigest != v2.ExpectedRouteDigest {
		t.Fatalf("v2 envelope=%+v err=%v", got, err)
	}
	ack, err := json.Marshal(ownershipDeliveryHTTPAckV2(v2))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(ack))
	r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "2")
	w = httptest.NewRecorder()
	channel.poolVIPOwnershipDeliveryAckForAgent(w, r, agent)
	if w.Code != http.StatusNoContent || store.v2Persists != 1 {
		t.Fatalf("v2 ack status=%d persists=%d", w.Code, store.v2Persists)
	}
	duplicate := []byte(strings.TrimSuffix(string(ack), "}") + `,"applied_role":"withdrawal"}`)
	r = httptest.NewRequest(http.MethodPost, "/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(duplicate))
	r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "2")
	w = httptest.NewRecorder()
	channel.poolVIPOwnershipDeliveryAckForAgent(w, r, agent)
	if w.Code != http.StatusBadRequest || store.v2Persists != 1 {
		t.Fatalf("ambiguous v2 ack status=%d persists=%d", w.Code, store.v2Persists)
	}
}

func TestPoolVIPOwnershipDeliveryNegotiatesExactV3AndPersistsAppliedManifest(t *testing.T) {
	agent := ownershipDeliveryHTTPAgent()
	envelope := ownershipDeliveryHTTPEnvelopeV3(t, agent)
	if err := nodes.ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		t.Fatalf("v3 fixture: %v", err)
	}
	store := &ownershipDeliveryHTTPV3Store{ownershipDeliveryHTTPV2Store: ownershipDeliveryHTTPV2Store{ownershipDeliveryHTTPStore: ownershipDeliveryHTTPStore{envelope: ownershipDeliveryHTTPEnvelope(agent)}}, envelopeV3: envelope}
	channel := &AgentChannel{ownershipDeliveryStore: store}
	r := httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
	r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "3")
	w := httptest.NewRecorder()
	channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
	if w.Code != http.StatusOK || store.v3Loads != 1 {
		t.Fatalf("v3 get status=%d loads=%d", w.Code, store.v3Loads)
	}
	ack := nodes.PoolVIPOwnershipDeliveryAckV3{PoolVIPOwnershipDeliveryAck: ownershipDeliveryHTTPAck(envelope.PoolVIPOwnershipDeliveryEnvelope), AppliedManifest: envelope.Manifest, AppliedLeaseEpoch: envelope.LeaseEpoch}
	body, _ := json.Marshal(ack)
	r = httptest.NewRequest(http.MethodPost, "/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
	r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "3")
	w = httptest.NewRecorder()
	channel.poolVIPOwnershipDeliveryAckForAgent(w, r, agent)
	if w.Code != http.StatusNoContent || store.v3Persists != 1 || store.applied.Services[0].ServiceID != envelope.Manifest.Services[0].ServiceID {
		t.Fatalf("v3 ack status=%d persists=%d applied=%+v", w.Code, store.v3Persists, store.applied)
	}
	for _, capability := range []string{"03", "2,3", "4"} {
		r = httptest.NewRequest(http.MethodGet, "/agent/pool-vip-ownership-delivery", nil)
		r.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, capability)
		w = httptest.NewRecorder()
		channel.poolVIPOwnershipDeliveryForAgent(w, r, agent)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("non-exact capability %q status=%d", capability, w.Code)
		}
	}
}

type ownershipDeliveryHTTPStore struct {
	envelope      nodes.PoolVIPOwnershipDeliveryEnvelope
	state         nodes.PoolVIPOwnershipAckState
	loadCalls     int
	lastLoadAgent nodes.PoolVIPOwnershipAgentIdentity
	persistCalls  int
	lastDuplicate bool
}

type ownershipDeliveryHTTPV2Store struct {
	ownershipDeliveryHTTPStore
	envelopeV2 nodes.PoolVIPOwnershipDeliveryEnvelopeV2
	stateV2    nodes.PoolVIPOwnershipAckState
	v2Loads    int
	v2Persists int
}

type ownershipDeliveryHTTPV3Store struct {
	ownershipDeliveryHTTPV2Store
	envelopeV3          nodes.PoolVIPOwnershipDeliveryEnvelopeV3
	stateV3             nodes.PoolVIPOwnershipAckState
	v3Loads, v3Persists int
	applied             nodes.PoolVIPOwnershipManifestV3
}

func (s *ownershipDeliveryHTTPV3Store) LoadIssuedPoolVIPOwnershipDeliveryV3(_ context.Context, _ nodes.PoolVIPOwnershipAgentIdentity) (nodes.PoolVIPOwnershipDeliveryEnvelopeV3, bool, error) {
	s.v3Loads++
	return s.envelopeV3, true, nil
}

func (s *ownershipDeliveryHTTPV3Store) UpdatePoolVIPOwnershipAckV3(_ context.Context, _ nodes.PoolVIPOwnershipAgentIdentity, ack nodes.PoolVIPOwnershipDeliveryAckV3, receipt time.Time, validate func(nodes.PoolVIPOwnershipDeliveryEnvelopeV3, nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error)) (nodes.PoolVIPOwnershipAckValidation, error) {
	result, err := validate(s.envelopeV3, s.stateV3)
	if err != nil {
		return nodes.PoolVIPOwnershipAckValidation{}, err
	}
	s.stateV3, s.applied, s.v3Persists = result.NextState, ack.AppliedManifest, s.v3Persists+1
	return result, nil
}

func (s *ownershipDeliveryHTTPV2Store) LoadIssuedPoolVIPOwnershipDeliveryV2(_ context.Context, _ nodes.PoolVIPOwnershipAgentIdentity) (nodes.PoolVIPOwnershipDeliveryEnvelopeV2, bool, error) {
	s.v2Loads++
	return s.envelopeV2, true, nil
}

func (s *ownershipDeliveryHTTPV2Store) UpdatePoolVIPOwnershipAckV2(_ context.Context, _ nodes.PoolVIPOwnershipAgentIdentity, _ nodes.PoolVIPOwnershipDeliveryAckV2, _ time.Time, validate func(nodes.PoolVIPOwnershipDeliveryEnvelopeV2, nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error)) (nodes.PoolVIPOwnershipAckValidation, error) {
	result, err := validate(s.envelopeV2, s.stateV2)
	if err != nil {
		return nodes.PoolVIPOwnershipAckValidation{}, err
	}
	s.stateV2 = result.NextState
	s.v2Persists++
	return result, nil
}

func (s *ownershipDeliveryHTTPStore) LoadIssuedPoolVIPOwnershipDelivery(_ context.Context, agent nodes.PoolVIPOwnershipAgentIdentity) (nodes.PoolVIPOwnershipDeliveryEnvelope, bool, error) {
	s.loadCalls++
	s.lastLoadAgent = agent
	return s.envelope, true, nil
}

func (s *ownershipDeliveryHTTPStore) UpdatePoolVIPOwnershipAck(_ context.Context, agent nodes.PoolVIPOwnershipAgentIdentity, ack nodes.PoolVIPOwnershipDeliveryAck, receiptTime time.Time, validate func(nodes.PoolVIPOwnershipDeliveryEnvelope, nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error)) (nodes.PoolVIPOwnershipAckValidation, error) {
	if receiptTime.IsZero() {
		return nodes.PoolVIPOwnershipAckValidation{}, errors.New("missing receipt time")
	}
	result, err := validate(s.envelope, s.state)
	if err != nil {
		return nodes.PoolVIPOwnershipAckValidation{}, err
	}
	s.state = result.NextState
	s.persistCalls++
	s.lastDuplicate = result.Duplicate
	return result, nil
}

func ownershipDeliveryHTTPAgent() nodes.PoolVIPOwnershipAgentIdentity {
	return nodes.PoolVIPOwnershipAgentIdentity{
		NodeID: uuid.MustParse("00000000-0000-4000-8000-000000000006"),
		OrgID:  uuid.MustParse("00000000-0000-4000-8000-000000000001"),
	}
}

func ownershipDeliveryHTTPEnvelope(agent nodes.PoolVIPOwnershipAgentIdentity) nodes.PoolVIPOwnershipDeliveryEnvelope {
	return nodes.PoolVIPOwnershipDeliveryEnvelope{
		Version: 1, OrgID: agent.OrgID.String(), SiteID: "00000000-0000-4000-8000-000000000002", ClusterID: "00000000-0000-4000-8000-000000000003",
		PoolID: "00000000-0000-4000-8000-000000000004", ConnectorNodeID: "00000000-0000-4000-8000-000000000005", TargetNodeID: agent.NodeID.String(),
		OperationID: "00000000-0000-4000-8000-000000000007", ManifestIdentity: strings.Repeat("a", 64), Role: policyspec.PoolVIPOwnershipServing,
		PromotionGeneration: 7, ManifestRevision: 11, LeaseEpoch: 13, DeliveryPhase: "serve",
		DeliveryID: "00000000-0000-4000-8000-000000000008", DeliveryNonce: strings.Repeat("b", 64),
	}
}

func ownershipDeliveryHTTPAck(envelope nodes.PoolVIPOwnershipDeliveryEnvelope) nodes.PoolVIPOwnershipDeliveryAck {
	return nodes.PoolVIPOwnershipDeliveryAck{
		Version: envelope.Version, OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID, PoolID: envelope.PoolID,
		ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID, OperationID: envelope.OperationID,
		ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role, PromotionGeneration: envelope.PromotionGeneration,
		ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch, DeliveryPhase: envelope.DeliveryPhase,
		DeliveryID: envelope.DeliveryID, DeliveryNonce: envelope.DeliveryNonce,
	}
}

func ownershipDeliveryHTTPEnvelopeV2(agent nodes.PoolVIPOwnershipAgentIdentity) nodes.PoolVIPOwnershipDeliveryEnvelopeV2 {
	base := ownershipDeliveryHTTPEnvelope(agent)
	base.Version = nodes.PoolVIPOwnershipDeliveryAttestationVersion
	v := nodes.PoolVIPOwnershipDeliveryEnvelopeV2{PoolVIPOwnershipDeliveryEnvelope: base, OwnedRoutes: []string{"10.44.0.0/16"}, ExpectedVIPMapDigest: strings.Repeat("c", 64)}
	v.ExpectedRouteDigest, _ = nodes.PoolVIPOwnershipOwnedRouteDigest(v.OwnedRoutes)
	return v
}

func ownershipDeliveryHTTPAckV2(envelope nodes.PoolVIPOwnershipDeliveryEnvelopeV2) nodes.PoolVIPOwnershipDeliveryAckV2 {
	return nodes.PoolVIPOwnershipDeliveryAckV2{PoolVIPOwnershipDeliveryAck: ownershipDeliveryHTTPAck(envelope.PoolVIPOwnershipDeliveryEnvelope), AppliedRole: envelope.Role, AppliedManifestIdentity: envelope.ManifestIdentity, AppliedPromotionGeneration: envelope.PromotionGeneration, AppliedManifestRevision: envelope.ManifestRevision, AppliedLeaseEpoch: envelope.LeaseEpoch, OwnedRouteDigest: envelope.ExpectedRouteDigest, VIPMapDigest: envelope.ExpectedVIPMapDigest}
}

func ownershipDeliveryHTTPEnvelopeV3(t *testing.T, agent nodes.PoolVIPOwnershipAgentIdentity) nodes.PoolVIPOwnershipDeliveryEnvelopeV3 {
	t.Helper()
	base := ownershipDeliveryHTTPEnvelope(agent)
	base.Version = nodes.PoolVIPOwnershipDeliveryHandoffVersion
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	manifest := nodes.PoolVIPOwnershipManifestV3{Version: 1, OrgID: base.OrgID, SiteID: base.SiteID, ClusterID: base.ClusterID, PoolID: base.PoolID, ConnectorNodeID: base.ConnectorNodeID, Role: base.Role, PromotionGeneration: base.PromotionGeneration, ManifestRevision: base.ManifestRevision, LeaseEpoch: base.LeaseEpoch, LeaseExpiresAt: expires, DNSZone: "cluster.k8s.example", DNSVIP: "100.64.0.2", HandoffOwnerID: base.OperationID, RouteIntent: "serving", WGPeers: []nodes.PoolVIPOwnershipWGPeerV3{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}}}, Routes: []string{"10.44.0.0/16"}, Services: []nodes.PoolVIPOwnershipServiceV3{{ServiceID: "00000000-0000-4000-8000-000000000020", VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", DNSName: "api.default.cluster.k8s.example", Protocol: "tcp", Port: 443}}}
	policyManifest := policyspec.PoolVIPOwnershipManifest{Version: 1, OrgID: manifest.OrgID, SiteID: manifest.SiteID, ClusterID: manifest.ClusterID, PoolID: manifest.PoolID, ConnectorNodeID: manifest.ConnectorNodeID, Role: manifest.Role, PromotionGeneration: manifest.PromotionGeneration, ManifestRevision: manifest.ManifestRevision, LeaseEpoch: manifest.LeaseEpoch, LeaseExpiresAt: expires, DNSZone: manifest.DNSZone, DNSVIP: manifest.DNSVIP, HandoffOwnerID: manifest.HandoffOwnerID, RouteIntent: manifest.RouteIntent, WGPeers: []policyspec.PoolVIPOwnershipWGPeer{{PublicKey: manifest.WGPeers[0].PublicKey, AllowedIPs: manifest.WGPeers[0].AllowedIPs}}, Routes: manifest.Routes, Services: []policyspec.PoolVIPOwnershipService{{ServiceID: manifest.Services[0].ServiceID, VIP: manifest.Services[0].VIP, Namespace: manifest.Services[0].Namespace, Service: manifest.Services[0].Service, ServiceCIDR: manifest.Services[0].ServiceCIDR, DNSName: manifest.Services[0].DNSName, Protocol: manifest.Services[0].Protocol, Port: manifest.Services[0].Port}}}
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(policyManifest)
	if err != nil {
		t.Fatal(err)
	}
	base.ManifestIdentity = identity
	routeDigest, _ := nodes.PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	vipDigest := policyspec.VIPMapDigest([]policyspec.VIPMapping{{ServiceID: manifest.Services[0].ServiceID, VIP: manifest.Services[0].VIP, Namespace: manifest.Services[0].Namespace, Service: manifest.Services[0].Service, ServiceCIDR: manifest.Services[0].ServiceCIDR, DNSName: manifest.Services[0].DNSName, Protocol: manifest.Services[0].Protocol, PortLow: 443, PortHigh: 443}})
	return nodes.PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: base, ExpiresAt: expires, Manifest: manifest, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipDigest}
}
