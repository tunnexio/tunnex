package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type baseAuthorityHTTPStore struct {
	authority nodes.KubernetesOwnershipBaseAuthority
	digest    string
	found     bool
	loads     int
	acks      int
	seen      *nodes.KubernetesOwnershipBaseAuthorityAck
}

func (s *baseAuthorityHTTPStore) LoadPendingKubernetesOwnershipBaseAuthority(_ context.Context, _ nodes.KubernetesOwnershipBaseAuthorityAgentIdentity) (nodes.KubernetesOwnershipBaseAuthority, bool, error) {
	s.loads++
	return s.authority, s.found, nil
}

func (s *baseAuthorityHTTPStore) AcknowledgeKubernetesOwnershipBaseAuthority(_ context.Context, agent nodes.KubernetesOwnershipBaseAuthorityAgentIdentity, ack nodes.KubernetesOwnershipBaseAuthorityAck, _ time.Time) (bool, error) {
	if _, err := nodes.ValidateKubernetesOwnershipBaseAuthorityAck(agent, s.authority, s.digest, ack); err != nil {
		return false, err
	}
	s.acks++
	duplicate := s.seen != nil
	if s.seen != nil && *s.seen != ack {
		return false, nodes.ErrKubernetesOwnershipBaseAuthorityConflict
	}
	s.seen = &ack
	return duplicate, nil
}

func baseAuthorityHTTPFixture(t *testing.T, state nodes.DesiredState) (nodes.KubernetesOwnershipBaseAuthority, string) {
	t.Helper()
	hash, err := nodes.KubernetesOwnershipBaseStateHash(state)
	if err != nil {
		t.Fatal(err)
	}
	authority := nodes.KubernetesOwnershipBaseAuthority{
		WireVersion: 1, AuthorityRevision: 3, NodeID: state.NodeID,
		OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		BaseVersion: state.Version, BaseHash: hash,
		Classifications: []nodes.KubernetesOwnershipPoolClassification{{
			Scope:       nodes.KubernetesOwnershipPoolScope{OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222", ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444"},
			Disposition: nodes.KubernetesOwnershipPoolDispositionArmFence,
			Fields:      nodes.KubernetesOwnershipPoolFields{Routes: []string{"10.44.0.0/16"}, WGPeers: []nodes.KubernetesOwnershipWGPeer{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}}}},
		}},
	}
	authority, digest, err := nodes.CanonicalKubernetesOwnershipBaseAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	return authority, digest
}

func TestDesiredStateAddsOnlyExactPendingBaseAuthority(t *testing.T) {
	state := desiredStateWithGatewayDNSRequest{DesiredState: nodes.DesiredState{ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", Version: 17, Peers: []nodes.Peer{}}}
	authority, digest := baseAuthorityHTTPFixture(t, state.DesiredState)
	store := &baseAuthorityHTTPStore{authority: authority, digest: digest, found: true}
	channel := &AgentChannel{baseAuthorityStore: store}
	node := sqlc.Node{ID: uuid.MustParse(authority.NodeID), OrgID: uuid.MustParse(authority.OrgID), SiteID: pgtype.UUID{Bytes: uuid.MustParse(authority.SiteID), Valid: true}}
	got, err := channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, state)
	if err != nil || got.KubernetesOwnershipBaseAuthority == nil || got.KubernetesOwnershipBaseAuthority.AuthorityRevision != 3 {
		t.Fatalf("state=%+v err=%v", got, err)
	}

	store.authority.BaseHash = strings.Repeat("f", 64)
	if _, err := channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, state); err == nil {
		t.Fatal("wrong-base authority was delivered")
	}
	channel.baseAuthorityStore = nil
	got, err = channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, state)
	if err != nil || got.KubernetesOwnershipBaseAuthority != nil {
		t.Fatalf("default-off state=%+v err=%v", got, err)
	}
}

func TestBaseAuthorityAckIsStrictPrincipalBoundAndReplaySafe(t *testing.T) {
	state := nodes.DesiredState{ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", Version: 17, Peers: []nodes.Peer{}}
	authority, digest := baseAuthorityHTTPFixture(t, state)
	store := &baseAuthorityHTTPStore{authority: authority, digest: digest, found: true}
	channel := &AgentChannel{baseAuthorityStore: store}
	agent := nodes.KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: uuid.MustParse(authority.NodeID), OrgID: uuid.MustParse(authority.OrgID), SiteID: uuid.MustParse(authority.SiteID)}
	ack := nodes.KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: authority.AuthorityRevision, NodeID: authority.NodeID, OrgID: authority.OrgID,
		SiteID: authority.SiteID, BaseVersion: authority.BaseVersion, BaseHash: authority.BaseHash, AuthorityDigest: digest, AppliedAt: "2026-08-28T10:11:12.000000345Z"}
	post := func(raw []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		channel.kubernetesOwnershipBaseAuthorityAckForAgent(w, httptest.NewRequest(http.MethodPost, "/agent/kubernetes-ownership-base-authority/ack", bytes.NewReader(raw)), agent)
		return w
	}
	body, _ := json.Marshal(ack)
	if w := post(body); w.Code != http.StatusNoContent || store.acks != 1 {
		t.Fatalf("first status=%d acks=%d", w.Code, store.acks)
	}
	if w := post(body); w.Code != http.StatusNoContent || store.acks != 2 {
		t.Fatalf("replay status=%d acks=%d", w.Code, store.acks)
	}
	for name, raw := range map[string][]byte{
		"unknown":   []byte(strings.TrimSuffix(string(body), "}") + `,"unknown":true}`),
		"duplicate": []byte(strings.TrimSuffix(string(body), "}") + `,"wire_version":1}`),
		"trailing":  append(append([]byte(nil), body...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if w := post(raw); w.Code != http.StatusBadRequest || store.acks != 2 {
				t.Fatalf("status=%d acks=%d", w.Code, store.acks)
			}
		})
	}
	changed := ack
	changed.NodeID = uuid.New().String()
	changedBody, _ := json.Marshal(changed)
	if w := post(changedBody); w.Code != http.StatusBadRequest || store.acks != 2 {
		t.Fatalf("cross-principal status=%d acks=%d", w.Code, store.acks)
	}
}

func TestBaseAuthorityAckRouteRequiresMTLSAndStore(t *testing.T) {
	channel := &AgentChannel{}
	w := httptest.NewRecorder()
	channel.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/agent/kubernetes-ownership-base-authority/ack", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", w.Code)
	}
}

func TestPendingBaseAuthorityKeepsOriginalTupleAcrossWake(t *testing.T) {
	base := nodes.DesiredState{ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", Version: 17, Peers: []nodes.Peer{}}
	authority, digest := baseAuthorityHTTPFixture(t, base)
	node := sqlc.Node{ID: uuid.MustParse(authority.NodeID), OrgID: uuid.MustParse(authority.OrgID), SiteID: pgtype.UUID{Bytes: uuid.MustParse(authority.SiteID), Valid: true}}
	store := &baseAuthorityHTTPStore{authority: authority, digest: digest, found: true}
	channel := &AgentChannel{baseAuthorityStore: store}
	base.Version = 23 // a wake changed no canonical base bytes
	got, err := channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, desiredStateWithGatewayDNSRequest{DesiredState: base})
	if err != nil || got.Version != 17 || !reflect.DeepEqual(got.KubernetesOwnershipBaseAuthority, &authority) {
		t.Fatalf("pending tuple changed or was refused: version=%d err=%v", got.Version, err)
	}
	agent := nodes.KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: node.ID, OrgID: node.OrgID, SiteID: uuid.UUID(node.SiteID.Bytes)}
	ack := nodes.KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: authority.AuthorityRevision, NodeID: authority.NodeID, OrgID: authority.OrgID,
		SiteID: authority.SiteID, BaseVersion: got.Version, BaseHash: authority.BaseHash, AuthorityDigest: digest, AppliedAt: "2026-08-28T10:11:12.000000345Z"}
	if _, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(t.Context(), agent, ack, time.Now().UTC()); err != nil {
		t.Fatalf("original pending receipt refused: %v", err)
	}
	store.found = false // real store omits the acknowledged delivery
	got, err = channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, desiredStateWithGatewayDNSRequest{DesiredState: base})
	if err != nil || got.Version != 23 || got.KubernetesOwnershipBaseAuthority != nil {
		t.Fatalf("ordinary cursor did not resume after ACK: version=%d err=%v", got.Version, err)
	}

	for _, name := range []string{"future_cursor", "zero_cursor", "changed_content", "wrong_node", "wrong_org", "wrong_site"} {
		t.Run(name, func(t *testing.T) {
			bad, changed := authority, base
			switch name {
			case "future_cursor":
				bad.BaseVersion = base.Version + 1
			case "zero_cursor":
				bad.BaseVersion = 0
			case "changed_content":
				changed.MTU = 1300
			case "wrong_node":
				bad.NodeID = uuid.NewString()
			case "wrong_org":
				bad.OrgID = uuid.NewString()
			case "wrong_site":
				bad.SiteID = uuid.NewString()
			}
			channel := &AgentChannel{baseAuthorityStore: &baseAuthorityHTTPStore{authority: bad, found: true}}
			if _, err := channel.withKubernetesOwnershipBaseAuthority(t.Context(), node, desiredStateWithGatewayDNSRequest{DesiredState: changed}); err == nil {
				t.Fatal("non-exact pending authority was accepted")
			}
		})
	}
}
