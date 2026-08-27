package http

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type fakeGatewayDNSMailbox struct {
	pendingForOrg     uuid.UUID
	pendingForGateway uuid.UUID
	pending           []fqdnresolver.GatewayDNSRequest
	pendingErr        error
	completedOrg      uuid.UUID
	completedGateway  uuid.UUID
	completed         fqdnresolver.GatewayDNSResponse
	completeErr       error
}

func (m *fakeGatewayDNSMailbox) PendingForGateway(_ context.Context, orgID, gatewayID uuid.UUID, limit int) ([]fqdnresolver.GatewayDNSRequest, error) {
	if limit != 1 {
		panic("agent desired state must expose one bounded DNS request")
	}
	m.pendingForOrg, m.pendingForGateway = orgID, gatewayID
	return m.pending, m.pendingErr
}

func (m *fakeGatewayDNSMailbox) Complete(_ context.Context, orgID, gatewayID uuid.UUID, response fqdnresolver.GatewayDNSResponse) error {
	m.completedOrg, m.completedGateway, m.completed = orgID, gatewayID, response
	return m.completeErr
}

func TestAgentChannelGatewayDNSDesiredStateIsAuthenticatedAndGatewayScoped(t *testing.T) {
	org, gateway, other := uuid.New(), uuid.New(), uuid.New()
	request := fqdnresolver.GatewayDNSRequest{RequestID: uuid.New(), OrgID: org, GatewayID: gateway, Deadline: time.Now().Add(time.Minute)}
	mailbox := &fakeGatewayDNSMailbox{pending: []fqdnresolver.GatewayDNSRequest{request, {RequestID: uuid.New()}}}
	channel := &AgentChannel{dnsMailbox: mailbox}
	state, err := channel.withGatewayDNSRequest(t.Context(), sqlc.Node{ID: gateway, OrgID: org}, nodes.DesiredState{NodeID: gateway.String()})
	if err != nil {
		t.Fatal(err)
	}
	if mailbox.pendingForOrg != org || mailbox.pendingForGateway != gateway {
		t.Fatalf("mailbox scope=(%s,%s), want authenticated (%s,%s)", mailbox.pendingForOrg, mailbox.pendingForGateway, org, gateway)
	}
	if state.DNSResolveRequest == nil || state.DNSResolveRequest.RequestID != request.RequestID {
		t.Fatalf("desired state request=%#v, want first pending request %#v", state.DNSResolveRequest, request)
	}
	if state.DNSResolveRequest.GatewayID == other {
		t.Fatal("desired state leaked a request for another gateway")
	}
}

func TestAgentChannelGatewayDNSCompletionUsesCertificateDerivedIdentity(t *testing.T) {
	org, gateway := uuid.New(), uuid.New()
	response := fqdnresolver.GatewayDNSResponse{RequestID: uuid.New(), OrgID: uuid.New(), GatewayID: uuid.New()}
	mailbox := &fakeGatewayDNSMailbox{completeErr: fqdnresolver.ErrGatewayDNSRPCReplay}
	channel := &AgentChannel{dnsMailbox: mailbox}
	err := channel.completeGatewayDNSResponse(t.Context(), sqlc.Node{ID: gateway, OrgID: org}, response)
	if !errors.Is(err, fqdnresolver.ErrGatewayDNSRPCReplay) {
		t.Fatalf("completion error=%v, want replay propagation", err)
	}
	if mailbox.completedOrg != org || mailbox.completedGateway != gateway {
		t.Fatalf("completion trusted body identities (%s,%s), want authenticated certificate identities (%s,%s)", mailbox.completedOrg, mailbox.completedGateway, org, gateway)
	}
	if mailbox.completed.RequestID != response.RequestID {
		t.Fatal("completion did not preserve correlated response")
	}
}

func TestAgentChannelGatewayDNSDesiredStateFailsAtomicallyOnMailboxRead(t *testing.T) {
	mailbox := &fakeGatewayDNSMailbox{pendingErr: errors.New("mailbox unavailable")}
	channel := &AgentChannel{dnsMailbox: mailbox}
	_, err := channel.withGatewayDNSRequest(t.Context(), sqlc.Node{ID: uuid.New(), OrgID: uuid.New()}, nodes.DesiredState{})
	if err == nil {
		t.Fatal("mailbox read failure must fail desired-state atomically")
	}
}

func TestAgentChannelGatewayDNSNotifierWakesOnlySelectedGateway(t *testing.T) {
	selected, other := uuid.New(), uuid.New()
	hub := nodepush.New()
	selectedWake, stopSelected := hub.Subscribe(selected)
	defer stopSelected()
	otherWake, stopOther := hub.Subscribe(other)
	defer stopOther()
	channel := &AgentChannel{hub: hub}
	channel.NotifyGatewayDNSRequest(t.Context(), uuid.New(), selected)
	select {
	case <-selectedWake:
	case <-time.After(time.Second):
		t.Fatal("selected gateway was not woken")
	}
	select {
	case <-otherWake:
		t.Fatal("unrelated gateway was woken")
	default:
	}
}
