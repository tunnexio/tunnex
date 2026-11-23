package http

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// deviceAccessFacts is everything the device diagnostic reads, gathered before
// any check is written so the ordering below is a pure function of facts.
type deviceAccessFacts struct {
	deviceStatus  string
	deviceAddress string
	healthBlocked bool
	fullTunnel    bool

	gatewayName   string
	gatewayStatus string // "" when the home gateway row is gone
	gatewayFresh  bool

	destination string
	// k8sAPI is set when the destination is a cluster's Kubernetes API (K8N-3).
	k8sAPI *deviceAccessK8sAPI

	policyErr    error
	policy       policyspec.AccessEvaluation
	reach        nodes.GatewayReach
	health       *nodes.PolicyHealth
	policyReport bool
}

// deviceAccessK8sAPI is what the diagnostic knows about a destination that is a cluster's Kubernetes API.
type deviceAccessK8sAPI struct {
	cluster string
	name    string // the API's name in the tunnel
	enabled bool
	address string // the API's address; "" while API access is off

	// What the cluster's own gateway says about forwarding to the API server.
	gatewayAssigned bool
	gatewayName     string
	gatewayFresh    bool   // active and seen recently
	endpointState   string // "ready", a refusal reason, or "" when the gateway has not said
}

// k8sAPIAllowedNote is the fixed sentence returned when Tunnex allows a connection to a cluster's API.
// Tunnex decides the network path only; it holds no cluster credential and cannot see what the cluster
// answers.
const k8sAPIAllowedNote = "Tunnex allows the connection. The cluster still decides what you may do: a 401 or 403 from kubectl is the cluster's answer, not Tunnex's."

// k8sAPIEndpointCheck writes the endpoint check: whether the cluster's gateway can forward to the
// cluster's API server at all. It is the gateway's own report; nothing is probed.
func k8sAPIEndpointCheck(b *accessCheckBuilder, k deviceAccessK8sAPI) {
	facts := map[string]string{"cluster": k.cluster}
	if k.gatewayName != "" {
		facts["gateway"] = k.gatewayName
	}
	switch {
	case !k.gatewayAssigned:
		facts["reason"] = "no_gateway"
		b.add(api.AgentAccessCheckStatusFail, "k8s_api_endpoint_unavailable", "The cluster has no gateway assigned, so nothing forwards to its API server.", facts)
	case !k.gatewayFresh:
		b.add(api.AgentAccessCheckStatusInconclusive, "k8s_api_endpoint_not_observed", "The cluster's gateway is not active or has not been seen recently, so its path to the API server is not known.", facts)
	case k.endpointState == "":
		b.add(api.AgentAccessCheckStatusInconclusive, "k8s_api_endpoint_not_observed", "The cluster's gateway has not reported whether it can forward to the API server yet. A gateway older than this feature never reports it.", facts)
	case k.endpointState == nodes.K8sAPIEndpointReady:
		b.add(api.AgentAccessCheckStatusPass, "k8s_api_endpoint_ready", "The cluster's gateway forwards to the cluster's API server.", facts)
	case k.endpointState == nodes.K8sAPIEndpointOnGatewayNode:
		facts["reason"] = k.endpointState
		b.add(api.AgentAccessCheckStatusFail, "k8s_api_endpoint_unavailable", "The cluster's gateway runs on the cluster's only control-plane node and cannot forward to the API server on its own node. Run the gateway on a worker node.", facts)
	default:
		facts["reason"] = k.endpointState
		b.add(api.AgentAccessCheckStatusFail, "k8s_api_endpoint_unavailable", "The cluster's gateway cannot forward to the cluster's API server.", facts)
	}
}

// deviceAccessChecks writes the UIX-1 checks in their fixed order: device,
// posture, gateway, destination, route, rule, applied. A destination that is a
// cluster's Kubernetes API adds one more, endpoint (K8N-3).
func deviceAccessChecks(f deviceAccessFacts) accessCheckBuilder {
	b := accessCheckBuilder{}

	if f.deviceStatus == "active" && f.deviceAddress != "" {
		b.add(api.AgentAccessCheckStatusPass, "device_active", "Device is active and has a tunnel address.", map[string]string{"address": f.deviceAddress})
	} else {
		b.add(api.AgentAccessCheckStatusFail, "device_not_active", "Device is not active or has no tunnel address.", map[string]string{"status": f.deviceStatus})
	}

	if f.healthBlocked {
		b.add(api.AgentAccessCheckStatusFail, "posture_blocked", "Device is blocked by device posture.", nil)
	} else {
		b.add(api.AgentAccessCheckStatusPass, "posture_not_blocking", "Device posture is not blocking this device.", nil)
	}

	gatewayFacts := map[string]string{}
	if f.gatewayName != "" {
		gatewayFacts["gateway"] = f.gatewayName
	}
	if f.gatewayStatus != "" {
		gatewayFacts["status"] = f.gatewayStatus
	}
	if f.gatewayStatus == "active" && f.gatewayFresh {
		b.add(api.AgentAccessCheckStatusPass, "gateway_reporting", "Home gateway is active and was seen recently.", gatewayFacts)
	} else {
		b.add(api.AgentAccessCheckStatusFail, "gateway_not_reporting", "Home gateway is not active or has not been seen recently.", gatewayFacts)
	}

	dstIP, dstErr := netip.ParseAddr(f.destination)
	literal := dstErr == nil
	unresolved := !literal && f.policyErr == nil && len(f.policy.DestinationAnswers) == 0
	destinations := []netip.Addr{}
	apiAddress := netip.Addr{}
	if f.k8sAPI != nil && f.k8sAPI.enabled {
		// The API's name resolves to exactly one address, the one API access allocated. The policy was
		// evaluated against it, so the route and rule checks below read as for a literal address.
		apiAddress, _ = netip.ParseAddr(f.k8sAPI.address)
	}
	switch {
	case f.k8sAPI != nil && !f.k8sAPI.enabled:
		// API access is off: the name has no address and no rule can match it.
		literal, unresolved = false, f.policyErr == nil
		b.add(api.AgentAccessCheckStatusFail, "k8s_api_not_enabled", "API access is off for cluster "+f.k8sAPI.cluster+", so its Kubernetes API has no address in the tunnel. Turn on API access for the cluster.",
			map[string]string{"cluster": f.k8sAPI.cluster, "name": f.k8sAPI.name})
	case f.k8sAPI != nil && apiAddress.IsValid():
		literal, unresolved = true, false
		destinations = append(destinations, apiAddress)
		b.add(api.AgentAccessCheckStatusPass, "k8s_api_destination", "Destination is the Kubernetes API of cluster "+f.k8sAPI.cluster+".",
			map[string]string{"cluster": f.k8sAPI.cluster, "name": f.k8sAPI.name, "address": apiAddress.String()})
	case literal:
		destinations = append(destinations, dstIP)
		b.add(api.AgentAccessCheckStatusPass, "destination_ip", "Destination is a literal IP; DNS is not required.", map[string]string{"ip": dstIP.String()})
	case f.policyErr != nil:
		// Reported once below; a hostname cannot be resolved without the artifact.
	case unresolved:
		b.add(api.AgentAccessCheckStatusInconclusive, "device_dns_not_observed", "The compiled policy holds no answers for this hostname; enter its resolved IP to continue.", nil)
	default:
		for _, raw := range f.policy.DestinationAnswers {
			if answer, err := netip.ParseAddr(raw); err == nil {
				destinations = append(destinations, answer)
			}
		}
		b.add(api.AgentAccessCheckStatusPass, "fqdn_generation_active", "The compiled policy supplies the answers for this hostname.", map[string]string{"answers": strconv.Itoa(len(destinations))})
	}

	if f.policyErr != nil {
		// Routes and rules both come from the compiled artifact; without it
		// neither can be stated, so one check stands in for both.
		b.add(api.AgentAccessCheckStatusInconclusive, "compiled_policy_unavailable", "The compiled policy of the home gateway could not be evaluated.", nil)
	} else {
		if len(destinations) == 0 {
			b.add(api.AgentAccessCheckStatusInconclusive, "route_destination_unresolved", "The home gateway route cannot be evaluated without a destination address.", nil)
		} else {
			routeFacts := map[string]string{}
			covered := true
			for _, destination := range destinations {
				kind, prefix := f.reachFor(destination)
				if kind == "" {
					covered = false
					break
				}
				routeFacts[kind] = prefix
			}
			switch {
			case covered:
				b.add(api.AgentAccessCheckStatusPass, "route_configured", "The home gateway carries a route for this destination.", routeFacts)
			case f.fullTunnel:
				b.add(api.AgentAccessCheckStatusInconclusive, "route_not_configured", "The destination is outside the home gateway's networks; this full-tunnel device sends it to the home gateway's default route, which is not evaluated here.", nil)
			default:
				b.add(api.AgentAccessCheckStatusFail, "route_not_configured", "The home gateway has no route for this destination.", nil)
			}
		}

		// A hostname the artifact holds no answers for has no tuple to match;
		// the destination check above already says what is missing.
		if !unresolved {
			if f.policy.Allowed {
				code, message := "matching_grant", "The compiled policy permits this tuple."
				if f.policy.Mode == "off" {
					code, message = "policy_not_enforcing", "Zero Trust enforcement is off; the compiled mesh permits this tuple."
				}
				b.add(api.AgentAccessCheckStatusPass, code, message, policyFacts(f.policy))
			} else {
				message := "No active compiled grant permits this tuple."
				if f.k8sAPI != nil {
					message = "No rule lets this device reach the Kubernetes API of " + f.k8sAPI.cluster + "."
				}
				b.add(api.AgentAccessCheckStatusFail, "no_matching_grant", message, policyFacts(f.policy))
			}
		}
	}

	if f.policyErr == nil && f.policy.Mode == "off" {
		b.add(api.AgentAccessCheckStatusPass, "applied_policy_not_required", "Zero Trust enforcement is off; no applied enforcement hash is required.", nil)
	} else if f.health == nil || !f.health.PushKnown || !f.policyReport || f.health.AppliedHash == "" || f.health.PushedHash == "" {
		b.add(api.AgentAccessCheckStatusInconclusive, "applied_policy_not_observed", "Home gateway has not reported enough applied-policy evidence.", nil)
	} else if f.health.Degraded || f.health.AppliedHash != f.health.PushedHash {
		b.add(api.AgentAccessCheckStatusFail, "applied_policy_mismatch", "Home gateway applied policy does not agree with the current compiled policy.", map[string]string{"health": string(f.health.Kind)})
	} else {
		b.add(api.AgentAccessCheckStatusPass, "applied_policy_current", "Home gateway reports the current compiled policy in force.", map[string]string{"policy_hash": f.health.PushedHash})
	}
	if f.k8sAPI != nil && f.k8sAPI.enabled {
		k8sAPIEndpointCheck(&b, *f.k8sAPI)
	}
	return b
}

// reachFor names the part of the home gateway's reach that covers addr: the
// device pool, the gateway's own site subnets, or a compiled route.
func (f deviceAccessFacts) reachFor(addr netip.Addr) (kind, prefix string) {
	if f.reach.PoolCIDR != "" {
		if match := matchingPrefix([]string{f.reach.PoolCIDR}, addr); match != "" {
			return "device_pool", match
		}
	}
	if match := matchingPrefix(f.reach.LocalSubnets, addr); match != "" {
		return "gateway_site_subnet", match
	}
	if match := matchingPrefix(f.reach.Routes, addr); match != "" {
		return "gateway_route", match
	}
	return "", ""
}

func (s apiServer) TestDeviceAccess(ctx context.Context, req api.TestDeviceAccessRequestObject) (api.TestDeviceAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.nodes == nil || s.devices == nil {
		return nil, apierr.New(500, "device_diagnostic_unavailable", "device diagnostic services are unavailable")
	}
	dev, err := s.devices.Get(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	if dev.Kind == "agent" {
		// The agent diagnostic owns agent identities; the two never overlap.
		return nil, apierr.NotFound("device_not_found", "device not found")
	}

	destination := strings.TrimSpace(req.Params.Destination)
	protocol := string(req.Params.Protocol)
	if destination == "" || len(destination) > 253 || (protocol != "tcp" && protocol != "udp") || req.Params.Port < 1 || req.Params.Port > 65535 {
		return nil, apierr.New(400, "invalid_device_access_tuple", "destination, protocol, or port is invalid")
	}

	facts := deviceAccessFacts{deviceStatus: dev.Status, healthBlocked: dev.HealthBlocked, fullTunnel: dev.FullTunnel, destination: destination}
	if dev.AssignedIp != nil {
		facts.deviceAddress = *dev.AssignedIp
	}

	// K8N-3: a destination that is a cluster's Kubernetes API (its tunnel name, or the address of an API
	// whose access is on) is evaluated against that address and gets the endpoint check.
	evaluated := destination
	var apiDestination k8ssvc.APIDestination
	if s.k8s != nil {
		resolved, isAPI, err := s.k8s.ResolveAPIDestination(ctx, req.OrgId, destination)
		if err != nil {
			return nil, err
		}
		if isAPI {
			apiDestination = resolved
			facts.k8sAPI = &deviceAccessK8sAPI{cluster: resolved.ClusterName, name: resolved.FQDN, enabled: resolved.Enabled, address: resolved.VIP,
				gatewayAssigned: resolved.ConnectorNodeID != uuid.Nil}
			if resolved.Enabled {
				evaluated = resolved.VIP
			}
		}
	}

	nodeRows, nodeErr := s.nodes.ListNodes(ctx, req.OrgId)
	facts.policyErr = nodeErr
	if nodeErr == nil {
		var home *sqlc.Node
		for i := range nodeRows {
			if nodeRows[i].ID == dev.NodeID {
				home = &nodeRows[i]
				break
			}
		}
		if home == nil {
			facts.policyErr = errors.New("home gateway unavailable")
		} else {
			facts.gatewayName, facts.gatewayStatus = home.Name, home.Status
			// The same recency window the device and gateway lists use.
			facts.gatewayFresh = home.LastSeenAt.Valid && deviceOnline(&home.LastSeenAt.Time)
			facts.policyReport = home.PolicyReportedAt.Valid
			batch := s.nodes.LoadSiteTopoBatch(ctx, req.OrgId, nodeRows)
			health := s.nodes.PolicyHealthForNodes(ctx, req.OrgId, nodeRows, batch)[home.ID]
			facts.health = &health
			facts.policy, facts.reach, facts.policyErr = s.nodes.EvaluateDeviceAccess(ctx, req.OrgId, dev.ID, *home, facts.deviceAddress, evaluated, protocol, req.Params.Port, batch)
		}
		if facts.k8sAPI != nil && facts.k8sAPI.gatewayAssigned {
			facts.k8sAPI.gatewayAssigned = false // true again only if the node still exists
			for i := range nodeRows {
				if nodeRows[i].ID != apiDestination.ConnectorNodeID {
					continue
				}
				gateway := nodeRows[i]
				facts.k8sAPI.gatewayAssigned, facts.k8sAPI.gatewayName = true, gateway.Name
				facts.k8sAPI.gatewayFresh = gateway.Status == "active" && !gateway.RevokedAt.Valid && gateway.LastSeenAt.Valid && deviceOnline(&gateway.LastSeenAt.Time)
				facts.k8sAPI.endpointState = nodes.Capabilities(gateway.Capabilities).K8sAPIEndpoint
				break
			}
		}
	}

	b := deviceAccessChecks(facts)
	body := api.DeviceAccessDiagnostic{DeviceId: dev.ID, Destination: destination, Protocol: api.DeviceAccessDiagnosticProtocol(protocol), Port: req.Params.Port,
		Overall: api.DeviceAccessDiagnosticOverall(b.overall()), FirstBlocker: b.firstBlocker, Checks: b.checks}
	if facts.k8sAPI != nil && body.Overall == api.DeviceAccessDiagnosticOverallAllowed {
		note := k8sAPIAllowedNote
		body.Note = &note
	}
	return api.TestDeviceAccess200JSONResponse{Body: body, Headers: api.TestDeviceAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
