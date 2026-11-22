package http

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
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

	policyErr    error
	policy       policyspec.AccessEvaluation
	reach        nodes.GatewayReach
	health       *nodes.PolicyHealth
	policyReport bool
}

// deviceAccessChecks writes the UIX-1 checks in their fixed order: device,
// posture, gateway, destination, route, rule, applied.
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
	switch {
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
				b.add(api.AgentAccessCheckStatusFail, "no_matching_grant", "No active compiled grant permits this tuple.", policyFacts(f.policy))
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
			facts.policy, facts.reach, facts.policyErr = s.nodes.EvaluateDeviceAccess(ctx, req.OrgId, dev.ID, *home, facts.deviceAddress, destination, protocol, req.Params.Port, batch)
		}
	}

	b := deviceAccessChecks(facts)
	body := api.DeviceAccessDiagnostic{DeviceId: dev.ID, Destination: destination, Protocol: api.DeviceAccessDiagnosticProtocol(protocol), Port: req.Params.Port,
		Overall: api.DeviceAccessDiagnosticOverall(b.overall()), FirstBlocker: b.firstBlocker, Checks: b.checks}
	return api.TestDeviceAccess200JSONResponse{Body: body, Headers: api.TestDeviceAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
