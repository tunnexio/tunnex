package http

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// S8.1 site-to-site handlers (EPIC 8). All are site:manage-gated (owner/admin) — site registration,
// binding, subnet advertisement, and approval are network-shaping powers. The sites service is CORE
// (all editions, D11); Zero-Trust governance of the resulting site traffic is enterprise (Slice 3).

func toAPISite(s sqlc.Site) api.Site {
	var mtu *int
	if s.LinkMtu != nil {
		v := int(*s.LinkMtu)
		mtu = &v
	}
	return api.Site{Id: s.ID, Name: s.Name, LinkTransport: api.SiteLinkTransport(s.LinkTransport), LinkMtu: mtu, CreatedAt: s.CreatedAt}
}

func (s apiServer) ListSites(ctx context.Context, req api.ListSitesRequestObject) (api.ListSitesResponseObject, error) {
	// S8.3 D5: a MEMBER reads the topology their traffic traverses (org:view — the same member-read gate as
	// ListNodes/ListDevices/Overview). Mutations + getSiteReferences + the pending queue stay site:manage.
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	list, err := s.sites.ListSites(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Site, len(list))
	for i, x := range list {
		out[i] = toAPISite(x)
	}
	return api.ListSites200JSONResponse{Body: out, Headers: api.ListSites200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ListRoutedRanges GET /organizations/{orgId}/routed-ranges — the org's declared routed LAN ranges for
// split-tunnel device AllowedIPs (S8.5). SAME auth class as the revocation poll: a member (org:view) of
// THIS org. The org-scoped authorize IS the cross-org guard — a device (its user's bearer) in org A can
// never fetch org B's ranges (authorize 403s a non-member). Ranges-ONLY; approved-only; sorted/canonical;
// empty is a first-class answer.
func (s apiServer) ListRoutedRanges(ctx context.Context, req api.ListRoutedRangesRequestObject) (api.ListRoutedRangesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	ranges, err := s.sites.ListRoutedRanges(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	// GATED forwards: only those whose resolver is reachable via `ranges` (S8.5 Slice 3, D4). Same poll,
	// same body — ranges + forwards ride together; the client applies set_allowed_ips + set_resolvers.
	fwds, err := s.sites.ListRoutedForwards(ctx, req.OrgId, ranges)
	if err != nil {
		return nil, err
	}
	apiFwds := make([]api.DNSForward, 0, len(fwds))
	for _, f := range fwds {
		apiFwds = append(apiFwds, api.DNSForward{Domain: f.Domain, ResolverIp: f.ResolverIP})
	}
	body := api.RoutedRanges{Ranges: ranges, Forwards: apiFwds}
	// WF-A D-WFA-6: when a device_id is passed, ALSO carry that device's dial (endpoint + gateway pubkey)
	// derived from the ACTIVE HUB, so a running device re-homes on promotion via THIS poll. DeviceDial does
	// the cross-org (org-scoped GetDevice) + cross-device (owner) guard — a device fetches only its OWN dial.
	// nil dial (device's node not a hub-set member) leaves the fields NULL → the client keeps its baked
	// endpoint (the deferred spoke-device case). The dial carries NO device-identity material (channel contract).
	if req.Params.DeviceId != nil {
		p, _ := authctx.PrincipalFrom(ctx)
		ep, pk, derived, derr := s.nodes.DeviceDial(ctx, req.OrgId, *req.Params.DeviceId, p.UserID)
		if derr != nil {
			return nil, derr
		}
		if derived {
			body.DialEndpoint = &ep
			body.DialPubkey = &pk
		}
	}
	return api.ListRoutedRanges200JSONResponse{
		Body:    body,
		Headers: api.ListRoutedRanges200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// RouteLAN POST /organizations/{orgId}/routed-lans — the S8.5 D1 one-screen affordance: route a LAN
// through a gateway in one call (register-site + bind + advertise + approve, byte-identical to the long
// path). site:manage (all-editions core, D11). A range collision returns the typed refusal (site+bind+
// pending persist). name is optional.
func (s apiServer) RouteLAN(ctx context.Context, req api.RouteLANRequestObject) (api.RouteLANResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "node_id + cidr are required")
	}
	cidr, err := netip.ParsePrefix(req.Body.Cidr)
	if err != nil || !cidr.Addr().Is4() {
		return nil, apierr.BadRequest("invalid_cidr", "cidr must be a valid IPv4 CIDR")
	}
	name := ""
	if req.Body.Name != nil {
		name = *req.Body.Name
	}
	p, _ := authctx.PrincipalFrom(ctx)
	site, _, err := s.sites.RouteLAN(ctx, p.UserID, req.OrgId, req.Body.NodeId, name, cidr)
	if err != nil {
		return nil, err
	}
	return api.RouteLAN201JSONResponse{Body: toAPISite(site), Headers: api.RouteLAN201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) RegisterSite(ctx context.Context, req api.RegisterSiteRequestObject) (api.RegisterSiteResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" {
		return nil, apierr.BadRequest("name_required", "a site name is required")
	}
	site, err := s.sites.RegisterSite(ctx, req.OrgId, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return api.RegisterSite201JSONResponse{Body: toAPISite(site), Headers: api.RegisterSite201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) AddSiteSubnet(ctx context.Context, req api.AddSiteSubnetRequestObject) (api.AddSiteSubnetResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	cidr, err := netip.ParsePrefix(req.Body.Cidr)
	if err != nil || !cidr.Addr().Is4() {
		return nil, apierr.BadRequest("invalid_cidr", "cidr must be a valid IPv4 CIDR")
	}
	sub, err := s.sites.AddSubnet(ctx, req.OrgId, req.SiteId, cidr)
	if err != nil {
		return nil, err
	}
	return api.AddSiteSubnet201JSONResponse{
		Body:    api.SiteSubnet{Id: sub.ID, SiteId: sub.SiteID, Cidr: sub.Cidr.String(), Status: api.SiteSubnetStatus(sub.Status)},
		Headers: api.AddSiteSubnet201ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

func (s apiServer) BindSiteNode(ctx context.Context, req api.BindSiteNodeRequestObject) (api.BindSiteNodeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.sites.BindNode(ctx, req.OrgId, req.SiteId, req.Body.NodeId); err != nil {
		return nil, err
	}
	// S8.6: binding a gateway changes hub-set membership → re-elect + persist (the D5 generation bumps).
	// Best-effort: a reconcile hiccup must not fail the bind (the set self-heals on the next reconcile).
	if _, err := s.nodes.ReconcileHubSet(ctx, req.OrgId); err != nil {
		slog.WarnContext(ctx, "hub_set_reconcile_failed", "op", "bind", "org_id", req.OrgId.String(), "error", err.Error())
	}
	return api.BindSiteNode204Response{}, nil
}

// UnbindSiteNode detaches the site's gateway (D6 replace-node = unbind then bind a new node).
func (s apiServer) UnbindSiteNode(ctx context.Context, req api.UnbindSiteNodeRequestObject) (api.UnbindSiteNodeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	// S8.6 #6 compat: the body is OPTIONAL (spec: UnbindSiteNodeRequest, node_id optional; a bodyless
	// legacy request is shimmed to {} at the router). With a node_id, unbind that gateway (the #3
	// explicit-id path); without one, UnbindSiteNode resolves the site's sole gateway (uuid.Nil).
	var nodeID uuid.UUID
	if req.Body != nil && req.Body.NodeId != nil {
		nodeID = *req.Body.NodeId
	}
	if err := s.sites.UnbindSiteNode(ctx, req.OrgId, req.SiteId, nodeID); err != nil {
		return nil, err
	}
	// S8.6: unbinding removes a gateway from the hub-set candidate pool → re-elect + persist (best-effort).
	if _, err := s.nodes.ReconcileHubSet(ctx, req.OrgId); err != nil {
		slog.WarnContext(ctx, "hub_set_reconcile_failed", "op", "unbind", "org_id", req.OrgId.String(), "error", err.Error())
	}
	return api.UnbindSiteNode204Response{}, nil
}

func (s apiServer) ListSiteSubnets(ctx context.Context, req api.ListSiteSubnetsRequestObject) (api.ListSiteSubnetsResponseObject, error) {
	// S8.3 D5: member-readable (org:view) — part of the read-only topology; approval/advertise stay site:manage.
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	list, err := s.sites.ListSubnets(ctx, req.OrgId, req.SiteId)
	if err != nil {
		return nil, err
	}
	out := make([]api.SiteSubnet, len(list))
	for i, x := range list {
		out[i] = api.SiteSubnet{Id: x.ID, SiteId: x.SiteID, Cidr: x.Cidr.String(), Status: api.SiteSubnetStatus(x.Status)}
	}
	return api.ListSiteSubnets200JSONResponse{Body: out, Headers: api.ListSiteSubnets200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListPendingSiteSubnets(ctx context.Context, req api.ListPendingSiteSubnetsRequestObject) (api.ListPendingSiteSubnetsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	list, err := s.sites.ListPendingSubnets(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.SiteSubnet, len(list))
	for i, x := range list {
		out[i] = api.SiteSubnet{Id: x.ID, SiteId: x.SiteID, Cidr: x.Cidr.String(), Status: api.SiteSubnetStatus(x.Status)}
	}
	return api.ListPendingSiteSubnets200JSONResponse{Body: out, Headers: api.ListPendingSiteSubnets200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ApproveSiteSubnet(ctx context.Context, req api.ApproveSiteSubnetRequestObject) (api.ApproveSiteSubnetResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.sites.ApproveSubnet(ctx, p.UserID, req.OrgId, req.SubnetId); err != nil {
		return nil, err
	}
	return api.ApproveSiteSubnet204Response{}, nil
}

// ListSiteDNSForwards GET /sites/{siteId}/dns-forwards — the site's cross-site DNS zones (S8.4; site:manage, core).
func (s apiServer) ListSiteDNSForwards(ctx context.Context, req api.ListSiteDNSForwardsRequestObject) (api.ListSiteDNSForwardsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	fwds, err := s.sites.ListDNSForwards(ctx, req.OrgId, req.SiteId)
	if err != nil {
		return nil, err
	}
	body := make([]api.DNSForward, 0, len(fwds))
	for _, f := range fwds {
		body = append(body, api.DNSForward{Domain: f.Domain, ResolverIp: f.ResolverIP})
	}
	return api.ListSiteDNSForwards200JSONResponse{Body: body, Headers: api.ListSiteDNSForwards200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// SetSiteDNSForward POST /sites/{siteId}/dns-forwards — add/update a forwarded zone (S8.4; site:manage, core).
func (s apiServer) SetSiteDNSForward(ctx context.Context, req api.SetSiteDNSForwardRequestObject) (api.SetSiteDNSForwardResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_body", "domain + resolver_ip required")
	}
	if err := s.sites.SetDNSForward(ctx, p.UserID, req.OrgId, req.SiteId, req.Body.Domain, req.Body.ResolverIp); err != nil {
		return nil, err
	}
	return api.SetSiteDNSForward204Response{}, nil
}

// RemoveSiteDNSForward DELETE /sites/{siteId}/dns-forwards/{domain} — full-sweep withdraw (S8.4; site:manage, core).
func (s apiServer) RemoveSiteDNSForward(ctx context.Context, req api.RemoveSiteDNSForwardRequestObject) (api.RemoveSiteDNSForwardResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.sites.RemoveDNSForward(ctx, p.UserID, req.OrgId, req.SiteId, req.Domain); err != nil {
		return nil, err
	}
	return api.RemoveSiteDNSForward204Response{}, nil
}

// RemoveSiteSubnet DELETE /site-subnets/{subnetId} — un-advertise / remove a subnet (WF-5). All-editions
// core like the rest of the site model (authorize FIRST, no edition gate); route withdrawn full-sweep.
func (s apiServer) RemoveSiteSubnet(ctx context.Context, req api.RemoveSiteSubnetRequestObject) (api.RemoveSiteSubnetResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.sites.RemoveSubnet(ctx, p.UserID, req.OrgId, req.SubnetId); err != nil {
		return nil, err
	}
	return api.RemoveSiteSubnet204Response{}, nil
}

// GetSiteReferences GET /sites/{siteId} — the D1 reverse link + D4 cascade preview counts.
func (s apiServer) GetSiteReferences(ctx context.Context, req api.GetSiteReferencesRequestObject) (api.GetSiteReferencesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	refs, err := s.sites.GetReferences(ctx, req.OrgId, req.SiteId)
	if err != nil {
		return nil, err
	}
	return api.GetSiteReferences200JSONResponse{
		Body:    api.SiteReferences{RuleCount: int(refs.RuleCount), SubnetCount: int(refs.SubnetCount)},
		Headers: api.GetSiteReferences200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// DeleteSite DELETE /sites/{siteId} — cascades subnets + site-referencing rules; unbinds the gateway (D4).
func (s apiServer) DeleteSite(ctx context.Context, req api.DeleteSiteRequestObject) (api.DeleteSiteResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.sites.DeleteSite(ctx, p.UserID, req.OrgId, req.SiteId); err != nil {
		return nil, err
	}
	return api.DeleteSite204Response{}, nil
}

// SetHubPriority PUT /organizations/{orgId}/nodes/{nodeId}/hub-priority — pin (or clear) a gateway's HA hub
// priority (S8.6 D1). site:manage (topology-consequential — pinning creates the HA hub set). Audited
// old→new in the service. Cross-org node id → 404.
func (s apiServer) SetHubPriority(ctx context.Context, req api.SetHubPriorityRequestObject) (api.SetHubPriorityResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermSiteManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	var pri *int32
	if req.Body.Priority != nil {
		v := int32(*req.Body.Priority)
		pri = &v
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.nodes.SetHubPriority(ctx, p.UserID, req.OrgId, req.NodeId, pri); err != nil {
		return nil, err
	}
	return api.SetHubPriority204Response{Headers: api.SetHubPriority204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// GetHubSet GET /organizations/{orgId}/hub-set — the org's persisted active hub set + per-member L1 metrics
// (S8.6 Slice 6). org:view — MEMBER-readable (the D5/S8.3 read-only-topology precedent); the pin control is
// site:manage. ONE truth — the same persisted org_hub_set the compiler + health read.
func (s apiServer) GetHubSet(ctx context.Context, req api.GetHubSetRequestObject) (api.GetHubSetResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	view, err := s.nodes.GetHubSetView(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	members := make([]api.HubMember, 0, len(view.Members))
	for _, m := range view.Members {
		hm := api.HubMember{NodeId: m.NodeID, Role: api.HubMemberRole(m.Role)}
		if m.HubPriority != nil {
			v := int(*m.HubPriority)
			hm.HubPriority = &v
		}
		if m.Metrics != nil { // absent metrics stay absent (not-reporting ≠ idle-with-zeroes)
			hm.Metrics = &api.HubMemberMetrics{LastHandshakeAt: m.Metrics.LastHandshakeAt, RxBytes: m.Metrics.RxBytes, TxBytes: m.Metrics.TxBytes}
		}
		members = append(members, hm)
	}
	return api.GetHubSet200JSONResponse{
		Body:    api.HubSet{Generation: view.Generation, Members: members},
		Headers: api.GetHubSet200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}
