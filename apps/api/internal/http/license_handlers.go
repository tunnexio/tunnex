package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Licence install and read (S12.1 slice 6).
//
// ⛔ NO REBUILD, NO RESTART — that is the entire point of a runtime gate. The manager holds the parse in
// memory and every entitlement question re-reads it, so an installed key takes effect on the next request.
//
// ⚠ READING IS NOT OWNER-GATED. Any member may see which tier the deployment is on, because a user who
// hits a ceiling needs to understand why without having to ask an owner. INSTALLING is owner-only:
// `license:manage`, named per capability and deliberately not a reuse of `org:update` — an admin who can
// rename an org must not thereby change the commercial entitlement of the whole box.

func licenceStatusBody(st licence.Status, h licence.StoreHealth) api.LicenseStatus {
	feats := []string{}
	for _, f := range licence.AllFeatures() {
		if licence.Has(st.Tier, f) {
			feats = append(feats, string(f))
		}
	}
	body := api.LicenseStatus{
		State:              api.LicenseStatusState(stateName(st.State)),
		Tier:               api.LicenseStatusTier(st.Tier),
		Features:           feats,
		ClockWentBackwards: &st.ClockWentBackwards,
	}
	// ⛔ THE STORE'S HEALTH RIDES BESIDE THE ENTITLEMENT, NEVER INSTEAD OF IT. A deployment whose store is
	// unreachable is still entitled to whatever it last knew — reporting a fault in place of the tier
	// would be the downgrade this whole design exists to prevent, performed by the display layer.
	if h.Stale {
		body.StoreStale = &h.Stale
	}
	if h.Rejected != "" {
		r := api.LicenseStatusStoreRejected(h.Rejected)
		body.StoreRejected = &r
	}
	if h.Detail != "" {
		body.StoreDetail = &h.Detail
	}
	if c, _ := licence.GatewayCeilingFor(st.Tier); c != nil {
		body.GatewayCeiling = c
	}
	if c, _ := licence.OrgCeilingFor(st.Tier); c != nil {
		body.OrgCeiling = c
	}
	if !st.ExpiresAt.IsZero() {
		e := st.ExpiresAt
		body.ExpiresAt = &e
	}
	if !st.GraceEndsAt.IsZero() {
		g := st.GraceEndsAt
		body.GraceEndsAt = &g
	}
	return body
}

func stateName(s licence.State) string {
	switch s {
	case licence.StateValid:
		return "valid"
	case licence.StateExpired:
		return "expired"
	case licence.StateLapsed:
		return "lapsed"
	default:
		return "unlicensed"
	}
}

// GetLicense reports the current entitlement.
//
// ⛔ IT ALWAYS ANSWERS. An absent licence is COMMUNITY, not an error — a deployment with no key is a
// supported, complete deployment, and a 404 here would say otherwise.
func (s apiServer) GetLicense(ctx context.Context, req api.GetLicenseRequestObject) (api.GetLicenseResponseObject, error) {
	// ⚠ ANY MEMBER OF ANY ORGANIZATION MAY READ IT. The licence is deployment-wide, so there is no org to
	// scope the read to — and what it exposes (tier, ceilings, expiry) is what every gated refusal already
	// tells the caller. Reading it is not a privilege.
	if _, err := requireVerifiedUser(ctx); err != nil {
		return nil, err
	}
	st := s.licence.Evaluate(time.Now())
	body := licenceStatusBody(st, s.licence.StoreStatus())
	// ⛔ THE NUMERATOR MUST COME FROM THE SAME PLACE THE CEILING IS ENFORCED. The nav badge built its
	// fraction from the CURRENT ORG's gateway list over the DEPLOYMENT's ceiling — so a newly created
	// organization showed "0 / 5" while the deployment was full and the next enrolment was already
	// refused. Serving the enforced count here makes the two halves the same question.
	//
	// ⚠ A COUNT FAILURE LEAVES IT ABSENT RATHER THAN ZERO. Zero is a claim ("there is room"); absent is
	// the truth ("we could not count"), and the client renders the ceiling alone.
	if s.nodes != nil {
		if n, err := s.nodes.CountLiveGateways(ctx); err == nil {
			used := int(n)
			body.GatewaysInUse = &used
		}
	}
	return api.GetLicense200JSONResponse{
		Body:    body,
		Headers: api.GetLicense200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// InstallLicense verifies and installs a key.
//
// ⛔ A KEY THAT DOES NOT VERIFY IS REFUSED AND THE EXISTING ENTITLEMENT IS LEFT UNTOUCHED. A fat-fingered
// paste must never downgrade a working deployment — the manager enforces that, and the refusal says which
// half was wrong so an operator can act.
func (s apiServer) InstallLicense(ctx context.Context, req api.InstallLicenseRequestObject) (api.InstallLicenseResponseObject, error) {
	// ⛔ INSTALLING IS DEPLOYMENT-WIDE AND THERE IS NO DEPLOYMENT-ADMIN ROLE IN THIS PRODUCT. The closest
	// available authority is "owner of some organization on this deployment", which is what this requires.
	//
	// ⚠ RECORDED AS A KNOWN GAP, NOT PRESENTED AS A DESIGN: on a shared multi-tenant deployment — which
	// the org switcher just made real — an owner of ANY org can install a key that changes EVERY org's
	// ceilings. Per-org licensing cannot fix it (the data cannot hold it); a deployment-admin role could,
	// and does not exist. Surfaced for disposition rather than invented here.
	p, err := requireOwnerOfSomeOrg(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Key == "" {
		return nil, apierr.BadRequest("invalid_request", "a licence key is required")
	}

	// ⛔ `before` COMES BACK FROM THE WRITE, IT IS NOT READ AROUND IT.
	//
	// A before/after audit row is only true if the "before" was read while it was still true, and a handler
	// that reads it after persisting records `from: growth, to: growth` — a row that exists, parses, and
	// says nothing. Rather than pin that ordering with a test, the ordering was removed: the previous tier
	// is observable only inside Persist, so Persist returns it. There is nothing left to reorder.
	res, before, err := s.licence.Persist(ctx, licence.TrustedKeys, req.Body.Key)
	if err != nil {
		return nil, err
	}
	if !res.OK {
		// ⚠ THE REASON IS NAMED AND THE REMEDY DIFFERS PER REASON. "invalid" alone sends an operator
		// looking in the wrong place — a key for another deployment and a corrupted paste need opposite
		// actions.
		return nil, apierr.BadRequest("license_rejected", licenceRefusal(res.Reason))
	}

	st := s.licence.Evaluate(time.Now())
	// ⛔ AUDITED. Installing a licence changes what the whole deployment may do; it belongs in the record
	// beside org deletion. The KEY ITSELF IS NEVER LOGGED — the licence id and tier identify it without
	// putting a credential in an audit row.
	if e := s.orgs.RecordLicenseInstall(ctx, anyOrgOf(p), p.UserID, map[string]any{
		"license_id": res.Claims.ID,
		"from_tier":  string(before),
		"tier":       string(st.Tier),
		"band":       res.Claims.Band,
		"expires_at": res.Claims.ExpiresAt,
		"kid":        res.Claims.Kid,
	}); e != nil {
		return nil, e
	}

	return api.InstallLicense200JSONResponse{
		Body:    licenceStatusBody(st, s.licence.StoreStatus()),
		Headers: api.InstallLicense200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func licenceRefusal(r licence.Reason) string {
	switch r {
	case licence.ReasonUnknownVersion:
		return "This key was issued for a newer version of Tunnex. Upgrade, then install it again."
	case licence.ReasonUnknownKid:
		return "This key was not issued by this Tunnex. It may belong to another deployment, or it was " +
			"signed by a key this build no longer trusts."
	case licence.ReasonBadSignature:
		return "This key did not verify. It is most likely truncated — licence keys are one long line, " +
			"and some mail clients wrap them. Copy it again from the original email."
	default:
		return "This does not look like a Tunnex licence key. It should begin `tnxl_`."
	}
}

// requireOwnerOfSomeOrg is the closest thing this product has to a deployment administrator.
//
// ⛔ IT IS NOT ONE, AND THE DIFFERENCE MATTERS ON A SHARED DEPLOYMENT. `PermLicenseManage` is owner-only
// WITHIN an org; ownership of one org is not authority over the box. Recorded at the seam so the gap is
// met by whoever next reads this, rather than discovered by a customer.
func requireOwnerOfSomeOrg(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	for _, role := range p.Roles {
		if rbac.Can(role, rbac.PermLicenseManage) {
			return p, nil
		}
	}
	return nil, apierr.New(http.StatusForbidden, "forbidden",
		"installing a licence requires being an owner of an organization on this deployment")
}

// anyOrgOf picks a stable org for the audit row. ⚠ The EVENT is deployment-wide; audit_logs is org-scoped,
// so it has to land somewhere. Deterministic (lowest id) so repeated installs by the same actor thread
// onto one org's timeline rather than scattering.
func anyOrgOf(p *authctx.Principal) uuid.UUID {
	var pick uuid.UUID
	for id := range p.Roles {
		if pick == uuid.Nil || id.String() < pick.String() {
			pick = id
		}
	}
	return pick
}
