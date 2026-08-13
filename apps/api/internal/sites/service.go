// Package sites is the S8.1 site/gateway model service (EPIC 8). A SITE is a first-class org
// ENTITY that OWNS a gateway node (D6) — replacing the node preserves the site's identity, subnets,
// and future advertisements. This layer is CORE (all editions, D11): the model + routing are
// plumbing like the IP allocator; Zero-Trust GOVERNANCE of site traffic (enforcing gates a site
// subnet) is the enterprise half, landing in Slice 3.
package sites

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetguard"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetsrc"
)

type Service struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: sqlc.New(pool)} }

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// auditTarget writes one append-only audit row for a given target type/id. It RETURNS its error (never
// swallows): swallowing an InsertAuditLog failure inside a tx poisons the tx and surfaces later as a
// mystery commit-rollback (the swallowed-audit law). audit() + auditSite() are thin target-typed wrappers.
func (s *Service) auditTarget(ctx context.Context, q *sqlc.Queries, orgID, actor uuid.UUID, targetType, targetID, action string, meta map[string]any) error {
	b, _ := json.Marshal(meta)
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorUserID: pgtype.UUID{Bytes: actor, Valid: true},
		Action:      action,
		TargetType:  strptr(targetType),
		TargetID:    strptr(targetID),
		Metadata:    b,
	})
	return err
}

// audit writes a site_subnet-targeted audit row (subnet advertisement/approval events).
func (s *Service) audit(ctx context.Context, q *sqlc.Queries, orgID, actor, subnetID uuid.UUID, action string, meta map[string]any) error {
	return s.auditTarget(ctx, q, orgID, actor, "site_subnet", subnetID.String(), action, meta)
}

func strptr(s string) *string { return &s }

// RegisterSite creates a site entity in the org. A duplicate name in the org is a 409.
func (s *Service) RegisterSite(ctx context.Context, orgID uuid.UUID, name string) (sqlc.Site, error) {
	site, err := s.q.CreateSite(ctx, sqlc.CreateSiteParams{OrgID: orgID, Name: name})
	if pgerr.IsUnique(err) {
		return sqlc.Site{}, apierr.Conflict("site_name_taken", "a site with that name already exists in this organization")
	}
	return site, err
}

// ListSites returns the org's sites.
func (s *Service) ListSites(ctx context.Context, orgID uuid.UUID) ([]sqlc.Site, error) {
	return s.q.ListSitesByOrg(ctx, orgID)
}

// GetSite fetches one org-scoped site (404 when absent / cross-org).
func (s *Service) GetSite(ctx context.Context, orgID, siteID uuid.UUID) (sqlc.Site, error) {
	site, err := s.q.GetSite(ctx, sqlc.GetSiteParams{ID: siteID, OrgID: orgID})
	if err != nil {
		return sqlc.Site{}, apierr.NotFound("site_not_found", "no such site in this organization")
	}
	return site, nil
}

// AddSubnet attaches a routed subnet to a site (org-checked). Advertisement approval + pool
// disjointness are Slice 4 — this is the model. A duplicate (site, cidr) is a 409.
func (s *Service) AddSubnet(ctx context.Context, orgID, siteID uuid.UUID, cidr netip.Prefix) (sqlc.SiteSubnet, error) {
	if _, err := s.GetSite(ctx, orgID, siteID); err != nil {
		return sqlc.SiteSubnet{}, err
	}
	sub, err := s.q.AddSiteSubnet(ctx, sqlc.AddSiteSubnetParams{SiteID: siteID, Cidr: cidr.Masked()})
	if pgerr.IsUnique(err) {
		return sqlc.SiteSubnet{}, apierr.Conflict("subnet_exists", "that subnet is already on the site")
	}
	return sub, err
}

// ListSubnets returns a site's routed subnets (org-checked).
func (s *Service) ListSubnets(ctx context.Context, orgID, siteID uuid.UUID) ([]sqlc.SiteSubnet, error) {
	if _, err := s.GetSite(ctx, orgID, siteID); err != nil {
		return nil, err
	}
	return s.q.ListSiteSubnets(ctx, siteID)
}

// BindNode binds a gateway node to a site (single-node v1). Cross-org bind or unknown node -> 404;
// binding to an already-occupied site -> 409 (the single-node partial unique index). The node's
// bytes are copied into a pgtype.UUID because nodes.site_id is nullable.
//
// S8.5 #2: REFUSE to silently re-home a gateway already bound to ANOTHER site (`node_already_bound_to_site`)
// — an unconditional UPDATE would strand the prior site with no gateway (the RouteLAN retry orphan). A bind
// to the SAME site is an idempotent no-op (RouteLAN's resume path relies on it).
func (s *Service) BindNode(ctx context.Context, orgID, siteID, nodeID uuid.UUID) error {
	cur, err := s.q.GetNodeSiteBinding(ctx, sqlc.GetNodeSiteBindingParams{ID: nodeID, OrgID: orgID})
	if err == pgx.ErrNoRows {
		return apierr.NotFound("node_or_site_not_found", "no such node in this organization, or the site is not in this organization")
	}
	if err != nil {
		return err
	}
	if cur.Valid {
		if cur.Bytes == siteID {
			return nil // already bound to THIS site — idempotent no-op (resume-safe)
		}
		return apierr.Conflict("node_already_bound_to_site", "this gateway is already bound to another site; unbind it first")
	}
	// Unbound at read time → ATOMIC claim. The `site_id IS NULL` predicate in BindNodeToSite is the real
	// guard: under a concurrent bind, only one UPDATE matches, so the read above can never be raced into a
	// silent re-home. On 0 rows we lost the race (or the site is missing) → re-read to classify.
	n, err := s.q.BindNodeToSite(ctx, sqlc.BindNodeToSiteParams{
		ID: nodeID, OrgID: orgID, SiteID: pgtype.UUID{Bytes: siteID, Valid: true},
	})
	if pgerr.IsUnique(err) {
		return apierr.Conflict("site_has_gateway", "this site already has a gateway (single-node v1); unbind it first")
	}
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	// 0 rows: a concurrent bind claimed the gateway first, or the site does not exist. Re-read to emit the
	// right typed error — NEVER an orphaning silent success.
	cur2, err := s.q.GetNodeSiteBinding(ctx, sqlc.GetNodeSiteBindingParams{ID: nodeID, OrgID: orgID})
	if err != nil {
		if err == pgx.ErrNoRows {
			return apierr.NotFound("node_or_site_not_found", "no such node in this organization, or the site is not in this organization")
		}
		return err
	}
	if cur2.Valid {
		if cur2.Bytes == siteID {
			return nil // the racer bound us to THIS same site → idempotent no-op
		}
		return apierr.Conflict("node_already_bound_to_site", "this gateway is already bound to another site; unbind it first")
	}
	// Still unbound → the claim's EXISTS(site) clause failed: the site is not in this org.
	return apierr.NotFound("node_or_site_not_found", "no such node in this organization, or the site is not in this organization")
}

// UnbindNode detaches a node from its site — the SITE entity survives (the point of D6:
// replace-node is unbind-old + bind-new; site identity + subnets are untouched).
func (s *Service) UnbindNode(ctx context.Context, orgID, nodeID uuid.UUID) error {
	n, err := s.q.UnbindNode(ctx, sqlc.UnbindNodeParams{ID: nodeID, OrgID: orgID})
	if err != nil {
		return err
	}
	if n == 0 {
		return apierr.NotFound("node_not_found", "no such node in this organization")
	}
	return nil
}

// UnbindSiteNode detaches a gateway node from the site (D6 replace-node = unbind-old then bind-new). S8.6 #3:
// with an explicit nodeID the caller names WHICH node — post the single-node lift a site may hold several
// gateways, so an arbitrary pick could unbind the wrong one. S8.6 #6 compat: a nil nodeID (the legacy
// bodyless DELETE shape) resolves to the site's SOLE gateway; a multi-gateway site then requires an explicit
// id (409). The exact scoped UPDATE (id + org + site) unbinds only the named node; 0 rows → a deterministic
// 404.
func (s *Service) UnbindSiteNode(ctx context.Context, orgID, siteID, nodeID uuid.UUID) error {
	if _, err := s.GetSite(ctx, orgID, siteID); err != nil { // org-check the site
		return err
	}
	if nodeID == uuid.Nil { // bodyless legacy caller (#6): unbind the site's sole gateway, deterministically
		ids, err := s.q.ListNodeIDsForSite(ctx, sqlc.ListNodeIDsForSiteParams{
			SiteID: pgtype.UUID{Bytes: siteID, Valid: true}, OrgID: orgID,
		})
		if err != nil {
			return err
		}
		switch len(ids) {
		case 0:
			return apierr.NotFound("site_no_gateway", "this site has no bound gateway to unbind")
		case 1:
			nodeID = ids[0]
		default:
			return apierr.Conflict("multiple_gateways", "this site has multiple gateways; specify node_id")
		}
	}
	n, err := s.q.UnbindNodeFromSite(ctx, sqlc.UnbindNodeFromSiteParams{
		NodeID: nodeID, OrgID: orgID, SiteID: pgtype.UUID{Bytes: siteID, Valid: true},
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return apierr.NotFound("node_not_bound_to_site", "no such gateway bound to this site in this organization")
	}
	return nil
}

// SiteReferences is what points at a site: the counts the UI shows BEFORE a delete (D4 cascade preview)
// and on the site page's reverse link (D1). A rule is referenced if it names the site as src OR dst.
type SiteReferences struct {
	RuleCount   int64
	SubnetCount int64
}

// GetReferences returns the rule + subnet counts referencing a site (org-checked). ONE read serves both
// the D1 reverse link and the D4 cascade preview.
func (s *Service) GetReferences(ctx context.Context, orgID, siteID uuid.UUID) (SiteReferences, error) {
	if _, err := s.GetSite(ctx, orgID, siteID); err != nil {
		return SiteReferences{}, err
	}
	rules, err := s.q.CountPolicyRulesReferencingSite(ctx, sqlc.CountPolicyRulesReferencingSiteParams{
		OrgID: orgID, DstSiteID: pgtype.UUID{Bytes: siteID, Valid: true},
	})
	if err != nil {
		return SiteReferences{}, err
	}
	subs, err := s.q.ListSiteSubnets(ctx, siteID)
	if err != nil {
		return SiteReferences{}, err
	}
	return SiteReferences{RuleCount: rules, SubnetCount: int64(len(subs))}, nil
}

// DeleteSite deletes a site and cascades its subnets + site-referencing policy rules (ON DELETE CASCADE);
// the bound gateway is unbound (nodes.site_id -> NULL via the FK). Org-checked (404 cross-org/absent). The
// delete + its audit share ONE tx (a swallowed audit poisons the tx — the swallowed-audit law); the audit
// records the real cascade counts computed before the delete, never "may affect".
func (s *Service) DeleteSite(ctx context.Context, actor, orgID, siteID uuid.UUID) error {
	// GetReferences org-checks the site (its own GetSite) and returns the real cascade counts for the audit
	// — so no separate top-level GetSite (review #4: it was a redundant duplicate query).
	refs, err := s.GetReferences(ctx, orgID, siteID)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		n, err := q.DeleteSite(ctx, sqlc.DeleteSiteParams{ID: siteID, OrgID: orgID})
		if err != nil {
			return err
		}
		if n == 0 {
			return apierr.NotFound("site_not_found", "no such site in this organization")
		}
		return s.auditSite(ctx, q, orgID, actor, siteID, "site.deleted", map[string]any{
			"rules_deleted": refs.RuleCount, "subnets_released": refs.SubnetCount,
		})
	})
}

// auditSite writes a site-targeted audit row. Returns its error — swallowing it inside the delete tx
// would poison the commit (swallowed-audit law); auditTarget preserves that.
func (s *Service) auditSite(ctx context.Context, q *sqlc.Queries, orgID, actor, siteID uuid.UUID, action string, meta map[string]any) error {
	return s.auditTarget(ctx, q, orgID, actor, "site", siteID.String(), action, meta)
}

// ListPendingSubnets returns the org's advertised-but-unapproved subnets (the admin review queue).
func (s *Service) ListPendingSubnets(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListPendingSiteSubnetsForOrgRow, error) {
	return s.q.ListPendingSiteSubnetsForOrg(ctx, orgID)
}

// ApproveSubnet approves an advertised (pending) site subnet after the ONE disjointness validator
// (D5/D7): it must be disjoint from the org's OTHER approved site subnets, the device pool CIDR, and
// reserved ranges. On refusal it stays pending and the refusal is AUDITED (outcome-not-error — the
// audit must survive the failed approval, so it is written OUTSIDE the approve tx, S7.5.5 law). On
// success the approval is audited in-tx. Idempotent: approving an already-approved subnet is a no-op.
// (v1 reserved ranges = none — a seam; the validator already takes the third input.)
func (s *Service) ApproveSubnet(ctx context.Context, actor, orgID, subnetID uuid.UUID) error {
	var refusal *subnetguard.Overlap
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		sub, e := q.GetSiteSubnetForOrg(ctx, sqlc.GetSiteSubnetForOrgParams{ID: subnetID, OrgID: orgID})
		if e != nil {
			if e == pgx.ErrNoRows {
				return apierr.NotFound("subnet_not_found", "no such site subnet in this organization")
			}
			return e
		}
		if sub.Status == "approved" {
			return nil // idempotent no-op
		}
		// M6: serialize the disjointness read against every other range-writing seam (ResizePool +
		// k8s.RegisterCluster) with the SAME org advisory lock. Without it, a subnet-approval racing a
		// cluster registration (or a pool resize) could both pass the READ-COMMITTED check on a set that
		// excludes the other's uncommitted range, committing an overlap the unique index can't catch.
		if e := q.LockDeviceKey(ctx, orgID.String()); e != nil {
			return e
		}
		// The candidate must be disjoint from the org's approved subnets + the pool. The candidate is
		// PENDING, so it is NOT in the approved-only list — pass the WHOLE approved set to the validator.
		// (A prior `a.Cidr != sub.Cidr` filter here was a BYPASS wearing a convenience costume: it
		// exempted the exact-duplicate-CIDR collision — the ONE class the org-wide check most needs,
		// since site_subnets uniqueness is per-SITE, not per-org, so two sites CAN advertise the same
		// CIDR. Its stated purpose — exclude the candidate from its own list — was already satisfied
		// structurally. See the validator-input-filtering law in docs/S8.1-decisions.md.)
		// The whole input set (approved subnets + pool + the org's cluster VIP ranges) is assembled by the
		// shared collector — S10.3 F2: a new range class joins EVERY seam, and no caller can silently omit
		// one. The candidate is PENDING, so it is not in the approved-only list (no self-collision needed).
		ranges, e := subnetguard.Collect(ctx, subnetsrc.Source{Q: q}, orgID)
		if e != nil {
			return e
		}
		if ov, ok := subnetguard.Check(sub.Cidr, ranges); !ok {
			refusal = &ov // signal refusal; the tx COMMITS as a no-op, the audit + error happen OUTSIDE
			return nil
		}
		if _, e := q.ApproveSiteSubnet(ctx, subnetID); e != nil {
			return e
		}
		if e := s.audit(ctx, q, orgID, actor, subnetID, "site.subnet_approved", map[string]any{"cidr": sub.Cidr.String()}); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}
	if refusal != nil {
		// AUDIT the refusal in its own committed op (it must survive the refusal), then return typed.
		_ = s.audit(ctx, s.q, orgID, actor, subnetID, "site.subnet_approval_refused",
			map[string]any{"overlap_class": string(refusal.Class), "overlaps": refusal.With.String()})
		// S8.5 rider — teaching text on the ONE validator's refusal (rendered verbatim per convention): the
		// solo-admin who hits a range collision on the one-screen affordance gets a next step, not a dead end.
		return apierr.Conflict("subnet_not_disjoint",
			"this subnet overlaps the "+string(refusal.Class)+" range "+refusal.With.String()+"; approval refused. "+
				"Both sides use overlapping addresses — options: renumber one LAN to a non-overlapping range, or subnet-mapping (roadmap).")
	}
	return nil
}

// RemoveSubnet un-advertises a site subnet (WF-5). Correcting a mis-advertised subnet no longer needs a
// whole-site delete. A pending subnet just vanishes; an APPROVED subnet's route is withdrawn from every
// gateway on the next reconcile (finalizeArtifact drops it from the topology's approved set — the standard
// full-sweep, the same path DeleteSite relies on). Audited in-tx (swallowed-audit law: the audit error
// propagates, so a mystery commit-rollback can't hide a removal).
func (s *Service) RemoveSubnet(ctx context.Context, actor, orgID, subnetID uuid.UUID) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		sub, e := q.GetSiteSubnetForOrg(ctx, sqlc.GetSiteSubnetForOrgParams{ID: subnetID, OrgID: orgID})
		if e != nil {
			if e == pgx.ErrNoRows {
				return apierr.NotFound("subnet_not_found", "no such site subnet in this organization")
			}
			return e
		}
		if e := q.DeleteSiteSubnet(ctx, subnetID); e != nil {
			return e
		}
		// F4 — the full-sweep law's DNS instance: a forward whose resolver lived IN this subnet is now
		// unreachable (SetDNSForward only ever admitted a resolver inside an approved subnet). Sweep those
		// forwards in the same tx so a stale row can't keep directing a zone's queries at an unrouted
		// resolver. Forwards with resolvers elsewhere are kept. The removed set is named in the audit.
		site, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: sub.SiteID, OrgID: orgID})
		if e != nil {
			return e
		}
		kept := make([]DNSForward, 0)
		swept := make([]string, 0)
		for _, en := range decodeDNS(site.DnsForwarding) {
			if ip, err := netip.ParseAddr(en.ResolverIP); err == nil && sub.Cidr.Contains(ip) {
				swept = append(swept, en.Domain)
				continue
			}
			kept = append(kept, en)
		}
		if len(swept) > 0 {
			raw, e := json.Marshal(kept)
			if e != nil {
				return e
			}
			if e := q.SetSiteDNSForwarding(ctx, sqlc.SetSiteDNSForwardingParams{ID: sub.SiteID, DnsForwarding: raw}); e != nil {
				return e
			}
		}
		return s.audit(ctx, q, orgID, actor, subnetID, "site.subnet_removed", map[string]any{
			"cidr": sub.Cidr.String(), "was_status": sub.Status, "dns_forwards_swept": swept,
		})
	})
}
