package k8s

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s/scopeapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/k8sapiaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
)

// K8N-4: "expose every Service in this namespace" (docs/K8N-4-expose-by-namespace.md).
//
// A namespace rule names one cluster and one namespace. Each time the cluster's gateway reports its
// Services the control plane exposes the namespace's Service ports that are not exposed yet and, after
// a wait, withdraws the exposures IT created whose Service is gone. It never creates an access rule and
// never touches an exposure made by hand or by the operator.

const (
	// NamespaceRuleWithdrawWait is how long a rule-created exposure's Service port must stay missing
	// from fresh reports before the exposure is withdrawn. Withdrawing is not reversible for the access
	// rules that point at the exposure, so a Service recreated by a deploy must not trigger it.
	NamespaceRuleWithdrawWait = 10 * time.Minute

	namespaceRuleActorSystem    = "k8s-namespace-rule"
	maxNamespaceRulesPerCluster = 50
	// MaxNamespaceRuleExclusions bounds the Service names one rule can leave out.
	MaxNamespaceRuleExclusions = 100
	// MaxNamespaceRuleSelectorPairs bounds a rule's label selector.
	MaxNamespaceRuleSelectorPairs = 8
)

// Why a pass withdrew an exposure; recorded in the audit entry.
const (
	namespaceRuleWithdrawNotReported = "service_not_reported"
	namespaceRuleWithdrawExcluded    = "service_excluded"
)

// The outcome of a rule's last pass. Anything but NamespaceRuleOK means the rule is not fully applied,
// and the message says why.
const (
	NamespaceRulePending              = "pending"
	NamespaceRuleOK                   = "applied"
	NamespaceRuleInventoryStale       = "inventory_stale"
	NamespaceRuleInventoryUnavailable = "inventory_unavailable"
	NamespaceRuleVIPRangeExhausted    = "vip_range_exhausted"
	NamespaceRuleScopeReviewLimit     = "scope_review_limit"
	NamespaceRuleWithdrawalBlocked    = "withdrawal_blocked"
	NamespaceRuleError                = "error"
	// The gateway's report carries no labels, so a selector cannot be evaluated (slice B).
	NamespaceRuleGatewayTooOld = "gateway_too_old"
	// Some Services have more labels than the report carries, so the selector cannot decide them.
	NamespaceRuleLabelsIncomplete = "labels_incomplete"
)

// NamespaceRule is one rule with the result of its last pass.
type NamespaceRule struct {
	ID               uuid.UUID
	OrgID            uuid.UUID
	ClusterID        uuid.UUID
	Namespace        string
	ExcludedServices []string
	// Selector is the rule's label selector; empty = every Service of the namespace.
	Selector map[string]string
	// ManagedByOperator: declared by a TunnexNamespaceExposure resource (slice C). Edited only there.
	ManagedByOperator bool
	Status            string
	StatusMessage     string
	WaitingServices   int
	ExposedServices   int
	ExposedPorts      int
	LastReconciledAt  *time.Time
	CreatedAt         time.Time
}

// NamespaceEligible refuses the namespaces a rule may never name: Kubernetes' own, and Tunnex's.
func NamespaceEligible(namespace string) error {
	if !validDNSLabel(namespace) {
		return apierr.BadRequest("invalid_namespace", "name one Kubernetes namespace (lowercase letters, digits and hyphens)")
	}
	switch namespace {
	case "kube-system", "kube-public", "kube-node-lease":
		return apierr.BadRequest("namespace_not_eligible", "the Kubernetes system namespace "+namespace+" cannot be exposed by a namespace rule; expose a Service in it by hand if you need one")
	}
	if namespace == "tunnex" || strings.HasPrefix(namespace, "tunnex-") {
		return apierr.BadRequest("namespace_not_eligible", "Tunnex's own namespace "+namespace+" cannot be exposed by a namespace rule")
	}
	return nil
}

// NamespaceRuleInput is what an administrator chooses when creating a rule.
type NamespaceRuleInput struct {
	Namespace string
	// ExcludedServices are Services of the namespace the rule must not expose (slice A).
	ExcludedServices []string
	// Selector limits the rule to Services whose labels equal every pair (slice B). Empty = all.
	Selector map[string]string
}

// NamespaceRuleUpdate changes a rule in place. A nil field is left as it is.
type NamespaceRuleUpdate struct {
	ExcludedServices *[]string
	// Selector replaces the selector; a pointer to an empty map clears it.
	Selector *map[string]string
}

// normalizeSelector validates a label selector: equality pairs only, Kubernetes label syntax, bounded.
func normalizeSelector(selector map[string]string) (map[string]string, error) {
	if len(selector) > MaxNamespaceRuleSelectorPairs {
		return nil, apierr.BadRequest("selector_limit", fmt.Sprintf("a namespace rule's selector can have at most %d key=value pairs", MaxNamespaceRuleSelectorPairs))
	}
	out := make(map[string]string, len(selector))
	for key, value := range selector {
		if !ValidLabelKey(key) {
			return nil, apierr.BadRequest("invalid_selector", fmt.Sprintf("%q is not a Kubernetes label key; a selector is key=value pairs and has no wildcards or operators", key))
		}
		if !ValidLabelValue(value) {
			return nil, apierr.BadRequest("invalid_selector", fmt.Sprintf("%q is not a Kubernetes label value (key %s); a selector is key=value pairs and has no wildcards or operators", value, key))
		}
		out[key] = value
	}
	return out, nil
}

func selectorText(selector map[string]string) string {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, len(keys))
	for i, key := range keys {
		pairs[i] = key + "=" + selector[key]
	}
	return strings.Join(pairs, ",")
}

func sameSelector(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}

// normalizeExcludedServices validates an exclusion list and returns it sorted. Names only: a Service is
// named exactly, there is no pattern, and a name that matches nothing today is allowed.
func normalizeExcludedServices(names []string) ([]string, error) {
	if len(names) > MaxNamespaceRuleExclusions {
		return nil, apierr.BadRequest("excluded_services_limit", fmt.Sprintf("a namespace rule can exclude at most %d Services", MaxNamespaceRuleExclusions))
	}
	out := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if !validDNSLabel(name) {
			return nil, apierr.BadRequest("invalid_excluded_service", "name each excluded Service exactly (lowercase letters, digits and hyphens); patterns are not supported")
		}
		if seen[name] {
			return nil, apierr.BadRequest("invalid_excluded_service", "the Service "+name+" is listed twice")
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// ── the planner: pure, no database ───────────────────────────────────────────────────────────────────

// reportedService is one Service of the rule's namespace in the current report.
type reportedService struct {
	Service string
	UID     string
	Ports   []inventoryExposurePort
	// APIServer marks default/kubernetes (K8N-3). A rule never exposes it: the cluster's API is reached
	// through API access. It still counts as reported, so an exposure of it that a rule made before this
	// refusal existed is left in place rather than read as "gone" and withdrawn.
	APIServer bool
	// LabelsKnown is false for a Service of a report that carries no labels (an old gateway).
	// LabelsTruncated means the Service has more labels than Labels holds.
	LabelsKnown     bool
	LabelsTruncated bool
	Labels          map[string]string
}

// What a rule's selector says about one reported Service.
type selectorMatch int

const (
	selectorMatches selectorMatch = iota
	selectorDoesNotMatch
	// selectorLabelsUnknown: the report has no labels for the Service. Never read as a match, never as
	// a mismatch.
	selectorLabelsUnknown
	// selectorLabelsIncomplete: a selector key is absent from labels that were truncated.
	selectorLabelsIncomplete
)

// matchSelector decides one Service. An empty selector matches everything and reads no labels. A pair
// present with another value is a mismatch whatever else is unknown: no further label can change that.
func matchSelector(selector map[string]string, svc reportedService) selectorMatch {
	if len(selector) == 0 {
		return selectorMatches
	}
	if !svc.LabelsKnown {
		return selectorLabelsUnknown
	}
	absent := false
	for key, want := range selector {
		got, ok := svc.Labels[key]
		if ok && got != want {
			return selectorDoesNotMatch
		}
		if !ok {
			absent = true
		}
	}
	switch {
	case !absent:
		return selectorMatches
	case svc.LabelsTruncated:
		return selectorLabelsIncomplete
	}
	return selectorDoesNotMatch
}

// exposedPort is one live exposure in the rule's namespace, whoever made it.
type exposedPort struct {
	ID           uuid.UUID
	Service      string
	Protocol     string // tcp | udp | any (legacy)
	Port         int32  // 0 = a legacy all-ports exposure
	VIP          string
	RuleID       uuid.UUID // uuid.Nil = made by hand or by the operator
	MissingSince *time.Time
}

type plannedExposure struct {
	Service string
	UID     string
	Ports   []inventoryExposurePort
	VIP     string // the Service's existing address, "" = allocate one
}

type namespaceRulePlan struct {
	Expose       []plannedExposure
	MarkMissing  []uuid.UUID
	ClearMissing []uuid.UUID
	Withdraw     []uuid.UUID
	// WithdrawExcluded are the rule's own exposures of Services the administrator excluded. They are
	// withdrawn without the wait: an exclusion is a stated decision, not a Service that may come back.
	WithdrawExcluded []uuid.UUID
	// LabelsUnknown is set when the selector could not be evaluated for at least one Service because
	// the report carries no labels. LabelsIncomplete names the Services whose truncated labels left
	// the selector undecided. Neither is exposed, and neither is withdrawn.
	LabelsUnknown    bool
	LabelsIncomplete []string
}

func (p namespaceRulePlan) empty() bool {
	return len(p.Expose) == 0 && len(p.MarkMissing) == 0 && len(p.ClearMissing) == 0 && len(p.Withdraw) == 0 && len(p.WithdrawExcluded) == 0
}

// namespaceRuleSpec is the part of a rule the planner reads.
type namespaceRuleSpec struct {
	ID       uuid.UUID
	Excluded map[string]bool
	Selector map[string]string
}

// planNamespaceRule compares what the gateway reported for the namespace with the exposures that exist.
//   - A reported port nobody exposed is exposed. A port already exposed by anyone is left alone.
//   - Only rows carrying the rule's id can be marked missing or withdrawn; rows made by hand, by the
//     operator or by another rule are never returned in any list.
//   - An excluded Service is never exposed, and the rule's own exposures of it are withdrawn at once.
//   - With a selector, a Service that does not match is treated as not there: never exposed, and the
//     rule's own exposure of it is marked and withdrawn after the wait. A Service the selector cannot
//     decide (no labels reported, or truncated) is never exposed and its exposure is left as it is.
func planNamespaceRule(rule namespaceRuleSpec, reported []reportedService, exposed []exposedPort, now time.Time, wait time.Duration) namespaceRulePlan {
	ruleID := rule.ID
	type portKey struct {
		service  string
		protocol string
		port     int32
	}
	covered := map[portKey]bool{}
	allPorts := map[string]bool{}
	vipOf := map[string]string{}
	for _, row := range exposed {
		if _, ok := vipOf[row.Service]; !ok {
			vipOf[row.Service] = row.VIP
		}
		if row.Port == 0 {
			allPorts[row.Service] = true
			continue
		}
		covered[portKey{row.Service, row.Protocol, row.Port}] = true
	}
	var plan namespaceRulePlan
	reportedPorts := map[portKey]bool{}
	for _, svc := range reported {
		// The API server is never exposed and an exposure of it a rule once made is kept (K8N-3), so the
		// selector is not asked about it. An excluded Service is decided by the exclusion alone.
		match := selectorMatches
		if !svc.APIServer && !rule.Excluded[svc.Service] {
			match = matchSelector(rule.Selector, svc)
		}
		switch match {
		case selectorLabelsUnknown:
			plan.LabelsUnknown = true
		case selectorLabelsIncomplete:
			plan.LabelsIncomplete = append(plan.LabelsIncomplete, svc.Service)
		}
		var missing []inventoryExposurePort
		for _, port := range svc.Ports {
			if match != selectorDoesNotMatch {
				// "Still there" for the rule's own exposures: a match, or a Service it cannot decide.
				reportedPorts[portKey{svc.Service, string(port.Protocol), port.Port}] = true
			}
			if svc.APIServer || rule.Excluded[svc.Service] || match != selectorMatches {
				continue
			}
			if allPorts[svc.Service] || covered[portKey{svc.Service, string(port.Protocol), port.Port}] || covered[portKey{svc.Service, "any", port.Port}] {
				continue
			}
			missing = append(missing, port)
		}
		if len(missing) > 0 {
			plan.Expose = append(plan.Expose, plannedExposure{Service: svc.Service, UID: svc.UID, Ports: missing, VIP: vipOf[svc.Service]})
		}
	}
	for _, row := range exposed {
		if ruleID == uuid.Nil || row.RuleID != ruleID {
			continue
		}
		if rule.Excluded[row.Service] {
			plan.WithdrawExcluded = append(plan.WithdrawExcluded, row.ID)
			continue
		}
		present := reportedPorts[portKey{row.Service, row.Protocol, row.Port}]
		switch {
		case present && row.MissingSince != nil:
			plan.ClearMissing = append(plan.ClearMissing, row.ID)
		case present:
		case row.MissingSince == nil:
			plan.MarkMissing = append(plan.MarkMissing, row.ID)
		case now.Sub(*row.MissingSince) >= wait:
			plan.Withdraw = append(plan.Withdraw, row.ID)
		}
	}
	sort.Slice(plan.Expose, func(i, j int) bool { return plan.Expose[i].Service < plan.Expose[j].Service })
	sort.Strings(plan.LabelsIncomplete)
	return plan
}

// ── create / list / delete ───────────────────────────────────────────────────────────────────────────

// namespaceRuleActor is who is changing a rule: a signed-in administrator, or the operator's machine
// credential on behalf of a TunnexNamespaceExposure resource (slice C).
type namespaceRuleActor struct {
	UserID uuid.UUID // the human; uuid.Nil for a machine
	System string    // audit actor_system for a machine, "" for a human
	Cause  string    // the resource that drove a machine's change
	// MachineID is the credential a machine-made rule is marked with; uuid.Nil for a human.
	MachineID uuid.UUID
}

func (a namespaceRuleActor) machine() bool { return a.MachineID != uuid.Nil }

// resolveNamespaceRuleActor accepts a verified human session or a machine credential with a current human
// owner. Agents and gateways never change a rule.
func resolveNamespaceRuleActor(actor *authctx.Principal) (namespaceRuleActor, error) {
	if actor == nil || actor.AuthMethod == authctx.AuthAgent || actor.NodeID != uuid.Nil {
		return namespaceRuleActor{}, apierr.Forbidden("human_actor_required", "a namespace rule is created and removed by a signed-in administrator or by the GitOps operator")
	}
	if actor.IsMachine() {
		if actor.OwnerUserID == uuid.Nil {
			return namespaceRuleActor{}, apierr.Forbidden("actor_required", "the machine credential must have a current human owner")
		}
		_, system, cause := actor.AuditActor()
		if system == "" {
			return namespaceRuleActor{}, apierr.Forbidden("actor_required", "the machine credential audit identity is invalid")
		}
		return namespaceRuleActor{System: system, Cause: cause, MachineID: actor.MachineID}, nil
	}
	if actor.UserID == uuid.Nil {
		return namespaceRuleActor{}, apierr.Forbidden("human_actor_required", "a namespace rule is created and removed by a signed-in administrator or by the GitOps operator")
	}
	if !actor.EmailVerified {
		return namespaceRuleActor{}, apierr.Forbidden("email_not_verified", "verify your email before changing which Kubernetes Services are exposed")
	}
	return namespaceRuleActor{UserID: actor.UserID}, nil
}

// namespaceRuleOwnership refuses a change by the wrong owner. A rule declared in Git is edited only there:
// the operator would undo a dashboard edit within minutes. And the operator's credential never touches a
// rule a person made. A person may still REMOVE an operator's rule (the way out when the operator is
// gone); that is not an edit and is not checked here.
func namespaceRuleOwnership(who namespaceRuleActor, managedByMachine bool, namespace string, edit bool) error {
	switch {
	case who.machine() && !managedByMachine:
		return apierr.Conflict("rule_not_managed_by_operator", "the namespace rule for "+namespace+" was made outside the GitOps operator and can only be changed or removed in Tunnex")
	case !who.machine() && managedByMachine && edit:
		return apierr.Conflict("managed_by_operator", "the namespace rule for "+namespace+" is declared by a TunnexNamespaceExposure resource; change that resource instead")
	}
	return nil
}

// CreateNamespaceRule records the opt-in for one namespace of one cluster and runs the first pass. The
// rule is returned with that pass's outcome; a pass that could not run (no current report) leaves the
// rule in place, waiting for the gateway's next report.
func (s *Service) CreateNamespaceRule(ctx context.Context, orgID, clusterID uuid.UUID, in NamespaceRuleInput, actor *authctx.Principal) (NamespaceRule, error) {
	who, err := resolveNamespaceRuleActor(actor)
	if err != nil {
		return NamespaceRule{}, err
	}
	namespace := in.Namespace
	if err := NamespaceEligible(namespace); err != nil {
		return NamespaceRule{}, err
	}
	excluded, err := normalizeExcludedServices(in.ExcludedServices)
	if err != nil {
		return NamespaceRule{}, err
	}
	selector, err := normalizeSelector(in.Selector)
	if err != nil {
		return NamespaceRule{}, err
	}
	var ruleID uuid.UUID
	err = s.withTxRaw(ctx, func(q *sqlc.Queries, tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT true FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, clusterID, orgID).Scan(&exists); errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization")
		} else if e != nil {
			return e
		}
		var count int
		var duplicate bool
		if e := tx.QueryRow(ctx, `SELECT count(*), COALESCE(bool_or(namespace=$3), false) FROM k8s_namespace_exposure_rules WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID, namespace).Scan(&count, &duplicate); e != nil {
			return e
		}
		if duplicate {
			return apierr.Conflict("namespace_rule_exists", "this cluster already has a namespace rule for "+namespace)
		}
		if count >= maxNamespaceRulesPerCluster {
			return apierr.Conflict("namespace_rule_limit", fmt.Sprintf("a cluster can have at most %d namespace rules", maxNamespaceRulesPerCluster))
		}
		if e := tx.QueryRow(ctx, `INSERT INTO k8s_namespace_exposure_rules(org_id,cluster_id,namespace,created_by_user_id,excluded_services,selector,managed_by_machine) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			orgID, clusterID, namespace, pgUUID(who.UserID, who.UserID != uuid.Nil), excluded, selector, pgUUID(who.MachineID, who.machine())).Scan(&ruleID); e != nil {
			if pgerr.IsUnique(e) {
				return apierr.Conflict("namespace_rule_exists", "this cluster already has a namespace rule for "+namespace)
			}
			return e
		}
		return s.audit(ctx, q, orgID, who.UserID, who.System, who.Cause, "k8s_namespace_rule", ruleID.String(), "k8s.namespace_rule_created",
			map[string]any{"cluster_id": clusterID.String(), "namespace": namespace, "excluded_services": excluded, "selector": selectorText(selector), "managed_by_operator": who.machine()})
	})
	if err != nil {
		return NamespaceRule{}, err
	}
	// The first pass. Its outcome is on the rule; a failure here is not a failure to create the rule.
	_ = s.ReconcileNamespaceRules(ctx, orgID, clusterID)
	return s.namespaceRuleByID(ctx, orgID, clusterID, ruleID)
}

func (s *Service) namespaceRuleByID(ctx context.Context, orgID, clusterID, ruleID uuid.UUID) (NamespaceRule, error) {
	rules, err := s.ListNamespaceRules(ctx, orgID, clusterID)
	if err != nil {
		return NamespaceRule{}, err
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule, nil
		}
	}
	return NamespaceRule{}, apierr.NotFound("namespace_rule_not_found", "no such namespace rule on this cluster")
}

// UpdateNamespaceRule changes what a rule leaves out or selects and runs a pass. Excluding a Service
// withdraws the exposures the rule made for it on that pass (no wait); taking a name off the list
// exposes the Service again as a new exposure. A changed selector exposes what now matches on that pass;
// what no longer matches is withdrawn after the same wait as a Service that is gone. The rule is
// returned with the pass's outcome.
func (s *Service) UpdateNamespaceRule(ctx context.Context, orgID, clusterID, ruleID uuid.UUID, update NamespaceRuleUpdate, actor *authctx.Principal) (NamespaceRule, error) {
	who, err := resolveNamespaceRuleActor(actor)
	if err != nil {
		return NamespaceRule{}, err
	}
	var excluded []string
	if update.ExcludedServices != nil {
		if excluded, err = normalizeExcludedServices(*update.ExcludedServices); err != nil {
			return NamespaceRule{}, err
		}
	}
	var selector map[string]string
	if update.Selector != nil {
		if selector, err = normalizeSelector(*update.Selector); err != nil {
			return NamespaceRule{}, err
		}
	}
	err = s.withTxRaw(ctx, func(q *sqlc.Queries, tx pgx.Tx) error {
		var namespace string
		var before []string
		var selectorBefore map[string]string
		var managed bool
		if e := tx.QueryRow(ctx, `SELECT namespace,excluded_services,selector,managed_by_machine IS NOT NULL FROM k8s_namespace_exposure_rules WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, ruleID, orgID, clusterID).Scan(&namespace, &before, &selectorBefore, &managed); errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("namespace_rule_not_found", "no such namespace rule on this cluster")
		} else if e != nil {
			return e
		}
		if e := namespaceRuleOwnership(who, managed, namespace, true); e != nil {
			return e
		}
		meta := map[string]any{"cluster_id": clusterID.String(), "namespace": namespace}
		changed := false
		if update.ExcludedServices != nil {
			added, removed := stringSetDiff(before, excluded)
			if len(added) != 0 || len(removed) != 0 {
				changed = true
				meta["excluded_services_added"], meta["excluded_services_removed"] = added, removed
			}
		} else {
			excluded = before
		}
		if update.Selector != nil && !sameSelector(selectorBefore, selector) {
			changed = true
			meta["selector_before"], meta["selector"] = selectorText(selectorBefore), selectorText(selector)
		} else {
			selector = selectorBefore
		}
		if !changed {
			return nil
		}
		if _, e := tx.Exec(ctx, `UPDATE k8s_namespace_exposure_rules SET excluded_services=$3,selector=$4 WHERE id=$1 AND org_id=$2`, ruleID, orgID, excluded, selector); e != nil {
			return e
		}
		return s.audit(ctx, q, orgID, who.UserID, who.System, who.Cause, "k8s_namespace_rule", ruleID.String(), "k8s.namespace_rule_updated", meta)
	})
	if err != nil {
		return NamespaceRule{}, err
	}
	_ = s.ReconcileNamespaceRules(ctx, orgID, clusterID)
	return s.namespaceRuleByID(ctx, orgID, clusterID, ruleID)
}

// stringSetDiff returns what next has that prev lacks, and what prev had that next lacks, sorted.
func stringSetDiff(prev, next []string) (added, removed []string) {
	in := func(list []string) map[string]bool {
		set := make(map[string]bool, len(list))
		for _, v := range list {
			set[v] = true
		}
		return set
	}
	prevSet, nextSet := in(prev), in(next)
	added, removed = []string{}, []string{}
	for v := range nextSet {
		if !prevSet[v] {
			added = append(added, v)
		}
	}
	for v := range prevSet {
		if !nextSet[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// ListNamespaceRules returns a cluster's rules. A rule whose cluster has no current report is shown as
// stale or unavailable whatever its last pass said: without a report nothing is being applied.
func (s *Service) ListNamespaceRules(ctx context.Context, orgID, clusterID uuid.UUID) ([]NamespaceRule, error) {
	if _, err := s.GetCluster(ctx, orgID, clusterID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.id,r.org_id,r.cluster_id,r.namespace,r.excluded_services,r.selector,r.managed_by_machine IS NOT NULL,r.status,r.status_message,r.waiting_services,r.last_reconciled_at,r.created_at,
		       (SELECT count(DISTINCT s.name) FROM k8s_namespace_rule_exposures e JOIN k8s_services s ON s.id=e.service_id WHERE e.rule_id=r.id AND s.deleted_at IS NULL),
		       (SELECT count(*) FROM k8s_namespace_rule_exposures e JOIN k8s_services s ON s.id=e.service_id WHERE e.rule_id=r.id AND s.deleted_at IS NULL)
		FROM k8s_namespace_exposure_rules r
		WHERE r.org_id=$1 AND r.cluster_id=$2
		ORDER BY r.namespace`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]NamespaceRule, 0)
	for rows.Next() {
		var rule NamespaceRule
		if err := rows.Scan(&rule.ID, &rule.OrgID, &rule.ClusterID, &rule.Namespace, &rule.ExcludedServices, &rule.Selector, &rule.ManagedByOperator, &rule.Status, &rule.StatusMessage, &rule.WaitingServices,
			&rule.LastReconciledAt, &rule.CreatedAt, &rule.ExposedServices, &rule.ExposedPorts); err != nil {
			return nil, err
		}
		if rule.ExcludedServices == nil {
			rule.ExcludedServices = []string{}
		}
		if rule.Selector == nil {
			rule.Selector = map[string]string{}
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	if _, err := currentInventoryReport(ctx, s.pool, orgID, clusterID, false); err != nil {
		if _, _, ok := namespaceRuleInventoryStatus(err); !ok {
			return nil, err
		}
		latest, err2 := latestInventoryReceivedAt(ctx, s.pool, orgID, clusterID)
		if err2 != nil {
			return nil, err2
		}
		now := time.Now()
		for i := range out {
			out[i].Status, out[i].StatusMessage = namespaceRuleNoReportStatus(err, out[i].CreatedAt, latest, now)
		}
	}
	return out, nil
}

// namespaceRuleFirstReportGrace is how long a new rule waits for the gateway's next Service report
// before the lack of one is reported as a problem. It covers the report's 90s freshness plus the
// longest report interval (60s) — a healthy gateway always reports well within it.
const namespaceRuleFirstReportGrace = 150 * time.Second

const namespaceRuleAwaitingReportMessage = "waiting for the gateway's next Service report; nothing is exposed until it arrives"

// namespaceRuleAwaitingReport: the rule is newer than the cluster's latest Service report (or the
// cluster never reported) and still inside the grace. The missing report then says nothing about the
// gateway yet — the next one simply has not arrived.
func namespaceRuleAwaitingReport(created time.Time, latestReceived *time.Time, now time.Time) bool {
	return now.Sub(created) < namespaceRuleFirstReportGrace && (latestReceived == nil || !latestReceived.After(created))
}

// namespaceRuleNoReportStatus is the status shown and stored when the cluster has no current report.
// Only "no current report" is softened to pending, and only for a rule awaiting its first report; a
// stale report (the gateway stopped reporting) is never masked. Nothing is exposed either way.
func namespaceRuleNoReportStatus(err error, created time.Time, latestReceived *time.Time, now time.Time) (status, message string) {
	status, message, _ = namespaceRuleInventoryStatus(err)
	if status == NamespaceRuleInventoryUnavailable && namespaceRuleAwaitingReport(created, latestReceived, now) {
		return NamespaceRulePending, namespaceRuleAwaitingReportMessage
	}
	return status, message
}

// latestInventoryReceivedAt is when the cluster's newest Service report arrived, current or not.
func latestInventoryReceivedAt(ctx context.Context, db scopeDB, orgID, clusterID uuid.UUID) (*time.Time, error) {
	var latest *time.Time
	if err := db.QueryRow(ctx, `SELECT max(received_at) FROM k8s_service_inventory_reports WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&latest); err != nil {
		return nil, err
	}
	return latest, nil
}

func namespaceRuleInventoryStatus(err error) (status, message string, ok bool) {
	switch {
	case errors.Is(err, scopeapproval.ErrInventoryStale):
		return NamespaceRuleInventoryStale, "the cluster's gateway has not reported its Services recently; nothing is exposed or withdrawn until it does", true
	case errors.Is(err, scopeapproval.ErrInventoryUnavailable):
		return NamespaceRuleInventoryUnavailable, "there is no current Service report from the cluster's gateway (it sends none above 500 Services); nothing is exposed or withdrawn until there is", true
	}
	return "", "", false
}

// DeleteNamespaceRule removes a rule. withdraw=false keeps its exposures as ordinary dashboard
// exposures; withdraw=true withdraws every one in the same transaction, or changes nothing if any one
// is refused.
func (s *Service) DeleteNamespaceRule(ctx context.Context, orgID, clusterID, ruleID uuid.UUID, withdraw bool, actor *authctx.Principal) error {
	who, err := resolveNamespaceRuleActor(actor)
	if err != nil {
		return err
	}
	err = s.withTxRaw(ctx, func(q *sqlc.Queries, tx pgx.Tx) error {
		var namespace string
		var managed bool
		if e := tx.QueryRow(ctx, `SELECT namespace,managed_by_machine IS NOT NULL FROM k8s_namespace_exposure_rules WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, ruleID, orgID, clusterID).Scan(&namespace, &managed); errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("namespace_rule_not_found", "no such namespace rule on this cluster")
		} else if e != nil {
			return e
		}
		if e := namespaceRuleOwnership(who, managed, namespace, false); e != nil {
			return e
		}
		ids, e := namespaceRuleExposureIDs(ctx, tx, orgID, ruleID)
		if e != nil {
			return e
		}
		if withdraw {
			for _, id := range ids {
				svc, e := q.GetK8sService(ctx, sqlc.GetK8sServiceParams{OrgID: orgID, ID: id})
				if e != nil {
					return e
				}
				if e := s.unexposeServiceTx(ctx, q, tx, svc, who.UserID, who.System, who.Cause, map[string]any{"namespace_rule_id": ruleID.String(), "namespace_rule_removed": true}); e != nil {
					var apiError *apierr.Error
					if errors.As(e, &apiError) {
						return apierr.Conflict(apiError.Code, svc.Namespace+"/"+svc.Name+" cannot be withdrawn: "+apiError.Message+". Nothing was changed.")
					}
					return e
				}
			}
		}
		// The cascade removes the rule's ownership rows: kept exposures become ordinary dashboard exposures.
		if _, e := tx.Exec(ctx, `DELETE FROM k8s_namespace_exposure_rules WHERE id=$1 AND org_id=$2`, ruleID, orgID); e != nil {
			return e
		}
		exposures := "kept"
		if withdraw {
			exposures = "withdrawn"
		}
		return s.audit(ctx, q, orgID, who.UserID, who.System, who.Cause, "k8s_namespace_rule", ruleID.String(), "k8s.namespace_rule_deleted",
			map[string]any{"cluster_id": clusterID.String(), "namespace": namespace, "exposures": exposures, "exposure_count": len(ids), "managed_by_operator": managed})
	})
	if err == nil && withdraw {
		s.pushOrg(ctx, orgID)
	}
	return err
}

func namespaceRuleExposureIDs(ctx context.Context, tx pgx.Tx, orgID, ruleID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT s.id FROM k8s_namespace_rule_exposures e JOIN k8s_services s ON s.id=e.service_id
		WHERE e.org_id=$1 AND e.rule_id=$2 AND s.deleted_at IS NULL ORDER BY s.namespace,s.name,s.protocol,s.port_low,s.id`, orgID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ── the pass ─────────────────────────────────────────────────────────────────────────────────────────

// ReconcileNamespaceRulesForOrg applies every namespace rule of the organization. It is called after a
// gateway's Service report is accepted; an organization with no rule costs one query.
func (s *Service) ReconcileNamespaceRulesForOrg(ctx context.Context, orgID uuid.UUID) error {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT cluster_id FROM k8s_namespace_exposure_rules WHERE org_id=$1`, orgID)
	if err != nil {
		return err
	}
	var clusters []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		clusters = append(clusters, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var first error
	for _, clusterID := range clusters {
		if err := s.ReconcileNamespaceRules(ctx, orgID, clusterID); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ReconcileNamespaceRules applies one cluster's rules against its current Service report.
func (s *Service) ReconcileNamespaceRules(ctx context.Context, orgID, clusterID uuid.UUID) error {
	return s.reconcileNamespaceRulesAt(ctx, orgID, clusterID, time.Now().UTC())
}

type namespaceRuleRow struct {
	ID        uuid.UUID
	Namespace string
	Excluded  []string
	Selector  map[string]string
	CreatedAt time.Time
}

func (r namespaceRuleRow) spec() namespaceRuleSpec {
	spec := namespaceRuleSpec{ID: r.ID, Excluded: make(map[string]bool, len(r.Excluded)), Selector: r.Selector}
	for _, name := range r.Excluded {
		spec.Excluded[name] = true
	}
	return spec
}

func (s *Service) reconcileNamespaceRulesAt(ctx context.Context, orgID, clusterID uuid.UUID, now time.Time) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var vipRange string
	var dnsVIP *string
	if err := tx.QueryRow(ctx, `SELECT vip_range::text,host(dns_vip) FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, clusterID, orgID).Scan(&vipRange, &dnsVIP); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	ruleRows, err := tx.Query(ctx, `SELECT id,namespace,excluded_services,selector,created_at FROM k8s_namespace_exposure_rules WHERE org_id=$1 AND cluster_id=$2 ORDER BY namespace FOR UPDATE`, orgID, clusterID)
	if err != nil {
		return err
	}
	var rules []namespaceRuleRow
	for ruleRows.Next() {
		var rule namespaceRuleRow
		if err := ruleRows.Scan(&rule.ID, &rule.Namespace, &rule.Excluded, &rule.Selector, &rule.CreatedAt); err != nil {
			ruleRows.Close()
			return err
		}
		rules = append(rules, rule)
	}
	ruleRows.Close()
	if err := ruleRows.Err(); err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}

	report, err := currentInventoryReport(ctx, tx, orgID, clusterID, true)
	if err != nil {
		if _, _, ok := namespaceRuleInventoryStatus(err); !ok {
			return err
		}
		latest, lerr := latestInventoryReceivedAt(ctx, tx, orgID, clusterID)
		if lerr != nil {
			return lerr
		}
		// No current report: record why (or that a new rule awaits its first report), expose nothing,
		// withdraw nothing.
		for _, rule := range rules {
			status, message := namespaceRuleNoReportStatus(err, rule.CreatedAt, latest, now)
			if _, err := tx.Exec(ctx, `UPDATE k8s_namespace_exposure_rules SET status=$3,status_message=$4 WHERE org_id=$1 AND id=$2`, orgID, rule.ID, status, message); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}

	used, err := queryStrings(ctx, tx, `SELECT host(vip) FROM k8s_services WHERE org_id=$1 AND cluster_id=$2 AND deleted_at IS NULL`, orgID, clusterID)
	if err != nil {
		return err
	}
	if dnsVIP != nil {
		used = append(used, *dnsVIP)
	}
	// K8N-3: and around the cluster API's address while API access is on.
	apiVIPs, err := k8sapiaccess.EndpointVIPs(ctx, sqlc.New(tx), orgID, clusterID)
	if err != nil {
		return err
	}
	used = append(used, apiVIPs...)

	changed := false
	for _, rule := range rules {
		reported, err := reportedNamespaceServices(ctx, tx, report.ID, orgID, clusterID, rule.Namespace)
		if err != nil {
			return err
		}
		exposed, err := exposedNamespacePorts(ctx, tx, orgID, clusterID, rule.Namespace)
		if err != nil {
			return err
		}
		plan := planNamespaceRule(rule.spec(), reported, exposed, now, NamespaceRuleWithdrawWait)
		cause := "namespace_rule:" + rule.ID.String()
		status, message, waiting := NamespaceRuleOK, "", 0
		// What the selector could not decide is stated first; a failed withdrawal or exposure below
		// replaces it, being the more urgent thing to read.
		switch {
		case plan.LabelsUnknown:
			status = NamespaceRuleGatewayTooOld
			message = "this rule selects Services by label (" + selectorText(rule.Selector) + ") but the cluster's gateway reports Services without labels: it is older than label selectors. Upgrade the gateway. Until then the rule exposes no Service and withdraws none for its labels."
		case len(plan.LabelsIncomplete) > 0:
			status = NamespaceRuleLabelsIncomplete
			message = fmt.Sprintf("%d Service(s) in %s have more labels than the gateway reports (%s), so the rule cannot tell whether they match %s and leaves them as they are. Expose them by hand, or exclude them from the rule.",
				len(plan.LabelsIncomplete), rule.Namespace, namesPreview(plan.LabelsIncomplete, 5), selectorText(rule.Selector))
		}

		if len(plan.ClearMissing) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE k8s_namespace_rule_exposures SET missing_since=NULL WHERE org_id=$1 AND service_id=ANY($2::uuid[])`, orgID, plan.ClearMissing); err != nil {
				return err
			}
		}
		if len(plan.MarkMissing) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE k8s_namespace_rule_exposures SET missing_since=$3 WHERE org_id=$1 AND service_id=ANY($2::uuid[]) AND missing_since IS NULL`, orgID, plan.MarkMissing, now); err != nil {
				return err
			}
		}

		for _, withdrawal := range []struct {
			ids    []uuid.UUID
			reason string
		}{{plan.WithdrawExcluded, namespaceRuleWithdrawExcluded}, {plan.Withdraw, namespaceRuleWithdrawNotReported}} {
			for _, id := range withdrawal.ids {
				blockedBy, err := s.withdrawNamespaceRuleExposure(ctx, tx, orgID, rule.ID, id, cause, withdrawal.reason)
				if err != nil {
					return err
				}
				if blockedBy != "" {
					status, message = NamespaceRuleWithdrawalBlocked, blockedBy
					continue
				}
				changed = true
			}
		}

		if len(plan.Expose) > 0 {
			failStatus, failMessage, nextUsed, err := s.exposeNamespaceRuleServices(ctx, tx, orgID, clusterID, rule.ID, rule.Namespace, vipRange, used, plan.Expose, cause)
			if err != nil {
				return err
			}
			if failStatus != "" {
				// All of the namespace's missing Services, or none: nothing from this pass is kept.
				status, message, waiting = failStatus, failMessage, len(plan.Expose)
			} else {
				used, changed = nextUsed, true
			}
		}

		if _, err := tx.Exec(ctx, `UPDATE k8s_namespace_exposure_rules SET status=$3,status_message=$4,waiting_services=$5,last_reconciled_at=$6 WHERE org_id=$1 AND id=$2`,
			orgID, rule.ID, status, message, waiting, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if changed {
		s.pushOrg(ctx, orgID)
	}
	return nil
}

// withdrawNamespaceRuleExposure withdraws one exposure inside a savepoint. A refusal (an agent access
// request or a template version points at it) is returned as text and leaves the exposure in place.
func (s *Service) withdrawNamespaceRuleExposure(ctx context.Context, tx pgx.Tx, orgID, ruleID, serviceID uuid.UUID, cause, reason string) (blockedBy string, err error) {
	nested, err := tx.Begin(ctx)
	if err != nil {
		return "", err
	}
	q := sqlc.New(nested)
	svc, err := q.GetK8sService(ctx, sqlc.GetK8sServiceParams{OrgID: orgID, ID: serviceID})
	if err == nil {
		err = s.unexposeServiceTx(ctx, q, nested, svc, uuid.Nil, namespaceRuleActorSystem, cause,
			map[string]any{"namespace_rule_id": ruleID.String(), "namespace": svc.Namespace, "name": svc.Name, "reason": reason})
	}
	if err != nil {
		_ = nested.Rollback(ctx)
		var apiError *apierr.Error
		if errors.As(err, &apiError) {
			why := " is gone from the cluster"
			if reason == namespaceRuleWithdrawExcluded {
				why = " is excluded from this rule"
			}
			return svc.Namespace + "/" + svc.Name + why + " but its exposure cannot be withdrawn: " + apiError.Message, nil
		}
		return "", err
	}
	return "", nested.Commit(ctx)
}

// exposeNamespaceRuleServices exposes every planned Service inside one savepoint. On a limit it rolls
// the savepoint back and returns the status to record; nothing from the pass is kept.
func (s *Service) exposeNamespaceRuleServices(ctx context.Context, tx pgx.Tx, orgID, clusterID, ruleID uuid.UUID, namespace, vipRange string, used []string, planned []plannedExposure, cause string) (failStatus, failMessage string, nextUsed []string, err error) {
	nested, err := tx.Begin(ctx)
	if err != nil {
		return "", "", nil, err
	}
	nextUsed = append([]string(nil), used...)
	fail := func(status, message string) (string, string, []string, error) {
		_ = nested.Rollback(ctx)
		return status, message, nil, nil
	}
	for _, exposure := range planned {
		vip := exposure.VIP
		if vip == "" {
			vip, err = ipalloc.Allocate(vipRange, nextUsed)
			if errors.Is(err, ipalloc.ErrPoolExhausted) {
				return fail(NamespaceRuleVIPRangeExhausted, fmt.Sprintf(
					"the cluster's address range %s is full: %d Services in %s are waiting and none was exposed. Unexpose Services you no longer need, or register the cluster again with a larger range.",
					vipRange, len(planned), namespace))
			}
			if err != nil {
				_ = nested.Rollback(ctx)
				return "", "", nil, err
			}
			nextUsed = append(nextUsed, vip)
		}
		_, _, err := s.insertInventoryExposures(ctx, nested, inventoryExposureInsert{
			OrgID: orgID, ClusterID: clusterID, Namespace: namespace, Service: exposure.Service, ServiceUID: exposure.UID,
			Ports: exposure.Ports, VIP: vip, NamespaceRuleID: ruleID, ActorSystem: namespaceRuleActorSystem, Cause: cause,
		})
		if err != nil {
			var apiError *apierr.Error
			if !errors.As(err, &apiError) {
				_ = nested.Rollback(ctx)
				return "", "", nil, err
			}
			status := NamespaceRuleError
			if apiError.Code == "k8s_cluster_scope_pending_fanout_limit" || apiError.Code == "k8s_cluster_scope_limit_reached" {
				status = NamespaceRuleScopeReviewLimit
			}
			return fail(status, fmt.Sprintf("%s/%s could not be exposed (%s), so none of the %d waiting Services in %s was exposed.",
				namespace, exposure.Service, apiError.Message, len(planned), namespace))
		}
	}
	if err := nested.Commit(ctx); err != nil {
		return "", "", nil, err
	}
	return "", "", nextUsed, nil
}

func reportedNamespaceServices(ctx context.Context, tx pgx.Tx, reportID, orgID, clusterID uuid.UUID, namespace string) ([]reportedService, error) {
	rows, err := tx.Query(ctx, `
		SELECT i.service,i.service_uid,p.protocol,p.service_port,l.labels,COALESCE(l.truncated,false)
		FROM k8s_service_inventory_items i
		JOIN k8s_service_inventory_ports p ON p.report_id=i.report_id AND p.inventory_ref=i.inventory_ref
		LEFT JOIN k8s_service_inventory_item_labels l ON l.report_id=i.report_id AND l.inventory_ref=i.inventory_ref
		WHERE i.report_id=$1 AND i.org_id=$2 AND i.cluster_id=$3 AND i.namespace=$4
		ORDER BY i.service,p.protocol,p.service_port`, reportID, orgID, clusterID, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportedService
	for rows.Next() {
		var service, uid, protocol string
		var port int32
		// labels is NULL when the report carried none for this Service: unknown, not "no labels".
		var labels map[string]string
		var truncated bool
		if err := rows.Scan(&service, &uid, &protocol, &port, &labels, &truncated); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Service != service {
			out = append(out, reportedService{Service: service, UID: uid, APIServer: IsAPIServerService(namespace, service),
				LabelsKnown: labels != nil, LabelsTruncated: truncated, Labels: labels})
		}
		last := &out[len(out)-1]
		last.Ports = append(last.Ports, inventoryExposurePort{Protocol: scopeapproval.Protocol(protocol), Port: port})
	}
	return out, rows.Err()
}

func exposedNamespacePorts(ctx context.Context, tx pgx.Tx, orgID, clusterID uuid.UUID, namespace string) ([]exposedPort, error) {
	rows, err := tx.Query(ctx, `
		SELECT s.id,s.name,s.protocol,COALESCE(s.port_low,0),host(s.vip),e.rule_id,e.missing_since
		FROM k8s_services s
		LEFT JOIN k8s_namespace_rule_exposures e ON e.service_id=s.id
		WHERE s.org_id=$1 AND s.cluster_id=$2 AND s.namespace=$3 AND s.deleted_at IS NULL
		ORDER BY s.name,s.protocol,s.port_low,s.id`, orgID, clusterID, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposedPort
	for rows.Next() {
		var row exposedPort
		var ruleID *uuid.UUID
		if err := rows.Scan(&row.ID, &row.Service, &row.Protocol, &row.Port, &row.VIP, &ruleID, &row.MissingSince); err != nil {
			return nil, err
		}
		if ruleID != nil {
			row.RuleID = *ruleID
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func queryStrings(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

// namespaceRuleByService maps live exposures to the namespace rule that created them. serviceID
// uuid.Nil = every exposure of the organization.
func (s *Service) namespaceRuleByService(ctx context.Context, orgID, serviceID uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.service_id,e.rule_id FROM k8s_namespace_rule_exposures e
		JOIN k8s_services s ON s.id=e.service_id
		WHERE e.org_id=$1 AND s.deleted_at IS NULL AND ($2::uuid IS NULL OR e.service_id=$2)`, orgID, pgUUID(serviceID, serviceID != uuid.Nil))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]uuid.UUID{}
	for rows.Next() {
		var service, rule uuid.UUID
		if err := rows.Scan(&service, &rule); err != nil {
			return nil, err
		}
		out[service] = rule
	}
	return out, rows.Err()
}

// NamespaceRuleForService returns the namespace rule that created one exposure, or uuid.Nil.
func (s *Service) NamespaceRuleForService(ctx context.Context, orgID, serviceID uuid.UUID) (uuid.UUID, error) {
	rules, err := s.namespaceRuleByService(ctx, orgID, serviceID)
	return rules[serviceID], err
}

// namesPreview lists up to limit names and says how many more there are.
func namesPreview(names []string, limit int) string {
	if len(names) <= limit {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:limit], ", ") + fmt.Sprintf(" and %d more", len(names)-limit)
}
