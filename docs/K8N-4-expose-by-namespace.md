# K8N-4 — expose every Service in a namespace

Story branch: `k8n/namespace-expose` (from `story/kubernetes-next`). Not one of the four items in
`docs/EPIC-kubernetes-next.md`; it comes from customers with many Services.

## What happens today

An administrator exposes Services one at a time.

- **Dashboard:** Kubernetes → a cluster → Expose service. The dialog lists what the in-cluster
  gateway reported, the administrator picks one Service and its ports, and the control plane creates
  one exposure per port (`ExposeInventoryService`).
- **Operator:** one `TunnexExposedService` resource per Service port.

A team with fifty Services repeats this fifty times, and again for every Service added later.

What already exists and is reused here:

- **The gateway reports the cluster's Services.** Every 30 seconds the active in-cluster gateway
  sends the full list (namespace, name, each TCP/UDP port) to the control plane, which stores it as
  an immutable snapshot (`k8s_service_inventory_reports/_items/_ports`). A snapshot is "current"
  only for 90 seconds and only from the gateway that fronts the cluster. A cluster with more than
  500 Services reports nothing at all.
- **An exposure** is one row in `k8s_services` per Service port. All ports of one Service share one
  address from the cluster's range. Removing an exposure keeps the row (soft delete) so rules that
  point at it stay readable.
- **`managed_by_operator`** marks rows created with the operator's credential. The operator adopts
  and removes only those (K8L-8).

## Decision

A **namespace rule**: "in this cluster, expose every Service in namespace N". The control plane
keeps the rule and applies it each time the gateway reports.

### Where the automation lives: the control plane

The control plane already receives the full Service list and already has the one code path that
turns a reported Service into exposures. The rule is a small table and a function that runs after
each accepted report. Nothing new is installed in the cluster, dashboard users get it without the
operator, and it is tested against a database with seeded reports, no cluster needed.

The alternative, operator-only, would need a new resource kind, new permission for the operator to
list Services, a second copy of the "which Services exist" logic, and would do nothing for teams
that use the dashboard. Rejected for this slice. A resource that lets Git declare a namespace rule
is a later slice (below); it would create the same control-plane rule, not a second mechanism.

### What a rule does

1. **Creating a rule** names one cluster and one namespace. There is no "all namespaces" and no
   wildcard. One rule per namespace per cluster.
2. **Never eligible:** `kube-system`, `kube-public`, `kube-node-lease`, `tunnex`, `tunnex-system`
   and any namespace whose name starts with `tunnex-`. Refused at creation and again by the database.
3. **On every accepted report** (and once when the rule is created) the control plane compares the
   namespace's reported Services with the exposures that exist:
   - a reported Service port with no exposure is exposed, and the rule is recorded as its maker;
   - a port that someone already exposed, in the dashboard or through the operator, is left exactly
     as it is. The rule does not adopt it, change it or remove it.
4. **All ports** of each Service are exposed (every TCP and UDP port the gateway reports). Choosing
   ports per Service stays a manual exposure.
5. **No fresh report, no action.** If the gateway is down or its report is stale, nothing is exposed
   and nothing is withdrawn; the rule shows `inventory_stale` or `inventory_unavailable`.

### Exposure never grants access

A rule only gives Services an address and a name. Nobody can reach them until an access rule allows
it, exactly as with a manual exposure. A rule creates no access rule. Where the organisation uses
cluster scopes, each automatically exposed port arrives as a *pending* review in every active scope,
the same as a manual exposure does; it is not approved automatically.

### When a Service disappears

Only exposures the rule itself created are ever withdrawn by it.

- When a rule-created exposure's Service port is missing from a fresh report, the row is marked
  "missing since". If it is still missing **10 minutes** later, the exposure is withdrawn. If it
  comes back sooner, the mark is cleared and nothing else changes. The wait exists because
  withdrawing cannot be undone (next point) and a Service that is deleted and recreated by a deploy
  should not lose its rules.
- **Access rules that pointed at a withdrawn exposure are kept, and allow nothing.** They show as
  pointing at a vanished Service on Access Policies. If the Service later returns it is exposed
  again as a *new* exposure with a new id; the old rules do **not** come back to life. This is the
  existing behaviour of removing an exposure, unchanged.
- A withdrawal is refused, as today, while an approved or pending agent access request or an agent
  policy template version points at the exposure. The rule then shows `withdrawal_blocked` and tries
  again on the next report.
- There is no label selector yet, so "stops matching" today means "no longer reported in the
  namespace". See "Not in this slice".

### Removing a rule

The administrator must choose one of two, and the dashboard states both before confirming:

- **Keep** — the rule stops; its exposures stay and become ordinary dashboard exposures.
- **Withdraw** — every exposure the rule created is withdrawn in the same step, with the
  consequences above. If any one cannot be withdrawn, nothing is changed and the reason is returned.

Removing one rule-created exposure on its own is refused (`managed_by_namespace_rule`): the rule
would expose it again thirty seconds later. Excluding single Services from a rule is not built.

### Limits fail closed, with a reason

For one rule in one pass, either every missing Service of the namespace is exposed or none is.

- **Address range full** → nothing new is exposed; the rule shows `vip_range_exhausted` with the
  number of Services waiting. Existing exposures are untouched.
- **Scope review limit** (more than 500 pending reviews from one Service, or a scope's membership
  limit) → same, `scope_review_limit`.
- **More than 500 Services in the cluster** → the gateway sends no report; the rule shows
  `inventory_unavailable`.
- **Per-plan limits:** no plan limits the number of exposed Services today, so there is none to
  enforce. If one is added it belongs in the shared exposure path, where a refusal is recorded on
  the rule like the two above.

The status is stored on the rule, returned by the API and shown in the dashboard: `applied` when the
last pass did everything, otherwise one of the reasons above (or `pending` before the first pass,
`error` for anything else, with the message). A rule whose last pass succeeded but whose cluster has
no current report is shown as stale, not as applied.

### Dashboard and operator do not fight

| Row made by | The rule | The operator | Dashboard |
| --- | --- | --- | --- |
| Namespace rule | exposes, withdraws | reports `exists_outside_operator`, never touches it | marked "Namespace rule"; Unexpose withheld |
| Operator (`managed_by_operator`) | never touches it | owns it | marked "Managed by GitOps" (unchanged) |
| Dashboard, by hand | never touches it | never touches it | unchanged |

A `TunnexExposedService` for a port a rule already exposed is therefore not Ready and says why. That
is K8L-8's rule, unchanged. The rule and the operator never write the same row.

### Who may do it

Creating and removing a rule needs `k8s:manage`, a verified email and a human session. It is the
same capability as exposing Services by hand, so no new permission. The operator's machine
credential cannot create a rule in this slice.

Every automatic exposure and withdrawal is written to the audit log as a system actor
(`k8s-namespace-rule`) with the rule's id as the cause; creating and removing a rule is audited with
the human.

## What is built

- Migration `0238`: table `k8s_namespace_exposure_rules`, and `k8s_namespace_rule_exposures`, which
  records which exposures a rule made and since when one is missing. `k8s_services` itself is not
  changed. A first draft added two columns to it; that broke the tests that run today's code against
  an older schema, because every query that reads an exposure would have named the new columns. A
  side table leaves the exposure row, the policy compiler's query and the operator's view of it
  exactly as they were. Removing a rule deletes its side rows, which is what "keep" means.
- `apps/api/internal/k8s/namespace_rules.go`: a pure planner (reported Services + existing rows →
  expose / mark missing / clear / withdraw) and the pass that applies it in one transaction per
  cluster. Manual and automatic exposure share one insert path.
- API: list, create and delete a rule; `namespace_rule_id` on an exposed Service.
- Dashboard: "Expose every Service in a namespace…" on a cluster's Services, a confirmation that
  states the consequences and needs a tick before it can be confirmed, the cluster's rules with their
  status, and a "Namespace rule" mark on rows (with Unexpose withheld). The action is offered to
  anyone who may manage Kubernetes, also on a cluster registered by the operator: the rule's
  exposures are separate objects from the operator's.

## Not in this slice

- **Label selector.** The gateway's report carries no labels. Adding them changes the report format
  (version 2), the gateway image and the stored snapshot; the rule then gains an optional selector
  and "stops matching" gains its second meaning. Next slice. Until then a rule is a whole namespace.
- **Operator resource** (`TunnexNamespaceExposure`) so a rule can live in Git. It needs a CRD
  version in `deploy/helm/tunnex-operator-crds`, with that chart's generation and downgrade guards,
  and lets a machine credential create a rule. It creates this same control-plane rule.
- **Excluding one Service** from a rule.
- **Recognising Tunnex's namespace when it was installed under another name.** The control plane is
  not told the gateway's namespace; the refusal is by name (`tunnex`, `tunnex-system`, `tunnex-*`).

## Proof

- Unit: the planner (new Service, existing manual and operator rows left alone, missing-then-back,
  missing past the wait, another rule's rows ignored) and namespace eligibility.
- Database-backed, seeded reports, no cluster: a rule exposes a namespace and nothing outside it; a
  later report adds a Service; a missing Service is withdrawn only after the wait and its access
  rule is kept; a full range exposes nothing and records the reason; operator and manual rows are
  not adopted or removed; removing a rule with keep and with withdraw; no fresh report means no
  change; manual unexpose of a rule row is refused.
- **Substitute, not satisfied:** nothing here ran against a live cluster. Trigger for the real
  proof: the next live Kubernetes walk on `story/kubernetes-next`.
