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
- With a label selector (slice B below) "stops matching" has a second meaning: the Service is still
  there but its labels, or the rule's selector, changed. It is handled exactly like a Service that
  is gone, wait included.

### Removing a rule

The administrator must choose one of two, and the dashboard states both before confirming:

- **Keep** — the rule stops; its exposures stay and become ordinary dashboard exposures.
- **Withdraw** — every exposure the rule created is withdrawn in the same step, with the
  consequences above. If any one cannot be withdrawn, nothing is changed and the reason is returned.

Removing one rule-created exposure on its own is refused (`managed_by_namespace_rule`): the rule
would expose it again thirty seconds later. To take one Service out of a rule, exclude it (slice A
below).

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

The rule itself has an owner too (slice C): a rule declared by a `TunnexNamespaceExposure` is edited
only through that resource, and the operator never touches a rule made in the dashboard.

A `TunnexExposedService` for a port a rule already exposed is therefore not Ready and says why. That
is K8L-8's rule, unchanged. The rule and the operator never write the same row.

### Who may do it

Creating and removing a rule needs `k8s:manage`, a verified email and a human session. It is the
same capability as exposing Services by hand, so no new permission. Since slice C the operator's
machine credential can too, for rules it declares (see below).

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

## Slice A — exclude one Service from a rule

Story branch: `k8n/expose-slices`. A rule carries a list of Service names it must not expose.

- **What is stored.** `excluded_services` on the rule (migration `0240`): Service names of the
  rule's namespace, each a Kubernetes name, no duplicates, at most 100. A name that matches no
  Service today is accepted, so a Service can be excluded before it is deployed. The 101st name is
  refused (`excluded_services_limit`); there are no patterns and no wildcards.
- **What an exclusion does.** The rule never exposes that Service. Exposures of it that the rule
  made are withdrawn on the next pass, and a pass runs as part of the change. There is **no
  10-minute wait**: the wait protects against a Service that a deploy deletes and recreates, and an
  exclusion is an administrator's stated decision, confirmed in a dialog that states the
  consequences. Everything else is the withdrawal a vanished Service gets: access rules that pointed
  at the exposure are kept and allow nothing; a withdrawal is refused while an agent access request
  or an agent policy template version points at the exposure, the rule then shows
  `withdrawal_blocked` with the Service's name and tries again on every report; the withdrawal is
  audited as the system actor with the rule as cause and reason `service_excluded`.
- **Like every pass, it needs a current report.** If the gateway is not reporting when the exclusion
  is saved, the exclusion is stored, the rule shows `inventory_stale` or `inventory_unavailable`,
  and the exposure is withdrawn on the gateway's next report. Nothing new is exposed in between
  either. *Rejected:* withdrawing without a report. It would be the only thing a rule does blind,
  and "no fresh report, no action" is easier to state and to trust than a rule with one exception.
- **What it does not touch.** An exposure of the excluded Service made by hand or by the operator
  stays exactly as it is. An excluded Service can be exposed by hand, with chosen ports; that is the
  way to have "the whole namespace, except this one I manage myself".
- **Taking a name off the list** exposes the Service again on the next pass, as a new exposure with
  a new id. Access rules that pointed at the old one do not come back.
- **`default/kubernetes`** stays never-exposed by a rule whether or not it is listed.
- **API.** `excluded_services` is optional when creating a rule and is returned on the rule.
  `PATCH …/namespace-rules/{ruleId}` replaces the list and returns the rule after the pass. Same
  gate as creating a rule: `k8s:manage`, verified email, human session. The change is audited with
  the human, naming what was added and removed.
- **Dashboard.** Each rule has "Exclusions…". The dialog lists what is excluded, lets the
  administrator add a Service of the namespace (those the rule exposes are offered; any name can be
  typed) or take one back, and states before confirming how many exposed ports will be withdrawn
  and what that does to access rules. Confirming needs a tick whenever something will be withdrawn.

## Slice B — label selector

A rule may carry a selector: `key=value` pairs, **all** of which a Service's labels must equal.
No selector means the whole namespace, as before. There is no set-based matching (`in`, `notin`,
`exists`), no negation and no wildcard; at most 8 pairs.

### The gateway reports labels: report version 2

- Version 2 of the Service report adds, per Service, `labels` and `labels_truncated`. Its digest
  uses a new prefix and covers both. Nothing else changes: same endpoint, same sequence, same 500
  Service and 4 MB limits.
- **Bounded.** At most 32 labels and 2048 bytes of keys plus values per Service, taken in key
  order. A Service with more is reported with what fits and `labels_truncated: true`. The worst
  case adds about 1 MB to a report, so a cluster that reports today still reports. Keys and values
  must have Kubernetes label syntax; the control plane refuses a report that breaks any bound.
- **The control plane accepts both versions.** A version 1 report is validated and stored exactly
  as before; one that carries labels is refused. Labels are stored beside the snapshot
  (`k8s_service_inventory_item_labels`, migration `0241`), one row per reported Service of a
  version 2 report, so the snapshot tables and everything that reads them are unchanged. **A Service
  with no row there has unknown labels**: that is what a version 1 report looks like.
- **New gateway, old control plane.** An old control plane refuses version 2 with the same 400 it
  gives every refused report. The gateway then sends the same Services as version 1 at once and
  keeps to version 1 for 20 reports (10 minutes) before trying version 2 again. So upgrading the
  gateway first does not lose the Service list. The cost is one extra request per report from a
  gateway whose reports are refused for another reason (a standby), and up to 10 minutes of
  "labels unknown" after a refusal that had another cause.
- **What leaves the cluster.** Until now the report carried names, UIDs and ports. From version 2 it
  also carries the labels of every reported Service in every namespace, because the gateway is not
  told which namespaces have a selector rule. Labels are not returned by any API and are not shown
  in the dashboard; they are read only to match selectors. *Rejected for this slice:* telling the
  gateway which keys are wanted. It needs a second channel to the gateway and makes a selector
  change wait for it. Founder to confirm that sending all Service labels is acceptable.

### Matching

For each reported Service of the namespace the rule decides one of three things:

| Labels known | Result |
| --- | --- |
| every selector pair is present and equal | **matches**: exposed like any Service of a plain rule |
| a selector key is present with another value, or absent and the labels are complete | **does not match**: never exposed; an exposure the rule made is treated as a Service that is gone (marked, withdrawn after 10 minutes, cleared if it matches again sooner) |
| labels unknown (version 1 report), or a selector key is absent and the labels were truncated | **cannot tell**: not exposed; an exposure the rule made is left exactly as it is |

"Cannot tell" never exposes and never withdraws, and it is visible:

- `gateway_too_old` — the cluster's gateway reports Services without labels. The message says to
  upgrade the gateway and that until then the rule exposes nothing new and withdraws nothing for
  label reasons. A rule with a selector never falls back to the whole namespace.
- `labels_incomplete` — names how many Services have more labels than the report carries and says
  to expose them by hand or exclude them.

A Service that is absent from the report is gone whatever the labels say, so the 10-minute
withdrawal of a vanished Service still works under both statuses. Exclusions are applied first and
do not depend on labels. `default/kubernetes` is never exposed, whatever its labels.

### Changing a selector

`PATCH …/namespace-rules/{ruleId}` takes `selector` (replaces it; `{}` clears it back to the whole
namespace). Services that now match are exposed on the pass that runs with the call. Services that
no longer match are **not** withdrawn at once: they get the same 10-minute wait as a relabelled or
deleted Service, which is also the administrator's window to put a mistyped selector right before
anything irreversible happens. *Rejected:* a separate immediate path for selector edits; one
"stops matching" rule is easier to state, and unlike an exclusion a selector edit can take out many
Services by accident. The change is audited with the human, with the selector before and after.

### API and dashboard

- `selector` is optional on create, returned on the rule, and accepted by `PATCH`. Two new values
  of `status`: `gateway_too_old`, `labels_incomplete`. Same gate as the rest: `k8s:manage`,
  verified email, human session.
- Dashboard: the create dialog has an optional "Only Services with these labels" field
  (`app=web, tier=frontend`) and states that Services which stop matching are withdrawn after 10
  minutes. With a selector the dialog gives no count of what will be exposed, and says so: the
  dashboard does not read labels. Each rule shows its selector and has "Selector…" to change it,
  with the same statement before confirming.

## Slice C — `TunnexNamespaceExposure`, the rule in Git

A fourth operator resource. It declares one namespace rule and the operator turns it into the same
control-plane rule the dashboard makes. It is not a second mechanism: the operator lists no
Services, exposes nothing itself and needs no new permission in the cluster beyond reading its own
resource kind.

```yaml
apiVersion: tunnex.io/v1alpha1
kind: TunnexNamespaceExposure
metadata: { name: shop, namespace: tunnex-gitops }
spec:
  cluster: prod              # name of the TunnexCluster resource in the same namespace
  namespace: shop            # the Kubernetes namespace whose Services are exposed
  selector: { app: web }     # optional; key=value pairs, all must match
  excludedServices: [admin]  # optional; exact Service names
  deletionPolicy: Keep       # Keep (default) | Withdraw
```

### What the control plane allows a machine credential to do

Until now only a signed-in human could create, change or remove a rule. Now the operator's machine
credential can too, under the same `k8s:manage` it already uses to expose Services one at a time.
It is the same capability reached from Git rather than a new one, so no new permission; founder to
confirm. The credential must have a current human owner, as for every other operator write.

- A rule made with a machine credential is marked `managed_by_operator` (column
  `managed_by_machine`, migration `0242`; the same marker clusters, exposures and access rules have).
- **A machine credential may change or remove only rules so marked.** Asked to touch a dashboard
  rule, the control plane answers 409 `rule_not_managed_by_operator`.
- **A human may not edit a marked rule** through the API or the dashboard (409 `managed_by_operator`:
  "change its TunnexNamespaceExposure resource"). The operator would put the edit back within five
  minutes; refusing it is the honest answer.
- **A human may remove a marked rule.** That is the way out when the operator is gone. The dialog
  says that the operator creates the rule again within five minutes if its resource still exists.
- Operator changes are audited as the system actor `operator:<credential>` with the resource as
  cause (`tunnexnamespaceexposure:<namespace>/<name>`). The exposures and withdrawals a rule then
  makes are audited as the rule's, as before.

### What the operator does (K8L-8's rules)

- **Ownership.** A resource that holds a rule id confirms that rule by id. One that does not looks
  for the cluster's rule for its namespace: none → it creates one; one marked `managed_by_operator`
  that no other resource holds → it adopts it; one made in the dashboard → `Ready=False`,
  `exists_outside_operator`, and the resource never changes or removes it; one another resource
  holds → `declared_by_another_resource`.
- **Edits.** `selector` and `excludedServices` are applied in place with one call, and have exactly
  the effect they have in the dashboard: an added exclusion withdraws at once, a Service that stops
  matching is withdrawn after 10 minutes. `cluster` and `namespace` are the rule's identity; the CRD
  refuses an edit when it is applied, and if one gets through the resource is `Ready=False`,
  `spec_change_unsupported`, naming what is live. Nothing is written.
- **Ready is the rule's own status.** `Ready=True` only while the control plane reports the rule
  `applied`. Anything else is `Ready=False` with the rule's status as reason
  (`vip_range_exhausted`, `gateway_too_old`, `inventory_stale`, `withdrawal_blocked`, …) and the
  control plane's sentence as message. The resource's status also carries the rule id and the counts
  of Services and ports the rule exposes and Services waiting. A rule that is not applied is
  re-read every minute, an applied one every five.
- **Drift.** A rule removed behind the operator's back is created again from the resource, with a
  `DriftHealed` Event. Its former exposures were kept or withdrawn by whoever removed it; kept ones
  are ordinary dashboard exposures now and the new rule does not adopt them.
- **Never eligible, refused three times:** by the CRD when the resource is applied (`kube-system`,
  `kube-public`, `kube-node-lease`, `tunnex`, `tunnex-*`), by the control plane, by the database.

### Deleting the resource: `deletionPolicy`

Deleting a rule has two outcomes and neither is implied. The resource states which:

- **`Keep` (the default).** The rule is removed; the exposures it made stay, as ordinary dashboard
  exposures. Nothing new is exposed afterwards.
- **`Withdraw`.** The rule and every exposure it made are removed in one step. If one cannot be
  withdrawn nothing is changed, the resource stays (`TeardownBlocked`, with the Service's name) and
  the operator retries.

**Why `Keep` is the default.** A resource is deleted for many reasons that are not a decision to cut
access: a Git revert, a pruning sync, a namespace clean-up, an operator uninstall, a mistake.
Withdrawing is the one outcome that cannot be undone (access rules that pointed at the exposures
are kept but never work again). Keeping grants nothing new and leaves an administrator able to
unexpose each Service by hand. So the destructive outcome has to be written down. The operator
records which one it carried out in an Event on the resource.

If the rule is no longer the operator's when the resource is deleted (its credential was replaced,
or the rule was removed and made again in the dashboard), the resource is released and the rule is
left alone.

### CRD and chart

- Schema validation at admission: namespace syntax and the never-eligible list, `cluster` and
  `namespace` immutable, at most 8 selector pairs with label-value syntax, at most 100 unique
  excluded names, `deletionPolicy` one of two values. `selector` is a flat map on purpose: a
  `matchExpressions` block cannot be written and silently dropped, which would turn a selective
  rule into a whole-namespace one.
- `deploy/helm/tunnex-operator-crds` gains the fourth CRD and moves every CRD to schema
  generation 2, so an older chart cannot be installed over it. The operator chart's role gains the
  new kind.

## Not in this slice

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

## Slices A, B and C as built

Branch `k8n/expose-slices`. Migrations `0240` (exclusions), `0241` (selector, Service labels beside
the snapshot), `0242` (the operator's mark on a rule).

- **A.** `excluded_services` on the rule; `PATCH …/namespace-rules/{ruleId}`; "Exclusions…" in the
  dashboard. The planner returns the rule's own exposures of excluded Services as a separate list
  that is withdrawn without the wait.
- **B.** Report version 2 with bounded labels (gateway: `apps/node/internal/control`, the watcher
  and the reporter with its fall back to version 1); `k8s_service_inventory_item_labels`; a
  three-way selector match in the planner; `gateway_too_old` and `labels_incomplete`; the selector
  on create and in "Selector…".
- **C.** `TunnexNamespaceExposure` (types, CRD, controller, chart at schema generation 2, role);
  the control plane accepts the operator's credential for rules it marks, and keeps people and the
  operator from changing each other's rules.

Decisions taken while building, for the founder to confirm:

1. An exclusion withdraws at once; a selector change withdraws after the 10-minute wait.
2. An exclusion saved while the gateway is silent is applied on the next report, not blind.
3. Version 2 reports send the labels of every reported Service to the control plane.
4. A selector is equality pairs only, at most 8; an exclusion list is at most 100 exact names.
5. A Service with more than 32 labels (or 2048 bytes of them) may be undecidable; it is left as it
   is and named, never guessed.
6. The operator's credential may manage namespace rules under `k8s:manage`, with no new permission.
7. A person can remove, but not edit, a rule declared in Git.
8. `deletionPolicy` defaults to `Keep`.
9. The CRD's selector is a flat map, not Kubernetes' `matchLabels`/`matchExpressions` shape.
10. The CRD chart moves to schema generation 2. The CRD does not validate selector *keys* (a map's
    keys cannot be pattern-checked without an unbounded CEL rule); the control plane refuses a bad
    key and the resource is then `Ready=False`, `invalid_selector`.

### Proof

- Unit: the planner with exclusions and with a selector (match, mismatch, unknown labels, truncated
  labels, the API server, another rule's rows); selector and exclusion validation; report version 2
  digest (one golden value shared by gateway and control plane), bounds and the refusal of labels
  on version 1; the gateway's sender (version 2, fall back to version 1 for 20 reports, no fall
  back on other failures); the watcher keeping and following labels.
- Database-backed, seeded reports: exclusion at creation and by edit, withdrawn at once and only
  the rule's own, access rule kept, blocked withdrawal named and retried, no report means no
  change; selector exposes only matches, relabelled Service withdrawn after the wait, selector
  change marks and a correction inside the wait clears, an old gateway exposes nothing and says so
  while a plain rule keeps working, a rolled-back gateway withdraws nothing, truncated labels left
  alone; operator-made rules marked, the two owners refused on each other's rules, a person's
  removal of an operator rule, a deleted credential; the store keeps labels only for version 2;
  migrations down and up with data.
- Operator, against a fake control plane: create with cause, no write when settled, Ready only
  while `applied` with the control plane's status and sentence otherwise, a dashboard rule never
  adopted or removed, adoption only of an unclaimed operator rule, edits applied in place, a
  namespace edit refused, a removed rule recreated but not over a dashboard one, each
  `deletionPolicy` with its Event, a blocked withdraw holding the finalizer, release when nothing
  of its own is left. The CRD manifest is read and its admission rules checked for presence.
- Dashboard: component and view tests for the three dialogs and the GitOps mark.
- **Substitutes, not satisfied.** Nothing ran against a live cluster: no gateway sent a version 2
  report to a control plane, no API server evaluated the CRD's CEL rules or its immutability, and
  no operator pod reconciled a real resource. Trigger for the real proof: the next live Kubernetes
  walk on `story/kubernetes-next`, which should include a gateway older than version 2 beside a
  selector rule.

### Gaps closed afterwards (branch `k8n/expose-gaps`)

Tests only; no behaviour changed.

- **`withdrawal_blocked` for a Service that is gone** (the exclusion case was already covered).
  Database-backed: a pending agent access request pins a vanished Service's exposure; inside the
  wait it is only marked; past the wait the rule shows `withdrawal_blocked` and names the Service,
  the exposure and its mark stay and nothing is audited as withdrawn; a later pass says the same;
  the pass after the request is closed withdraws it, audited once. A second test pins with an agent
  policy template version: only the pinned exposure stays, another vanished Service of the same
  rule is withdrawn on the same pass, and a Service that returns clears the block.
- **`scope_review_limit`.** Database-backed: 16 active cluster scopes and a Service with 32 ports
  (512 pending reviews, limit 500). None of the namespace's two missing Services is exposed, also
  not the small one the pass reached first; no exposure row, review or audit entry is kept; the
  rule records the status, the Service and the count waiting, on that pass and the next. With 31
  ports the next pass exposes both.
- **The operator's machine credential over HTTP.** Through the production router, its validator
  and `MachineAuth` reading a `tnxm_` token from the database: the operator creates, changes and
  removes its own rules (marked `managed_by_operator`, audited as `operator:<name>` with the
  resource as cause) and gets 409 `rule_not_managed_by_operator` on a person's rule; a person gets
  409 `managed_by_operator` on editing the operator's rule and may remove it; a machine credential
  without `k8s:manage` is 403 on every write; an unknown or revoked token is 401; another
  organization's operator is 404.
- **Still not satisfied: CRD admission.** No `kube-apiserver` or `setup-envtest` binary was on the
  build machine and none was downloaded, so the CRD's CEL rules, immutability and patterns are
  still checked for presence only. Trigger unchanged: the next live walk, or a CI job that has
  envtest binaries.

## Founder ruling, 2026-11-24

Operator ownership of namespace rules stays as built: a rule marked `managed_by_operator` may be
changed by any machine credential of the organisation that holds `k8s:manage`, not only the one that
created it. Binding a rule to one credential would orphan every Git-declared rule when the operator's
credential is rotated, which is the routine case; two operators in one organisation editing each
other's rules is the rarer case and is visible in the audit log, which names the credential.
