# K8L-8 — the operator's Ready must be true, and a resource removes only what it created

Story branch: `story/kubernetes-launch-fixes`. From the 2026-11-22 review of the Kubernetes features;
traced in code, then pinned with tests.

## What the operator is

An optional pod for teams that keep their setup in Git. It turns three kinds of resource into the
same control-plane calls the dashboard makes: `TunnexCluster` (register a cluster),
`TunnexExposedService` (expose one Service port), `TunnexGrant` (let someone reach it). It carries
no traffic; the in-cluster gateway does that.

## What was wrong

A team using it trusts `Ready=True`. It could be false in five ways.

1. **A second port.** The control plane keeps one exposure per Service port. The operator matched an
   existing exposure by cluster, namespace and name only, so a resource for port 443 adopted the row
   for port 80, reported Ready, and 443 was never exposed. Deleting either resource unexposed the
   shared row.
2. **Edits.** After the first create only provider and platform were reconciled. Changing the
   connector, the port or the grant's subject was accepted as Ready for the new generation and
   nothing changed. The dashboard withholds "Change connector" for operator-managed clusters and
   points people at the resource, so there was no way to replace a connector at all.
3. **Adopting what it did not create.** A cluster was adopted by name, and an exposure by Service,
   even when made in the dashboard. Deleting the resource then deregistered the cluster (with its
   Services and grants) or unexposed the Service.
4. **Grants were never looked at again.** Once a rule id was recorded the grant was "Ready, grant
   placed" forever — after the rule was deleted or switched off in the dashboard, after the Service
   was recreated under a new id, after `expiresAt` had passed.
5. **No re-check.** Kubernetes tells the operator when a resource changes, not when the control
   plane does. Out-of-band changes were noticed on the default ten-hour resync.

## Decision

1. **Identity of an exposure** is cluster, namespace, name, protocol and port. Two ports are two
   exposures.
2. **Ownership.** A resource that already holds a control-plane id confirms that row by id. One that
   does not may adopt a matching object only if the operator's credential created it
   (`managed_by_operator`) and no other resource already holds it. Otherwise it is `Ready=False`
   with `exists_outside_operator` or `declared_by_another_resource`, and it never deletes that
   object.
3. **Edits.**
   - `TunnexCluster.spec.connector` is applied through the control plane's change-connector call,
     with the resource as the audit cause.
   - Fields the control plane cannot change in place — a cluster's name, site, address range,
     Service network and DNS zone; an exposure's cluster, namespace, name, protocol and port; a
     grant's subject — give `Ready=False`, reason `spec_change_unsupported`, with a message naming
     the field and what is live. Address ranges are compared as networks.
4. **Grants are re-checked every pass.** Rule gone → recreated from the resource (with an Event).
   Rule pointing at a Service id that no longer matches → deleted and recreated. Rule switched off →
   `Ready=False`, `rule_disabled`. `expiresAt` in the past → `Ready=False`, `Expired`.
5. **Every Ready resource is re-checked every five minutes.**
6. **One operator at a time:** the Deployment uses `Recreate`, so an upgrade cannot run two pods
   that both create.

## Deliberately not done here

- Rejecting immutable edits at admission with CRD validation rules. It is the better experience
  (the edit is refused when applied), but it changes the CRD schema, whose chart has its own
  generation and downgrade guards. The controller-side refusal is correct on its own; admission
  rules are a follow-up.
- Scoping resources per namespace. Anyone who may create these resources in any namespace can still
  expose a Service in any namespace of the cluster; treat that permission as administrator-grade.
  To be stated in the operator guide.

## Proof

- Unit, against a fake control plane: a second port is exposed, not adopted; an edited exposure, an
  edited cluster range and an edited grant subject are not Ready and write nothing; a dashboard
  exposure and a dashboard cluster are not adopted, and deleting the resource calls nothing; a
  duplicate declaration names the first resource; a connector edit issues exactly one change with
  the resource as cause and none when it already matches; a removed rule is recreated; a rule for a
  recreated Service is replaced; a switched-off rule and an expired grant are not Ready; a healthy
  grant is re-checked on the timer. The earlier suite passes with fixtures updated for ownership.
- Chart contract test passes with the `Recreate` strategy.
- Live walk on the k3s cluster: recorded below when run.
