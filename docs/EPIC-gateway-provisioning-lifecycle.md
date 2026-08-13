# EPIC — Gateway Provisioning & Lifecycle

Status: **registered / decision-first; no implementation authorized by this paper.**

**Roadmap boundary:** GPL-8 and GPL-9 are **post-beta roadmap** items. The beta scope does not
expand into continuous drift remediation, fleet capacity operations, or staged upgrade automation
until the Founder opens post-beta planning.

## Founder outcome

An owner may choose either an existing gateway or provision a Tunnex gateway inside the customer's
own cloud account from the Tunnex UI. Both modes converge to the same enrolled, monitored gateway
and work with Site Connectivity. Tunnex never becomes the owner of the customer's cloud account,
network, bill, or long-lived cloud credentials.

## Product modes

| Mode | Customer action | Tunnex responsibility |
| --- | --- | --- |
| Bring your own gateway | Select an existing VM/router or enroll it manually. | Enrolment, preflight, configuration evidence, health, upgrade guidance, validation, and safe retirement. |
| Provision with Tunnex | Select an existing customer VPC/VNet, subnet, region/zone, instance class, and optional HA count; approve the exact plan. | Generate a reviewed plan; customer-run connector executes it with temporary scoped credentials; enroll and monitor the created gateway. |
| On-prem | Provide an existing host/router and local network facts. | Same BYO flow. No cloud resource provisioning requirement. |

## Acceptance

1. Provisioning happens only in a customer-selected existing VPC/VNet and subnet. The UI shows
   resource count, public/private endpoint posture, IAM/RBAC permissions, expected billable
   resources, and exact rollback before approval.
2. Customer-run connector is the only cloud actor. It obtains short-lived, policy-scoped credentials
   from an optional customer Vault or another customer-approved identity source. CP stores no cloud
   credential, Vault token, secret lease value, or SSH key.
3. Every proposed change has a stable plan digest. The owner approves that digest once; a changed
   plan requires a new review and approval. Every provider mutation and its result is audited.
4. Provisioned gateways are tagged/labelled with customer-visible Tunnex ownership metadata and
   reconcile into the existing gateway health/desired-state model.
5. Health distinguishes VM/provider state, connector reachability, agent/reconcile state,
   WireGuard reachability, site-link state, and cloud-fabric forwarding. A healthy VM cannot make a
   tunnel or a behind-host path appear healthy.
6. Retire is two-stage: drain/rehome dependent devices and sites, prove no active dependency remains,
   then require an explicit typed confirmation before deleting customer-cloud infrastructure.
7. On-prem and BYO gateways remain first-class. Cloud provisioning is optional and unavailable
   provider capabilities are shown honestly, never as disabled-but-ready automation.

## Explicit non-goals

- No creation of a customer's whole VPC/VNet, peering, transit gateway, account/subscription,
  identity tenant, or general-purpose cloud resources in v1.
- No CP-to-cloud direct credentials, persistent access keys, customer SSH access, arbitrary shell
  command execution, or Docker socket access.
- No silent public IP, public inbound firewall, or delete action.
- No auto-upgrade or auto-cloud-route failover until their own safety/rollback stories are proved.

## Reuse and boundaries

- Existing gateway enrolment, desired-state reconciliation, health kinds, policy compatibility,
  certificate recovery, and revoke/delete protections remain authoritative.
- `EPIC-site-connectivity-experience.md` owns site CIDRs, cloud/on-prem fabric preflight,
  behind-host validation, and site link UX. This Epic supplies a gateway to that flow.
- The connector operates in the customer's environment. Its permission set is allow-listed per
  provider/action and it returns evidence, never raw credentials.

## Story map and proof ladder

| Story | Deliverable | Required proof before the next story |
| --- | --- | --- |
| GPL-0 | Decision record and lifecycle state model | Rule ownership, provider actor, plan-digest, billing disclosure, deletion, HA and rollback decisions; red forbidden transitions. |
| GPL-1 | Gateway inventory and ownership projection | UI/API distinguish BYO, provisioned, and on-prem gateways; no inferred cloud provider or cost; visual and RBAC proof. |
| GPL-2 | Reviewed provisioning plan | Existing-network selector, least-privilege action plan, cost/resource summary, plan digest, explicit approval and audit; cancel is zero mutation. |
| GPL-3 | Customer-run connector | Mutual identity, capability allow-list, Vault optional dynamic credentials, plan-digest verification, structured evidence, lease expiry/revocation, no-secrets persistence red. |
| GPL-4 | AWS provider implementation | Provision one gateway in a pre-existing VPC/subnet; provider preflight/red cases; source/dest, route, firewall and enrollment evidence; exact destroy rollback plan. |
| GPL-5 | Azure provider implementation | Same contract against a pre-existing VNet/subnet; NIC forwarding, UDR/NSG and enrollment evidence; exact destroy rollback plan. |
| GPL-6 | Lifecycle, HA and retirement | Provision HA pair, show overlay vs cloud-fabric HA truth, drain/rehome before deletion, deliberate provider delete only after typed confirmation. |
| GPL-7 | Box walks and runbooks | BYO/on-prem, AWS-provisioned, Azure-provisioned, failed preflight, denied approval, lease loss, agent failure, safe retire, and rollback on real customer-owned infrastructure. |
| GPL-8 | Fabric drift detection and remediation — **post-beta** | Provider facts are compared with approved intent; drift names the exact missing/changed rule or route; remediation is reviewed and never silently applied. |
| GPL-9 | Capacity, maintenance and release safety — **post-beta** | Gateway CPU/memory/peer/throughput/conntrack facts, drain mode, canary/ring upgrade plan, rollback evidence, and a redacted support bundle. |

## Required testing sequence

1. Pure lifecycle/state-machine tests: every transition, stale plan, expired lease, retry and
   cancellation path; no provider call from an unapproved state.
2. API/RBAC/audit tests: owner authorization, organization isolation, immutable plan digest,
   safe audit metadata, and secret absence from API/database/logs.
3. Connector contract tests: provider calls allow-listed by plan; altered plan or overbroad
   capability refuses; credential lease expires/revokes without affecting existing gateway traffic.
4. Provider fixture tests: created VM/NIC/security/route objects match the reviewed plan; each
   deliberate missing prerequisite reports the specific failure and leaves unrelated resources alone.
5. Live provider walk: first a red preflight, then a successful single gateway, enrollment,
   site-connectivity validation, connector outage, lease expiration, and rollback/destroy proof.
6. HA/retirement walk: prove no live device/site dependency is deleted; prove cloud resource delete
   requires the explicit final confirmation; prove cloud-route truth rather than claiming automatic
   end-to-end failover from an overlay promotion.
7. Drift/capacity walk: deliberately remove one approved cloud-fabric prerequisite and prove the
   exact drift report; drain one gateway, prove traffic uses the intended healthy path, then roll a
   canary upgrade before any fleet-wide change.

## Decide-items held for Founder ruling

1. **Provider order:** AWS first (recommended) then Azure, or both together. One provider must prove
   the connector contract before a second privileged integration expands it.
2. **Resource scope:** one gateway VM in a pre-existing network first (recommended), or optional HA
   pair in the first release.
3. **Cost source:** plan-time estimated provider cost only (recommended) versus live billing API
   integration; never claim an estimate is an invoice.
4. **Connector hosting:** customer-run container/agent beside the CP (recommended) versus a
   separately deployed customer runner. Tunnex-hosted cloud execution is refused.
5. **Deletion:** retain customer resources by default with a guided manual teardown (recommended)
   versus connector-driven delete after typed confirmation and drain proof.

## Completion condition

This Epic completes only when a customer can deliberately choose BYO, on-prem, or provisioned
gateway mode; see exactly what will be created or changed; approve it; prove the gateway and its
site path on the wire; and retire it without silently deleting live access or customer resources.
