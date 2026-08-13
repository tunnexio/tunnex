# EPIC 10 — Kubernetes Integration — commit-one (decisions before code)

**Status: HELD FOR RULING. Nothing built until the D3-ingress lean + this paper are ruled.**

Re-entered from `main` (`07579bf`) + `PLAN.md:1442-1450`. Decision-first per the story protocol.
The standing verify pass (four parallel investigations, file:line-grounded) precedes every decide-item
below — because the S9.1 re-scope taught that commit-one-first slicing collapses planned boundaries, and
here it collapses them in the OPPOSITE direction (the roadmap understates two stories and omits the one
genuinely-new concept).

## Verify pass — the substrate EPICs 8/9 already built (what K8s consumes)

1. **Subnet/policy (S8.1-8.5).** A Pod/Service CIDR maps to an approved `site_subnets` row →
   `dst_kind='site'` → a plain `AllowEntry{Dst: cidr}` (`enterprise/policy/compiler.go:416-433`),
   Option-A shape — **no new wire concept, no version bump**. A routed range falls out of
   `ListRoutedRanges` for free (`sites/routedranges.go:23`). A K8s **Service** (ClusterIP:port) is already
   a `resources` row (cidr:proto:ports, `0018_zero_trust.up.sql:51-65`). **Two deltas:** (A) a subnet is
   hard-coupled to ONE gateway (`nodes.site_id`, single-node v1) — a cluster is a many-node egress set;
   (B) `subnetguard.Check` (`subnetguard/subnetguard.go:33`) refuses overlapping default K8s CIDRs.
2. **Zero-touch (S3/S9.1).** A K8s gateway self-provisions by reusing enrollment VERBATIM: join-token →
   agent-generated RSA+WG keys → CSR → mTLS cert → `DesiredState` reconcile; server PKI via the D-S9.6
   `EnsureServerCert → DesiredState.OVPNServer → WriteServerMaterial(0600)` pattern. No secret hand-placed
   today. Three items Helm forces (D7).
3. **Identity/policy/edition (S7.x/S9.1).** The identity-binding invariant has THREE identical consumers
   (compiler `ListActiveDevicesForOrg` = reference, WG-peer roster, OVPN roster) — a shared JOIN gate
   (`active`/current-member/`NOT health_blocked`). `devices.user_id` is `NOT NULL REFERENCES users` ("no
   unowned peers", `0010_devices.up.sql:11`); `src_kind ∈ {group,user,site,cidr}` — **no severable
   non-human source principal.** Edition line clean: connectivity open (device/WG handlers ungated),
   governance enterprise (403 `edition_required`), default-OFF.
4. **Reconcile/agent (S3.1).** The operator reuses the reconcile DESIGN + seam interfaces (swap
   `ControlClient` for a CRD watcher, keep `WGBackend`). The node-agent runs as a DaemonSet/in-cluster
   gateway **but only privileged** (NET_ADMIN + /dev/net/tun + hostNetwork + writable `ip_forward` sysctl +
   operator-supplied endpoint). **EPIC 10 is greenfield** — zero helm/operator/CRD/controller-runtime code.

**Re-scope headline:** S10.3 is ~80% existing rails (mostly plumbing); S10.1 is bigger than "a chart"
(it forces three real externalizations); S10.2 is the genuinely-new engineering (CRD layer + K8s
`ControlClient`); the one genuinely-new CONCEPT (workload-as-source-identity) is NOT in the roadmap's three
stories — it is an expansion fork, ruled OUT of EPIC 10 (D4) and registered.

---

## Decide-items

### D1 — What the integration IS — RULED
**(a) in-cluster gateway pod + (c) operator for lifecycle/CRDs. Sidecar REJECTED.** A sidecar-per-pod is
the workload-identity model wearing a deployment costume — inconsistent with D4(a) and it does not fit the
gateway abstraction. The node-agent already runs as a privileged pod cleanly. **Deployment-first** (one
egress = one site, matches single-node `site_id`); **DaemonSet REGISTERED** as the multi-egress evolution
(Delta A).

### D2 — Zero-touch K8s form — RULED
**The Helm chart IS the one command** (`helm install … --set joinToken=…`); the gateway pod self-provisions
on the existing enroll→CSR→mTLS→`DesiredState` path verbatim. Join token supplied once as a Helm value →
K8s Secret → env (Delta E). Server material still arrives as desired state (D-S9.6). No hand-placed WG or
server keys. The Zero-Touch Gateway Law's K8s form: one `helm install`, zero SSH, no hand-placed secrets.

### D3 — Pod/Service reachability — EGRESS RULED, INGRESS LEAN (held for ruling)
Reuse the advertised-subnet + `resources` models unchanged (the B1-free instinct; roadmap-endorsed at
`PLAN.md:1450`).

**Egress (pod → outward) — RULED (ii): source-NAT the cluster behind the gateway.** Pods appear as the
gateway address; no Pod-CIDR advertisement, no collision. Egress NAT already exists (`egress_linux.go`).

**Ingress (client → in-cluster Service) — the verify + the lean.**

*Verify finding.* A client's route INTO the tunnel (`AllowedIPs`) is **pool + routed-ranges (= approved
site subnets), or full-tunnel `0.0.0.0/0`** (`devices/config.go:46-51`, `devices/service.go:373-377`).
**Resources never become client routes** — a `resource` is only the gateway-side forward-chain grant
target; the client must independently hold a route to send that traffic into the tunnel. Therefore reaching
an in-cluster Service DOES require its CIDR (or a superset) reachable as a routed range. `subnetguard` on
the defaults: the default Service CIDR **`10.96.0.0/12` CONTAINS the default device pool `10.99.0.0/24`** →
refused as `ClassPool` (`subnetguard.go:33`, pool default `nodes/service.go:52`). (A default overlay Pod
CIDR like `10.244.0.0/16` is typically disjoint and WOULD pass — but pods are not the ingress target;
Services are, and the Service CIDR is the one that collides.) **The collision returns on ingress.**

*Options.*
- **(I) Synthetic VIP range + per-Service /32 DNAT** — the ingress mirror of the egress-NAT ruling. Admin/
  operator picks ONE disjoint "service-VIP" range (passes `subnetguard` once), advertised as a routed
  range; each exposed Service gets a /32 VIP in it; the gateway DNATs VIP→ClusterIP; each VIP is a
  `resource` for grants. The client sees only the synthetic range — the colliding real Service CIDR is
  never advertised. Cost: a VIP↔ClusterIP map + DNAT programming + VIP allocation.
- **(II) Operator-renumbers the cluster Service CIDR** to a disjoint range, advertise natively. Cost:
  `--service-cluster-ip-range` is fixed at cluster creation — an EXISTING cluster cannot change it without a
  rebuild. Hostile to adoption.
- **(III) Service-as-resource via the gateway's own address** — expose each Service at `gateway-IP:port`,
  DNAT to the Service. Cost: port collisions on one IP; doesn't scale past a handful; loses per-Service
  identity. Zero new advertised range.

*Lean: (I).* Passes `subnetguard` once (never weakens the validator), never advertises the colliding real
Service CIDR, reuses `resource`+grant exactly (each VIP is a named resource — the Service-as-resource
instinct), works with ANY provider's default Service CIDR (portability), and is symmetric with the egress
ruling. **(III)** is (I) degenerated onto one IP — keep as the "few Services, no VIP range" shortcut.
**(II)** rejected as the default; kept only as a greenfield-cluster documented escape.

**D3(ii)↔D4(a) coupling (recorded so it is not a trap later).** NAT in BOTH directions collapses per-pod
attribution — a Service VIP maps to a kube-proxy-load-balanced pod set; which pod served a flow is invisible
at the gateway. This costs **nothing** under D4(a) precisely because pods are not policy subjects in v1. **If
ZTNA-for-workloads (D4(b)) is ever built, the NAT decision MUST be revisited** — per-pod identity needs
un-NAT'd attribution. Same coupling, both directions.

### D4 — Workload identity — RULED (a) scope-as-written; (b) REGISTERED with trigger
**Ruling: (a).** Pods egress through the gateway address-scoped; clients reach in to a Service-as-resource;
**no new identity, everything reused.** Workload-as-subject deferred OUT of EPIC 10.

**Registered: ZTNA-for-workloads.** The full argument, preserved verbatim (including the counter):

> The roadmap's three stories need no workload source identity (destinations + deploy + operator-management).
> The expanded option (b): a pod gets its own **service-account-bound severable principal** — the FOURTH
> consumer of the identity-binding invariant: FK-reachable like a user, the `active`/current-member/
> `NOT health_blocked` gate reproduced, CASCADE-severed on ServiceAccount/namespace delete, out-of-hash.
> A raw `src_cidr` grant would let a pod connect but SIDESTEP the invariant (nothing severs it on
> offboarding — the exact OVPN defect the third consumer fixed). A device-like row alone fails: it demands a
> human `user_id`. **Counter to weigh:** if the competitive wedge IS ZTNA-for-workloads (not "run Tunnex in
> k8s"), then (b) is the epic's point and belongs in.

Deferral reasoning (founder-ruled):
- **New principal class in a deployment epic = the smuggling pattern.** Every prior epic that introduced a
  principal (users, devices, sites) gave it its own commit-one. The invariant was only just unified across
  three consumers (S9.1); adding a fourth in the Helm-chart epic is exactly what commit-one-first exists to
  prevent.
- **The wedge doesn't require it.** Tunnex's differentiation is sovereign self-hosted site-to-site + a
  migration path off Pritunl. "Run Tunnex in my cluster and expose services to my workforce" serves that.
  "Govern pod-to-pod egress with per-workload identity" is a different product, a segment with different
  competitors, and nobody has asked for it.
- **Beta is two epics out.** A severable non-human principal (FK-reachable, membership-gated,
  CASCADE-severed, out-of-hash) is a multi-sitting story with its own review arc.

**Named trigger:** a design partner or prospect asking for governed pod-level egress. If it fires, it is the
strongest signal yet about which product is being built.

### D5 — Edition line — RULED
Connectivity open, governance enterprise. **Open:** the Helm chart, gateway connectivity, Service-as-resource
reachability (site/subnet/resource are CORE, D11, `site_handlers.go:18`). **Enterprise, default-OFF,
unlock-then-opt-in:** ZT governance of that traffic — grants, any policy-bearing CRD, and workload-subject if
D4(b) is ever built. The operator BINARY is deployment tooling (open); a CRD that expresses a **grant** gates
`edition_required` at parity with the API.

### D6 — Ledgered bindings K8s must NOT break — CONFIRMED (guardrails)
- **Identity-binding invariant.** Under D4(a) there is NO fourth consumer — pods reach out address-scoped, no
  identity claim (itself an argument for (a)). Under D4(b), the workload MUST be the fourth consumer
  (reproduce the JOIN gate, CASCADE-sever), never an `src_cidr` sidestep.
- **Disjointness (`subnetguard`).** Every advertised K8s CIDR PASSES the validator. Delta B is resolved by
  NAT (D3), never by weakening or bypassing the validator.
- **Zero-config golden.** Every K8s artifact contribution is content-derived / out-of-hash (rides WITH
  routes, like `PoolCIDR`/DNS forwarding) so a non-K8s org's compiled artifact stays byte-identical.
- **Honest-health.** The in-cluster gateway reports via `ReportWGInfo`/`PolicyHealth`; privileged-pod
  prerequisites surface as honest refusals (à la `ovpn_binary_absent`), never silent failure (see Portability
  #3).

### D7 — The externalizations S10.1 forces — CONFIRMED as real content
"Helm chart" ≠ trivial YAML. S10.1's real content is three externalizations:
- **Master key.** Today volume-only (`secrets.LoadOrInit(dir)`, `secrets.go:52`); an ephemeral pod can't lean
  on a volume-persisted key. **Security condition (ruled):** support a **file-mounted secret as the PREFERRED
  path** (a projected Secret volume — the SAME shape the current volume-persisted key already expects), with
  `TUNNEX_MASTER_KEY` env as the DOCUMENTED FALLBACK. Rationale: env leaks through process listings, crash
  dumps, and `kubectl describe` on the pod spec; a mounted file does not. State the posture in the paper/chart.
- **External store.** `TUNNEX_DATABASE_URL`/`TUNNEX_REDIS_URL` URL-wins + **validate-never-generate** (managed
  DB/Redis; fail-loud on unreachable). Ledgered (`docs/S6.6-decisions.md:145`), not built.
- **Token delivery.** Helm value → K8s Secret → consumed once via `IssueJoinToken` (replacing the human paste).

### Sequencing — RULED
**S10.1 (Helm + the three externalizations) → S10.3 (gateway on existing rails, proves value cheapest) →
S10.2 (operator + CRDs, the most net-new, automates what the gateway proved).** Gateway before operator.

---

## Portability (stated design property + four variance points)

**Stated property: ZERO cloud-provider API dependencies.** Verified — no AWS/Azure/GCP SDK or
metadata-endpoint deps in `apps/node` or `apps/api` go.mod. The gateway self-provisions from the join token +
operator-supplied endpoint; it never calls a cloud control plane. Tunnex-in-K8s runs identically on
EKS/GKE/AKS/on-prem/k3s — no per-cloud integration. First-class differentiator; must not regress.

1. **CNI address model.** VPC-CNI (EKS, Azure-CNI) gives pods real VPC IPs; overlay CNIs (Flannel/Calico/
   kubenet) give cluster-internal IPs. **Service exposure is CNI-AGNOSTIC** — the gateway reaches ClusterIP via
   in-cluster kube-proxy regardless of CNI. Pod-CIDR advertisement WOULD vary by CNI (VPC-CNI real IPs may
   collide with the VPC/other sites) — v1 sidesteps this by exposing Services, not pods (a D4(b) concern).
2. **Default Pod/Service CIDRs per provider.** EKS Service `10.100.0.0/16`; GKE `~10.x`; AKS kubenet Service
   `10.0.0.0/16` / Pod `10.244.0.0/16`; Azure-CNI pods on the VNet. Collisions with the pool/sites are
   UNPREDICTABLE across providers. **The D3(I) VIP-DNAT design makes this MOOT** — the real Service CIDR is
   never advertised, so its value is irrelevant. Portability win, and a second argument for (I) over renumber.
3. **Privileged-pod policy — FIRST-CLASS FINDING.** The gateway needs NET_ADMIN + /dev/net/tun + hostNetwork +
   a writable `ip_forward` sysctl. Against PodSecurity Standards: a "restricted"/"baseline" PSS namespace
   BLOCKS all of these; **GKE Autopilot forbids privileged/hostNetwork/NET_ADMIN entirely (hard block).**
   EKS / GKE-standard / AKS default namespaces allow it; a hardened (PSS-restricted) cluster refuses.
   **Disposition — honest documented prerequisite, NEVER silent failure:** the Helm chart DECLARES the
   requirement (a privileged-capable namespace / PSS exemption); on a blocking cluster the install FAILS LOUD
   with the prerequisite named. **GKE Autopilot = documented UNSUPPORTED for the in-cluster gateway** (honest
   refusal — the S8.6b Windows-full-tunnel-refusal precedent). This is the honest-health discipline applied to
   the deploy surface.
4. **Per-cloud fabric — PD-4 gains a K8s section.** The existing "Cloud fabric setup — one console visit per
   side" panel (`web/pages/Sites.tsx:455`) gains a K8s subsection: (a) a privileged-capable namespace, (b) the
   operator-supplied external endpoint (a LoadBalancer/NodePort exposing the gateway's WG `:51820` — the
   cloud-fabric step the client reaches the gateway through), (c) the disjoint synthetic VIP range. Honest
   "why a Service may not reach yet" parity with the existing behind-host text.

**No parity-scoping.** The bar is cloud-agnostic + honestly documented + same-engine-governed — NOT
NetBird/competitor feature-matching. Any competitor capability that looks load-bearing for a K8s buyer
surfaces as a NAMED CANDIDATE with its customer problem, not as parity scope. (None identified as
load-bearing beyond scope-as-written at commit-one; the privileged-pod prerequisite (#3) is the nearest
adoption blocker and is dispositioned honestly above.)

---

## Greenfield module discipline
First EPIC-10 commit adds a new Go module (`apps/operator` + controller-runtime/client-go). The module-path /
`GOFLAGS=-mod=readonly` guard and the both-editions build guard apply (module path `github.com/tunnexio/...`
≠ repo `iotunnex/tunnex`; `-mod=mod` breaks fresh clones — see the Makefile/go.mod GUARD notes).

## Slice cut — DEFERRED until D3-ingress is ruled
S10.1 → S10.3 → S10.2 is set, but the S10.3 gateway design hinges on the ingress ruling (VIP-DNAT vs the
alternatives). Slices are cut after this paper is ruled. Nothing built until then.

---

## Fork rulings (founder, 2026-07-25) — D3-ingress + Fork 2 + the DNS sub-item

### D3-ingress — RULED (I) VIP-DNAT
The ruling is settled by **(II)'s impossibility, not (I)'s elegance**: `--service-cluster-ip-range` is
immutable on a running cluster, so renumber-as-default means "works only on clusters you build for us."
(III) gateway-IP:port stays the DOCUMENTED SHORTCUT for a handful of Services. Four conditions, each borrowed
from a precedent this codebase already has:

1. **VIP range is allocator-known + `subnetguard`-validated** — same treatment as the OVPN transit subnet
   (D-S9.5): disjoint from the pool, every site subnet, AND other clusters' VIP ranges. Never a hardcoded
   default that collides in eighteen months.
2. **VIP↔ClusterIP mapping is DESIRED STATE** — CP-owned, agent reconciles, re-asserted every tick, swept on
   removal. No side channel (the D-S9.6 pattern).
3. **VIP stability is an INVARIANT, not a convenience** — a VIP is bound to a Service identity for its
   lifetime; a deleted Service's VIP must not be immediately re-allocated to a different Service while grants
   referencing it may still exist (the reassignment trap — Feature 5's red + the pool-address re-allocation
   watched live in the EPIC-8 walk). **RULED: identity-resolution at compile** (founder's prior, agreed):
   an exposed Service is a **resource with a stable ID** (a DESTINATION, not a source principal — does NOT
   touch D4(a)/the identity-binding invariant); a grant references the Service's stable ID; the compiler
   resolves ID → CURRENT VIP at compile time. A deleted+recreated Service gets a new VIP and grants
   auto-follow the identity — no quarantine timer, matching how the device-source ruling (Feature 5) handles
   the same hazard. Quarantine-freed-VIPs is the rejected alternative (timer complexity for no gain once
   grants track identity).
4. **Service removal is a FULL SWEEP** — VIP freed, DNAT rule gone, and any grant referencing it compiles to
   nothing with the HONEST surface, not a silent no-op (the `cidr_outside_org_ranges` precedent — surface a
   typed "service no longer exposed" state).

**DNS sub-item (name it before slicing) — RULED into S10.3.** Service-name→VIP reuses the S8.4 cross-site DNS
forwarding rail as a gateway DNS-REWRITE: a `dns_forwarding` entry points the cluster zone at the gateway's
own resolver IP; the gateway forwards to in-cluster CoreDNS and rewrites the ClusterIP answer → the Service's
VIP, from the same desired-state VIP map that drives DNAT. CoreDNS stays authoritative for names; only exposed
Services (with a VIP) rewrite to a routable answer (self-gates on exposure, honestly). Incremental on the
existing forwarder + the VIP map → an S10.3 SUB-SLICE, not its own story. The one new mechanism is the
response-rewrite mode; if it grows during build, halt-and-surface.

### Fork 2 — RULED: accept GKE-Autopilot-unsupported at v1, documented honestly
Reasons: (a) the requirements are INHERENT — a kernel-datapath VPN gateway needs NET_ADMIN + /dev/net/tun;
the userspace alternative (wireguard-go + userspace networking) is a SECOND data-plane engine in the
most-verified component = the rejected tier by standing ruling; (b) buyer-fit INVERTS — Tunnex's wedge is
sovereignty/self-hosting; Autopilot users deliberately outsourced their infra layer to Google, the opposite
posture; (c) the honest-limitation precedent (S8.6b Windows full-tunnel) is exactly this shape and it worked.
Conditions:
- The chart PREFLIGHTS and FAILS LOUD at install with a specific message naming the missing capability —
  never a pod that crash-loops (the refuse-loudly law at the PACKAGING tier).
- The unsupported set is documented UP FRONT alongside the NAT-traversal honesty, not in a footnote.
- Trigger registered: a real prospect on Autopilot OR a PSS-restricted mandate. If it fires, it reopens as its
  own story with the userspace-datapath question properly papered.

---

## Slice cut — S10.1 → S10.3 → S10.2 (gateway before operator)

**S10.1 — Helm chart + the three externalizations (the real content; "chart" is the small part).**
- Slice 1: **master-key externalization** — file-mounted secret PREFERRED (projected Secret volume, the shape
  `secrets.LoadOrInit(dir)` already expects), `TUNNEX_MASTER_KEY` env as documented fallback (env leaks via
  process listing / crash dump / `kubectl describe`). Posture stated in chart + paper.
- Slice 2: **external-store wiring** — `TUNNEX_DATABASE_URL`/`TUNNEX_REDIS_URL` URL-wins + validate-never-
  generate (fail-loud on unreachable); bundled pg/redis move behind a compose profile when URLs are set.
- Slice 3: **programmatic join-token delivery** — Helm value → K8s Secret → consumed once via `IssueJoinToken`.
- Slice 4: **the chart itself** — CP Deployment (api/web/nginx) + values (secrets/ingress/storage), sharing the
  install.sh env contract verbatim (no divergence, `docs/S6.6-decisions.md:157`). Preflight for the CP tier.

**S10.3 — in-cluster gateway (on existing rails).**
- Gateway Deployment (privileged: NET_ADMIN + /dev/net/tun + hostNetwork + ip_forward init) with the
  chart PREFLIGHT (Fork-2 fail-loud); Autopilot/PSS-restricted = honest UNSUPPORTED refusal.
- `BindNode` the in-cluster agent to a site; VIP range allocator-known + `subnetguard`-validated.
- VIP↔ClusterIP map as desired state; per-Service /32 VIP DNAT; exposed-Service-as-resource (stable ID,
  identity-resolution at compile); full-sweep on removal.
- DNS-rewrite sub-slice (Service-name→VIP via the S8.4 forwarder + VIP map).
- PD-4 K8s fabric section (privileged namespace, external endpoint LB/NodePort for WG:51820, VIP range).

**S10.2 — operator + CRDs (enterprise; the most net-new).**
- New Go module `apps/operator` (controller-runtime/client-go; module-path + `-mod=readonly` + both-editions
  guards apply).
- CRDs `TunnexPeer`/`TunnexRoute`; a K8s-resource `ControlClient` reusing the S3.1 reconcile DESIGN
  (dual push+ticker, full-resync, never-touch-dataplane-on-CP-error).
- A grant-bearing CRD gates `edition_required` at parity with the API (D5).

Build proceeds S10.1 Slice 1 first. Sha-first gates, halt-and-surface, tail-of-turn review on the
privileged/security-adjacent surfaces (master-key handling, the gateway securityContext, the preflight).

---

## S10.1 build record

- **Slice 1 (master-key externalization)** — DONE (`958d2ed`), both editions + security-reviewed clean.
- **Slice 2 (external-store URL-wins + fail-loud validation)** — DONE (`d4bbeeb`).
- **Slice 3 (join-token delivery) — RELOCATED to S10.3. Recorded as TWO facts (not re-openable):**
  (a) programmatic join-token issuance ALREADY EXISTS — `IssueJoinToken` (`node_handlers.go:90`) is a
  `POST …/nodes/join-token` returning a single-use token, machine-callable via session or `tnx_` bearer.
  The externalization the paper flagged is SATISFIED, not deferred. (b) The token is a GATEWAY input, so
  its chart-side plumbing (Helm value → Secret → env) belongs to the tunnex-gateway chart (S10.3). **S10.1's
  Go content is therefore complete at Slice 2.**
- **Slice 4 (CP Helm chart)** — DONE. `deploy/helm/tunnex-cp/` (control plane only; the gateway is the
  separate tunnex-gateway chart, S10.3). Five conditions encoded:
  1. Agent mTLS port 8443 = a raw L4 Service (LoadBalancer/NodePort), NEVER a terminating Ingress —
     cert-pinning + SNI=tunnex-control would break; NOTES names it the most likely misconfig.
  2. Master key REQUIRED, NEVER generated — `required` fails install with a named message; projected
     read-only Secret volume (file, not env); comment/NOTES the orphan-on-upgrade reasoning.
  3. Migrations = a pre-install,pre-upgrade HOOK Job (cmd/migrate), once, never raced; api pods run
     TUNNEX_AUTO_MIGRATE=false; api Deployment strategy=Recreate so schedulers never overlap.
  4. api.replicas=1 DELIBERATE (in-process schedulers); HA registered — trigger = HA-CP customer, real fix
     = leader election for the scheduler loops.
  5. **SUBSTITUTE (≠ SATISFIES):** `helm lint` + `helm template` render are the local gates (both green);
     a real `helm install` on a live cluster is the OWED wire proof — trigger = the EPIC-10 walk.

**Chart boundary (shapes S10.3):** `tunnex-cp` = control plane; `tunnex-gateway` = the in-cluster
gateway + join token. Two charts, one repo, shared values conventions.
