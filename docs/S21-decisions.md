# S21 — FQDN access resources: founder decision paper

**Status:** founder-approved decision record. The following D0–D9 values are
binding for S21 implementation.

## Re-entry and evidence

The authorized integration branch `story/S21-fqdn-access-resources` is clean and
equals `origin/main` at `6adef5688aaa8d1c7beee0f8f7aadce5d524deeb`.

The registration paper says EPIC 20 must finish and no S21 branch may exist, while
the founder has authorized this branch and evidence audit. This conflict requires
an explicit founder ruling; it is not silently reinterpreted.

Verified baseline facts:

- Resources are non-null static CIDR plus optional L4 protocol/ports, validated
  app-side (`apps/api/db/migrations/0018_zero_trust.up.sql:47-65`). The DB, SQL,
  generated clients, handler, CLI, and Access UI require a deliberate compatible
  contract migration, not an overloaded CIDR string.
- Referenced-resource deletion cascades rules (`0018_zero_trust.up.sql:71-90`),
  whereas the EPIC requires rendered impact and recovery. FQDN deletion must be
  refused or explicitly confirmed with recoverable, audited rule impact.
- The compiler is pure/deterministic (`apps/api/internal/policy/compiler.go:1-11`)
  and existing enforcement is L3/L4 default deny. DNS may supply addresses, never
  authorize a hostname; shared `IP:port` virtual hosts remain indistinguishable.
- Existing site `DNSForwards` are convenience-only, hash/version-blind
  (`apps/api/internal/policyspec/policyspec.go:322-328`; `hash_test.go:92-105`),
  not an FQDN lifecycle or authorization system.
- Client routing/DNS polling is fail-static (`apps/client/src/main/routedrangesmonitor.ts:33-48,101-160`)
  and policy content uses content-derived minimum versions
  (`apps/api/internal/policyspec/policyspec.go:190-206`). FQDN answer generations
  that change reachability must be in-hash and versioned.
- Policy read/write are `policy:view` / `policy:manage`, with the latter owner/admin
  (`apps/api/internal/rbac/rbac.go:20-25,172-231`); the current policy model is
  Enterprise-gated (`0018_zero_trust.up.sql:1-7`).

## Founder-approved dispositions

### D0 — start authority and scope

**Decision:** founder start of S21 is authorized despite historical registration
wording. Keep S21.7 native discovery and S22 L7 hostname isolation as non-goals.
EPIC 20 is complete enough for implementation.

### D1 — name contract

**Decision:** exact normalized FQDN only: lower-case IDNA ASCII with no stored
trailing dot. Wildcards, IP literals, URLs, ports, underscores, and empty labels
are rejected. A resource has exactly one destination kind: `cidr` or `fqdn`; the
existing CIDR wire behavior is unchanged.

### D2 — resolver authority and context

**Decision:** resolver context is server-selected Site/Gateway context. A
public/control-plane resolver is never a split-horizon substitute. An unbound
FQDN may be saved as a draft but never compiles. Context and selection audit are
visible to permitted operators.

### D3 — answer lifecycle bounds

**Decision:** CNAME depth is 8. There are at most 32 total canonical,
sorted/deduplicated A/AAAA answers. TTL floor is 30 seconds; ceiling is one hour;
jitter is ±10%; refresh occurs at 80% of effective TTL; last-known-good maximum
age is five minutes. A and AAAA are independently usable: reject only the invalid
family, but fail closed if neither usable family remains.

### D4 — failure and rebinding polarity

**Decision:** NXDOMAIN, SERVFAIL, timeout, resolver disagreement, overflow, or
last-good expiry withdraw the generation and deny new traffic. Reject loopback,
link-local, multicast, unspecified, documentation, and metadata ranges. Permit
public and RFC1918/ULA addresses only when returned by the selected resolver
context.

### D5 — enforcement and connection withdrawal

**Decision:** expand only the active generation into `/32`/`/128` L3/L4 allows
with resource protocol/ports; include it in the canonical hash and minimum version.
Retired answers are removed immediately and conntrack is flushed for those
destination tuples. Alternate IP inherits nothing; no shared `IP:port`
hostname-isolation claim.

### D6 — consumer and compatibility census

**Decision:** block S21.1 release until every Resource consumer is proven compatible
or explicitly deferred: groups/users/CIDR/Sites/Devices/AI Agents/JIT/templates/K8s
where applicable; API/OpenAPI/generated TS+Go/CLI/audit/flow logs/Test Access;
compiler/node agent/desktop/console. Use additive expand-contract migration with
tested rollback before removing old readers.

### D7 — entitlement, RBAC, and opt-in order

**Decision:** use distinct `fqdn_resource:view` and `fqdn_resource:manage`
permissions. FQDN enforcement is Enterprise enforcement and requires explicit
organization opt-in; it never auto-enforces or changes a rule. Ordered checks are
authenticated RBAC, entitlement availability, explicit org opt-in, then
mutation/compilation.

### D8 — routing, HA, and compatibility

**Decision:** FQDN answer generations are hashed, atomic, dual-stack, and require
a new content-derived policy version. Incompatible agents/gateways refuse loudly.
Distribute generations atomically to selected gateway/client paths; report
stale/incompatible/failed FQDN policy separately from tunnel/DNS health. Dual-stack,
reconnect, failover, and rollback converge by generation identity.

### D9 — truthful console and destructive recovery

**Decision:** Access owns resource CRUD/detail and rule selection. Show hostname,
resolver context, generation/count, TTL, last refresh/good, and resolving/healthy/
stale/failed/NXDOMAIN/permission states without fabricated health. Edit/delete shows
server-computed impact, confirms, audits intent/outcome, and has recovery. No browser
organization-wide sweep. Use the existing two-cloud live box walk plus
provider-neutral fixture proof.

## Approval gate

D0–D9 are founder-approved. Implementation must remain within these values; any
new product decision requires a separate founder disposition.
