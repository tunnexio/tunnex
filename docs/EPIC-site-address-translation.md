# EPIC — Site Address Translation & Interoperability

Status: **post-beta roadmap / decision-first; no implementation authorized by this paper.**

This Epic must not start before the beta planning window reopens. Ordinary site CIDR overlap
continues to refuse during beta; this paper records the future alternative without weakening that
guard.

## Founder outcome

Two customer sites with overlapping private CIDRs can communicate safely without weakening
Tunnex's existing disjointness guarantees or fabricating reachability. The product must make the
translated identity, policy semantics, DNS behavior, observability, rollback, and operational cost
explicit.

## Why this is separate

The current site model correctly refuses overlapping advertised ranges. Address translation changes
what a packet's source/destination means at policy, routing, DNS, telemetry and audit seams. It is
not a UI option or a harmless route-table setting; it needs its own data-plane design and wire proof.

## Explicit non-goals

- No weakening of the global overlap refusal for ordinary site subnets.
- No automatic translation chosen from a private address range.
- No NAT that makes a policy/audit record claim the original address when enforcement saw another.
- No full-mesh arbitrary site NAT in v1.

## Story map and proof ladder

| Story | Deliverable | Required proof before the next story |
| --- | --- | --- |
| SAT-0 | Decision record and translation identity model | Rule alias CIDR allocation, collision rules, policy/audit/telemetry semantics, DNS mapping, and expand/contract migration. |
| SAT-1 | Overlap preflight and alternatives | UI identifies exact collision and offers BYO renumbering or an explicit translation plan; no acceptance path silently permits overlap. |
| SAT-2 | One-direction site translation | Gateway-only deterministic translate/reverse-translate with fail-closed policy and route semantics; red original/translated identity cases. |
| SAT-3 | Visibility and operations | Map, logs, flows, DNS and support bundle show both real and alias identity without leaking or confusing authorization facts. |
| SAT-4 | HA, rollback and box walk | Translation survives gateway promotion, is removed cleanly on rollback, and proves packets across deliberately overlapping real sites. |

## Completion condition

An operator can make an informed choice between renumbering and a narrowly scoped translation;
the selected path is auditable, policy-correct, observable, recoverable, and proven on real
overlapping networks.
