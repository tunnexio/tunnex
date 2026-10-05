# S02–S03: durable sandbox authorization and static scope projection

Decision paper before code; follows S-sandbox-foundation-decisions.md. Baseline main f6d4945; local foundation 593544c.

## Dispositions

- MVP policy scope is canonical IPv4 CIDR plus `any`, `tcp` or `udp` and bounded port range (0/0 means all ports). Static user/group resource grants and user/group site-destination grants are delegable. Agent grants, source-site/CIDR rules, dynamic FQDN and Kubernetes grants are not delegable in this slice. Empty or invalid input is default-deny. Restrict IPv6 until the runtime can qualify it.
- Effective scope is current creator entitlement intersect requested scope intersect immutable template cap. Recompile from current rules rather than persist entitlements. Admission rejects requested tuples that lack complete coverage by a single current entitlement and template tuple (conservative; unions are not accepted initially). Revocation can leave only the remaining intersected scope.
- Store the distinct sandbox entity and template revision, desired/observed state, generation, expiry and peer binding. Store no credentials in these records. Network peer kind is sandbox; its user_id retains attribution only. It must bind one-to-one to a same-org sandbox and same creating user. Existing human/agent queries and behavior are preserved. Enrollment wiring remains separate.
- Organization provisioning opt-in defaults false. Creation also requires enforcing policy, an eligible enabled template, verified active human member, explicit sandbox:create and quota reservation. Member/admin/owner receive self-service permissions; only owner/admin receive sandbox:admin and sandbox:template_manage. AI-specific/machine roles receive none. Admin management does not allow creator spoofing at creation.
- All service reads/actions recheck current membership. Creator reads/actions are relationally scoped; org-wide lifecycle administration requires sandbox:admin. Template caps are immutable; disabling a template withdraws grants at the next policy compilation. Requested scope and creator identity are immutable in this slice.
- Serialize quota/idempotency on the org row. Caller-scoped idempotency key stores a hash of the normalized create intent; mismatched retries conflict. Same request returns one record. Limits proposed: 2 nondeleted sandboxes/user, 20/org; templates set TTL up to 24h. These are stored defaults, not product-approved guarantees, and opt-in stays off.
- Store methods are internal until public API contracts are generated and audited. No live migrations or policy updates. Test on a disposable local database only. `Ready` cannot be set by a client action.
- Fail closed on mesh/off mode: prevent existing sandboxes from being admitted by this service, withdraw scope if mode changes. Database guards prevent mode changes to blanket mesh while sandbox cleanup remains incomplete. Runtime provisioning must additionally gate network reachability and gateway policy revision; compiler output alone is not readiness or direct-underlay isolation.

## Acceptance

Ordinary feature tests prove requested A from creator A+B yields A only; outside entitlement/template rejected; rule withdrawal stops projected access; disabled templates/expired records disappear from projection; legacy behavior remains. Real disposable PostgreSQL tests prove migration, creator/org immutability, binding integrity, concurrent idempotency/quota, cross-org/non-owner/machine refusal and generation conflict. Downgrade refuses to discard live sandbox state. Generated RBAC matches source. Full public provisioning stays disabled pending remaining stories.

## Follow-on boundary review

Adding a third peer kind exposes existing binary human/agent assumptions: human roster queries use kind<>agent and generic owner device lifecycle/mode/posture paths accept peers by owner. Before enrollment, tighten human roster predicates to kind=human and reject sandbox peers from those generic controls. Keep gateway peer/offboarding queries seeing all kinds. This is normal first-class feature compatibility work, not a continuation of the stopped audit. Prove separation using the actual database roster queries.
