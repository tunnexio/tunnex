# EPIC 15 — Zero Trust for AI agents

**REGISTRATION ONLY. No design, no schema, no commit-one.** Sequenced **after EPIC 14, before the beta
bundle**. Written while the thinking is fresh; everything below is measured against the live schema and the
RBAC table, not asserted.

---

# ⛔ CORRECTIONS — 2026-08-04. READ BEFORE THE PAPER.

**A registered paper gets re-entered and believed. This one carried a cost model its own measurement pass
refuted, so the corrections come before the argument, not after it.** Everything below is measured with a
citation; where a claim is still second-hand it says so.

⛔ **STATUS UNCHANGED: EPIC 15 is registered, paper-only, UNRULED.** No commit-one, no branch, no S15.x.
**D14, D4 and the sequencing question are held for the founder.**

## The three halves, measured

| half | verdict |
|---|---|
| **destination** | ⛔ **already shipped** — see the rewritten 3a. A port-scoped `resource` expresses an MCP server today |
| **audit** | **inherited, CONDITIONALLY** — see below. The condition binds D4 |
| **principal** | **the whole remaining epic**, and it converges on one column |

## The audit half — inherited, and the condition is binding

`src_device_id` is **agent-stamped from the compiled artifact's `/32`→device map**; the CP performs one FK
join to `src_user_id` (`apps/api/internal/accesslog/ingest.go:40-75`). Explicitly **not** an `src_ip` lookup —
that inference is refused deliberately, and the refusal is narrower than it reads: what is refused is
*deriving a person from an address*, not attribution as such.

⛔ **THE CONDITION: attribution works IFF the principal is a `/32` the artifact maps to a device.** A
principal shape that is not address-bearing goes dark on attribution **silently** — the flow log will not
complain. **This is a constraint on the principal design (D4), not a property of the audit layer**, and it is
exactly the kind of thing discovered in slice 2 after slice 1 shipped.

## ⛔ D14 IS REFRAMED BY MEASUREMENT, NOT BY ARGUMENT

**`machine_credentials` has no `user_id` column** (live schema: `id · org_id · name · role · token_hash ·
fingerprint · created_at · last_used_at · revoked_at`).

> ## **EVERY MACHINE PRINCIPAL SHIPPED TODAY IS ALREADY OWNERLESS. D14 IS NOT "PERMIT OWNERLESS AGENTS" —
> ## IT IS "KEEP THE OWNERLESS PRINCIPAL WE ALREADY HAVE."**

**And the mechanical argument, which replaces the philosophical one:**

> **An ownerless agent is outside the cap query, outside any delegation link, and STILL INSIDE THE POOL. It
> costs the scarce thing and escapes both accountable ones.**

**`devices.user_id` carries three loads at once** — the per-user device cap
(`apps/api/db/queries/devices.sql:98-104`), the posture cut's *"which human account launched it"*, and any
future delegation link. **One column, three questions, and D14 turns all three off together.** An ownerless
agent is therefore not a variant of the design; it is a different design.

⚠ **Delegation exists in NEITHER layer.** `audit_logs` carries `actor_user_id` and `actor_system` as
**parallel columns, not a chain** — an event is attributed to a human OR a subsystem, never *"this system
acting for that human"*. `X-Tunnex-Cause` (S10.2) supplies **which CR triggered this**: provenance of the
TRIGGER. Delegation is provenance of the AUTHORITY. **The operator has the first and not the second.**

## The posture cut — scorecard corrected

| the founder's cut | status |
|---|---|
| **which human account launched it** | ✅ persisted — `devices.user_id` |
| **which enrolment** | ✅ weakly — `devices.id` + `created_at` + `provisioning_mode`; no device-enrolment provenance table (`node_join_tokens` is for NODES) |
| **which host — server-observed** | ✅ **`devices.node_id`** — which gateway it actually attaches to |
| **which host — client-claimed** | ⚠ `platform` / `name`, client-supplied, and `platform` is **empty on 2 of 3 live rows** |
| **which host — attested** | ⛔ absent, and not addable by a column |

⛔ **`node_id` is the row that satisfies the founder's own cut** — *keep only what binds to a real credential*.
It is **server-observed, not client-claimed**. Anything stored about the machine itself is client-reported and
must carry the same label the existing posture surface already applies to itself. **State that; do not
discover it.**

## ⛔ §0's SLICE-ORDER RATIONALE, REWRITTEN AGAINST MCP `2026-07-28`

**Shipped 28 July 2026, after this paper was registered.** Stateless core; `initialize`/`initialized` retired;
`Mcp-Session-Id` removed; and **`Mcp-Method` / `Mcp-Name` are now REQUIRED headers**, explicitly so gateways
can route and meter **without parsing bodies**.

**The ordering survives. The cost model behind it does not.** This paper argued per-tool granularity is last
*because* every mechanism we own is L3/L4 and cannot see inside an MCP call. The first clause is still true;
the second is weaker, because the consequential fields are now in headers.

> ## ⛔ **THE EPIC'S FIRST NAMED LAW — THE HEADER TRAP.** `Mcp-Method` and `Mcp-Name` are **mirrored from the
> ## body, and the body remains authoritative.** A gateway that authorizes on `Mcp-Name` without checking it
> ## against the body **is authorizing on a client-supplied claim.**

That is `A GUARD MUST BE EXERCISED THROUGH THE STACK IT RUNS IN`, one protocol over — the throttle that read
`r.RemoteAddr` after `middleware.RealIP` had already replaced it with a caller-controlled header. Three tests
passed and the guard was inert. **Here the header is *designed* to look authoritative, which is worse.** The
mitigation is to state which artifact the decision is made from, and to red-prove that a header/body mismatch
is refused.

## AP2 IS NOT A THIRD PROTOCOL

Signed **mandates** carried *inside* A2A and MCP messages; donated to the **FIDO Alliance, April 2026**.
**It does not move money and has no wire of its own — there is nothing to route, nothing to terminate, no port
to police.** Scope collapses to **a policy predicate plus an audit field, and only in the L7 tier**.

⛔ **NO "AP2 SUPPORT" CLAIM.** A claim of supporting a payments protocol, made to a buyer who cannot check it,
is a **render-floor violation at product scale** — the SOC 2 badge cut in S14.17, one domain over.

## Competitive corrections

**Versa** brokers **Versa's own** infrastructure APIs — a governance layer for AI operating Versa, **not** a
general zero-trust layer for a customer's arbitrary MCP servers. Stop treating it as the same product shape.
**Tailscale shipped Aperture** — an **LLM** gateway that *extracts* MCP calls for **observability**, with
finer-grained MCP control still *"planned"*, **and it is SaaS**. ⭐ **The anchor of our category moved and has
NOT shipped enforcement** — the sovereignty wedge holds, and the window is real but not wide.

## EMA validates the slice order from inside the protocol

MCP's **Enterprise Managed Authorization** extension has the corporate IdP decide **which servers an agent may
connect to**, and **explicitly does not govern what the agent does once connected** — the admission/runtime
line drawn exactly where slice 1 draws it.
⚠ **SECOND-HAND.** Read from descriptions and one implementer's account, **not** the normative text in
`modelcontextprotocol/ext-auth`. **Read it before the paper relies on this.**

## ⚠ CARRIED AS UNVERIFIED — flagged, NOT quotable as fact

- **`/.well-known/` discovery** — never checked. Search the FETCH side, not only the path string.
- **`access_events` is empty** — one rig, one table, one moment. Does **not** establish the ingest path never ran.
- **No pool-utilisation surface** — established by ONE encoding. The sibling claim ("no resize surface") was
  already wrong. Re-check with `assigned_ip`, `ipalloc`, the overview counts.
- **`Principal.AuthMethod`** — unlocated, not absent.
- ⛔ **THE PASS ITSELF.** One session, one rig, one reader. **Its two sharpest corrections — `pool_cidr` is
  resizable, and `node_id` is the server-observed host — both came from a reader pushing back, not from a
  measurement.** Neither would have been found by measuring more. Read this paper against the dossier before
  ruling.

---

# ⛔ 0. THE BOUNDARY, FIRST — BEFORE THE PITCH, NOT AFTER IT

> ## **UNDER PROMPT INJECTION, AUTHENTICATION IS INTACT AND AUTHORIZATION IS INTACT. ONLY *INTENT* IS**
> ## **CORRUPTED. ZERO TRUST BOUNDS THE BLAST RADIUS OF A CORRECTLY-AUTHENTICATED PRINCIPAL. IT DOES NOT**
> ## **DETECT INJECTION.**

This sits in the opening rather than the caveats **because it is the sentence under the most pressure to
soften.** Every honest version of this epic says the same thing, and every marketing version is tempted to
imply the opposite — that a boundary *catches* the manipulated request rather than *limiting what it can
reach*.

⛔ **ANY COPY CLAIMING DETECTION IS A RENDER-FLOOR VIOLATION AT PRODUCT SCALE.** The render floor says a
surface must not state more than the system knows. A landing page claiming we detect prompt injection is that
same defect with a larger blast radius than any screen: it is a promise the product cannot keep, made to
people who cannot check it. **Treat it as the same class of error as a UI that renders a number the server
never computed.**

---

# 1. THE PROBLEM, STATED WITHOUT EMBELLISHMENT

MCP servers today are deployed either on **localhost** — safe because unreachable — or on the **public
internet behind a bearer token and nothing else**. There is no network boundary and no device identity
between those two positions.

An AI agent is a **non-human principal that runs unattended, at machine rate**, and that can be
**prompt-injected into asking for the wrong thing while remaining correctly authenticated**.

**Reported scale:** 1,800+ MCP servers exposed without authentication, and the Cloud Security Alliance
published an **Agentic Trust Framework (Feb 2026)** arguing agents need identity governance as rigorous as
human users'. See §0 for what this epic can and cannot claim about that.

---

# 2. INVENTORY — what already covers this, and how closely

**MEASURED against the live schema and `rbac.go`.**

| existing capability | serves an agent unchanged? | how close, honestly |
|---|---|---|
| **Machine credentials** (`machine_credentials`: name, fixed `role='operator'`, `token_hash`, `fingerprint`) | **CLOSEST — but no** | A first-class **non-user org principal** already exists, audits as `operator:<name>`, and is mintable/revocable. This is most of an agent identity. **See the defect below.** |
| **Audit with a system actor** (`actor_system`, `InsertSystemAuditLog`) | **YES** | Non-human attribution is already first-class and the metadata carries a CAUSE. S14.15 added two writers to it. Reusable as-is. |
| **Temporary grants** (`policy_rules.expires_at`, S7.5.4) | **YES** | Expiry on a rule already exists and already sweeps. An agent grant that dies in 30 minutes needs no new mechanism. |
| **Zero Trust rules** (`src_kind`, `dst_kind`, default-deny, deterministic compiler) | **STRUCTURALLY yes** | The model is right. The **vocabulary** is not: see §3. |
| **Gateway enrollment + device identity** | **YES** | Identity↔credential binding, full-sweep revocation, reconcile loop — all transport-agnostic. |
| **Posture** (`device_health_checks`, enterprise) | **PARTLY** | The mechanism fits; the **vocabulary does not** (§3). And it is explicitly *client-reported, not attestation* — an agent inherits that weakness, and inherits it worse. |

## ⛔ THE DEFECT IN THE CLOSEST THING WE HAVE

`machine_credentials.role` is **fixed at `operator`** at mint (D3), and the `operator` role holds
**`PermPolicyManage`**.

> ## **SO THE EXISTING NON-HUMAN PRINCIPAL CAN WRITE ITS OWN ACCESS RULES. For a GitOps operator that was**
> ## **the point. For an agent that can be talked into a request, it is the whole threat model inverted —**
> ## **a compromised agent grants itself what it was denied.**

**An agent principal must be a DIFFERENT role, not a reused one** — and the repo's own convention says so:
*permissions are named per feature; never reuse an existing perm for a new capability*. This is the single
largest "already covered?" correction in the inventory, and it was found by reading the grant table rather
than by assuming the closest thing fit.

---

# 3. WHAT IS GENUINELY NEW — the founder's three candidates, argued

## 3a · MCP server as a first-class RESOURCE TYPE — ⛔ **REFUTED BY MEASUREMENT. THIS HALF IS ALREADY SHIPPED.**

> **This section previously argued "AGREED, and the precedent already exists — COST: SMALL–MEDIUM." Both
> halves were wrong, and wrong in the expensive direction: it pointed the work at a migration.**

**A port-scoped `resource` already expresses an MCP server, with ZERO schema change.** The live `resources`
table carries `cidr` + `protocol ∈ {any,tcp,udp}` + `port_low`/`port_high` under live CHECKs
(`resources_check`, `resources_port_low_check`). An MCP server at `10.1.2.3:8080/tcp` is a `resource` with
`protocol=tcp, port_low=port_high=8080`, referenced by the existing `dst_kind='resource'`.

⛔ **AND A NEW `dst_kind` WOULD BE INVISIBLE TO ENFORCEMENT BY CONSTRUCTION.** `hashAllow`
(`apps/api/internal/policyspec/hash.go:15-21`) is exactly five fields — `{SrcIP, DstCIDR, Protocol, PortLow,
PortHigh}`. **`dst_kind` never reaches the compiled artifact.** By the time enforcement sees a destination it
is resolved addresses and ports; a `resource` and a hypothetical `mcp_server` are indistinguishable.

**THE `k8s_service` PRECEDENT CLAIM IS STRUCK.** `policy_rules` uses a **discriminator column per kind** under
an exclusive-arm CHECK (`policy_rules_check`: each `dst_kind` requires its own `dst_*_id` NOT NULL and the
other three NULL). So a new kind is **a new column + two constraint rewrites + compiler resolution +
goldens** — to add something enforcement cannot see. It is not "one enum value".

**NO VERSION BUMP, and the reason is structural rather than a pattern-match to `site`.** `RequiredVersion`
(`apps/api/internal/policyspec/policyspec.go:128-149`) triggers only on `VIPMappings`/`K8sDNSZones`→7,
`PoolCIDR`→6, `Routes` or a CIDR `SrcIP`→5, else **4**. A CP-resolved destination emits an `AllowEntry`
**byte-identical in shape** to a resource's — there is nothing for an old agent to fail to understand, so
there is nothing to refuse.

**REVISED COST: naming, ownership metadata and UI. Not enforcement machinery.**

## 3b · AGENT as a third device type — **AGREED on the type, ARGUE with the posture**

`devices.transport` is `CHECK (transport IN ('wireguard','openvpn'))`; a third value is a CHECK change plus a
provisioning path. Mechanically small.

**The posture vocabulary is the substantive part:** `disk_encryption` means nothing for an agent.

**COST: MEDIUM.** A CHECK value is trivial; the provisioning path, the credential binding and the posture
vocabulary are not. **SEQUENCE: SECOND.**

⛔ **AND THE FOUNDER'S OWN CANDIDATE LIST GETS CUT HERE, ON HIS RULING.** Existing posture is
**client-reported, not attestation** — already labelled that way on the screen that ships it. A laptop
misreporting its disk encryption is a user lying about their own machine. **An agent self-reporting WHICH
MODEL IT IS, is the principal we are worried about being manipulated, being asked to describe itself.**

> ## **KEEP ONLY WHAT BINDS TO A REAL CREDENTIAL: which human account launched it · which host · which**
> ## **enrollment. DROP model self-reporting, or label it EXACTLY as existing posture is —**
> ## ***client-reported, not attestation*** — **and never let a rule depend on it.**

The three that survive are all bindable to something we issued and can revoke. *Which model* is bindable to
nothing, which is precisely why it is attractive to put on a screen and useless as a control.

## 3c · PER-TOOL GRANULARITY — **THE PART NOBODY ELSE IS DOING, AND THE PART THAT BREAKS THE ARCHITECTURE**

`read_file` vs `delete_repo` inside one MCP server.

**MEASURED CONSTRAINT:** every enforcement mechanism in this product operates at **L3/L4** — WireGuard peer
allow-lists, `ip` rules, nftables, the DOCKER-USER accept, resources as `cidr`+`protocol`+`port`. **A network
rule cannot see inside an MCP call.** Granting the server grants every tool on it.

> ## **SO TOOL-LEVEL RULES ARE NOT AN EXTENSION OF OUR ENFORCEMENT PLANE. THEY ARE A SECOND ONE — an L7**
> ## **proxy that terminates, parses and re-emits MCP.** That is a new data-path component with its own
> ## availability, latency, versioning and failure modes, sitting in the path of every agent call.

**AND THE ANSWER TO *"are we terminating MCP traffic, or enforcing at the network layer only?"* IS THE WHOLE
QUESTION — THOSE ARE DIFFERENT PRODUCTS.** Network-only is what we are today and what every existing mechanism
supports. Terminating MCP makes us a protocol proxy, with a parser in the path of every agent call.

**COST: LARGE, and structurally different from the other two.** A new data-path component with its own
availability, latency, versioning and failure modes — plus ongoing protocol churn (§4).
⛔ **AND TELEPORT SHIPPED THIS IN DEC 2025** (§5), so it is a catch-up item, not a differentiator. The first
draft of this paper called it *"the part nobody else is doing"*; that was wrong and unchecked.

**SEQUENCE: LAST — founder-ruled, and the reason is mine: ship a real boundary before putting a parsing proxy
in the path of every agent call.** If it is never built, the epic still delivers a working boundary.

---

# 4. THE COSTS, PLAINLY

- ⛔ **CORRECTED 2026-08-04: THE DESTINATION TYPE IS NOT NEW WORK** (see 3a). What remains is a **principal
  design** plus UI — and the two rulings below, which are founder-time rather than build-time.
  **The build shrank; the decisions did not.** Whether this stays an epic between EPIC 14 and the beta bundle,
  or becomes a story plus two rulings, is a SEQUENCING RULING and is not made by this paper.
- **It delays beta by its own length.** That is the decision, stated as a cost rather than buried.
- ⛔ **THE MCP PROTOCOL IS MOVING FAST. Anything coupled to its wire format may be stale in six months.**

**What is protocol-INDEPENDENT — the durable core:**
the agent **principal** and its role · **grants with expiry** · **audit attribution** · **device identity and
revocation** · **default-deny between a named source and a named destination**. None of that mentions MCP.
If MCP is replaced wholesale, this survives with a renamed destination type.

**What is protocol-COUPLED — and will rot:**
**per-tool enforcement (3c)**, because it must parse the protocol; any **tool discovery/enumeration**; any
posture field describing an MCP capability set.

**The sequencing follows from that split**, and it is the paper's main recommendation: **build the
protocol-independent core first and let it stand alone. Add the coupled layer last, knowing it is the part
that will need re-doing.**

---

# 5. ⛔ THE CATEGORY IS NOT EMPTY — MEASURED FACT, AND IT REPLACES WHAT THIS PAPER FIRST SAID

**This section is a CORRECTION.** The first draft treated primacy as *unproven and therefore deferred*, and
built a register row listing what would have to be true to earn it. **That framing was wrong, and generously
wrong in our own favour: the claim is not unproven, it is CHECKABLE AND FALSE.**

| who | what they already ship | when |
|---|---|---|
| **Versa Networks** | markets **"Industry's first Zero Trust MCP Server"** | ~May 2026 |
| ⛔ **Teleport** | **protocol-level MCP access control down to INDIVIDUAL TOOL INVOCATIONS**, deny-new-tools-by-default, JIT access for high-risk tools | Dec 2025 |
| **Octelium** | FOSS, self-hostable **architectural twin** — WireGuard + QUIC, unified identity for humans, workloads **and AI agents**, per-request ABAC, L7-aware policy, names MCP and A2A explicitly | shipping |
| Pomerium · AccuKnox · TrueFoundry | also shipping in the space | — |

> ## **SO WE DO NOT MAKE A PRIMACY CLAIM. NOT "not yet" — NOT AT ALL. Someone else already made it, and ours**
> ## **would be checkable and false the day it was published.**

⛔ **AND TELEPORT IS ALREADY WHERE §3c GOES.** Per-tool granularity is not our unclaimed differentiator; it is
**the thing a competitor shipped eight months before this paper was written.**

**PROVENANCE, RECORDED ACCURATELY BECAUSE IT CHANGES THE LESSON:** *"the part nobody else is doing"* was the
**FOUNDER'S** line, in the instruction that opened this epic. **I inherited it and repeated it in the paper
without checking**, and applied our own prior-art rule to it one step later than either of us should have.

> ## **NEITHER OF US CHECKED. The claim originated upstream and was laundered into a document by being**
> ## **restated — which is how an unverified premise acquires the authority of a written one.**

**That is the Tier-3 defect this epic has spent fourteen stories cutting from other people's copy, committed
in our own paper, about our own product — and it entered by inheritance rather than by invention, which is
the more common way it gets in.**

## THE ACTUAL REASON TO BUILD, STATED PLAINLY

Not to claim the space — the space is occupied. **Two reasons, and they are enough:**

1. **Beta is more compelling with agent support than without it.** A ZT product that cannot describe an agent
   principal in 2026 looks unfinished, regardless of who was first.
2. **Our existing model already carries most of the shape** — §2 measures how much. The marginal cost of the
   protocol-independent core is low *because it is mostly vocabulary on mechanisms that already ship*.

**Neither reason requires us to be first, and neither is weakened by Teleport being ahead on §3c.**

## WHAT SURVIVES OF THE POSITIONING RULE

The three conditions from the first draft **stand as the standing test for any comparative claim we ever
make** — it ships and holds on a live wire · a real prior-art survey with dates and citations, not a memory ·
**someone outside the company says it.**

⛔ **The correction is that condition 2 was RUN, and it FAILED.** That is what the condition is for. **A rule
that has never rejected anything is not a rule** — this one just rejected our own headline, which is the only
evidence that it works.

---

# 6. STATUS

**REGISTERED. NOT STARTED.** No design, no schema, no commit-one. EPIC 14 continues unchanged.
