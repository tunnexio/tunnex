# EPIC 15 — CLOSE

**The non-human principal.** S15.0 (paper) · S15.1 (the owned machine principal) · S15.2 (the address-bearing
agent, and the agent as an RBAC principal) — all merged. Walked 2026-08-04.

⛔ **The beta-bundle call is the founder's, and it comes after this document — not inside it.** Nothing here
is a readiness argument.

---

## 1. THE LEGS

| leg | verdict | what it establishes |
| --- | --- | --- |
| **1 — the owed restore proof** | ✅ **PASS** | `401 refused → 204 assign → 200 authenticates`, one credential, same call. Non-vacuous (three org-scoped endpoints returning real data) and **controlled** (a second credential left unowned returns 401 on those same three, so the flip was ownership, not the endpoint) |
| **2 — the deliberate red** | ✅ **PASS, all five steps** | enforcing + zero grants + **route forced** → dropped · grant → **a request that completed** · **adjacent port refused** · revoke → dead · **0 nft rules** on the wire |
| **3 — attribution** | ✅ **PASS** | 8931 `allow` and 8932 `deny`, both resolving device → owner via agent-stamped `src_device_id`, never `src_ip` |
| **4 — separateness** | ✅ **PASS** | own container, netns, certificate, WG interface; enrolled off-box through the public API |
| **5 — `RoleAgent`** | ✅ **PASS, both halves** | agent **401** on the wire · operator **201** creating a real rule |

### ⭐ The single most valuable step was one that FAILED first

**Leg 3 step 1** — the instrument check, ranked above attribution — returned **zero events** for the walk's
own traffic, despite an ALLOW whose kernel counter read `packets 1` and three DENYs.

> ## **AN EMPTY LOG READS IDENTICALLY TO A QUIET NETWORK *AND* TO A DISABLED COLLECTOR.** Three states, one
> ## appearance.

The cause was **off by design** (`TUNNEX_FLOWLOG_GROUP=0`), not broken. **Without instrument-first, this walk
would have reported *"attribution does not work"* about a subsystem that was never switched on** — a
confident, specific, wrong finding. Registered as **row 8**.

---

## 2. ⛔ TWO WITHDRAWN CRITERIA — BOTH MINE, AND THE REASON IS ONE FACT

The deck asked Leg 4 for *"the agent's `/32` handshakes from off-box"* and Leg 3 for *"a flow from the agent
producing an event"*. **Both assume an agent is a traffic source. It is not.**

> ## **AN AGENT'S OWN TRAFFIC IS LOCALLY-ORIGINATED ON THE GATEWAY, SO IT NEVER TRAVERSES `FORWARD` AND NEVER
> ## REACHES THE POLICY CHAIN OR THE FLOW LOG.** There is nothing to observe, by construction.

⛔ **That is a property of BEING the gateway — not a gap in D15.** What replaced the criteria is stronger than
what they asked for: the agent's `/32` carries **its own accept rule, with the flow-log clause**, identical in
shape to a human peer's —

```
ip saddr 10.99.0.4 ... tcp dport 8931 ... log prefix "tnx:<rule>" group 100 accept   ← the AGENT
ip saddr 10.99.0.5 ... tcp dport 8931 ... log prefix "tnx:<rule>" group 100 accept   ← a human device
```

**Enforced and attributable identically to a human device.** It is simply not a source of forwarded packets.

⚠ **The criteria were wrong, not unmet, and that distinction is recorded rather than smoothed over.** A
withdrawn criterion quietly dropped is indistinguishable from one that failed.

---

## 3. ⭐ THE DEFECT THE WALK FOUND, AND NOTHING ELSE COULD HAVE

S15.2 created an agent's device row with a **placeholder public key**. That row is a peer on its own gateway,
so the agent fed the placeholder to `wg syncconf` — **which is all-or-nothing**.

⛔ **The gateway configured ZERO peers.** Not one broken peer: the entire interface config rejected, every
human device on that gateway gone.

**No test could have found it.** Every unit and integration test passed. `generate-check` passed. Both
editions built. The defect lived in the space between a value the database accepted and a parser that
rejected the batch — **visible only when a real agent enrolled against a real WireGuard interface.**

### And the guard for it already existed

`ListActiveWireGuardPeersForNode` has filtered `public_key <> ''` since S9.1, **and its own comment names this
exact hazard.**

> ## **A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE HAZARD.** *Is there a key* is not *is this a
> ## key*. Emptiness is a special case of malformedness, and the guard tested the special case — while its
> ## comment named the general one, **which is what made it read as covered.**

**Fixed** with a format check at the one place the peer set is built, fail-closed **for the peer, never for
the interface**, with exclusions **surfaced by name**. Three reds, mutation-proven one at a time — including
*one bad peer, every good one still configures.*

⚠ **Class censused: 5 presence-only guards on values a consumer parses.** `public_key` fixed; **`assigned_ip`
(×3) open** — safe today only because every writer is `ipalloc.Allocate`. *That is a property of the writers,
not of the guard,* and it is exactly the property that stopped holding.

---

## 4. ⛔ WHAT THE WALK DID NOT COVER

Per the Human Gate Limit Law — **a review is only valid over what the data makes visible, and its silence
about the rest is indistinguishable from approval.**

- ⛔ **§7's FULL-SURFACE PASS IS UNRUN, NOT CLEAR.** The org question, pool utilisation, the Entra stale-seal
  ambiguity and the S15.2 badges were **never opened on screen**. Only "Talking:" was resolved (rows 6).
  **The founder ruled a full-surface pass; the walk delivered the five legs and one item of §7.**
- **`RoleAgent`'s wire contribution is not isolated** — the agent's 401 has two causes (no permission **and**
  no bearer route to the public API). The unit tests pin the role half; the wire cannot.
- **Single gateway, single org, containers on one bridge.** No multi-site, no HA, no cross-cloud, no
  Windows/macOS client.
- **§8's unseedable register stands**, except Leg 1's entry — now discharged.
- **The MCP claim is narrower than it sounds:** a real HTTP server on a known port proved *enforcement*. It
  did not prove *MCP* — no MCP protocol was spoken.

---

## 5. CARRIED FORWARD — every item open, none started

| item | state |
| --- | --- |
| **D23** — deactivated-owner fail-open | HELD. Ruled to be decided **after** D25's build, so the expensive data-plane case does not inherit a precedent from the cheaper pipeline one |
| **D26** — an agent inherits `ON DELETE CASCADE` | HELD. **Latent** — no code path deletes a `users` row |
| **step 4** — contract `machine_credentials.user_id` to `NOT NULL` | after every row is assigned. **An operator action, no code date** |
| **the org question** | registered, recommendation **B** (a switcher); founder rules |
| **`assigned_ip` ×3 presence-guarded** | measured, filed, not fixed |
| **`users.deleted_at`** | **18 pre-armed predicates, 5 data-plane**, on a column nothing writes |
| **register row 6** — "Talking:" | corrected: sighted, unlocatable, cause undetermined |
| **register row 7** — `GET /organizations` returns `[]` for a machine principal | open. D4's separation producing a hole nobody chose |
| **register row 8** — flow logging off by default, no signal | open. **The walk's most product-facing finding** |

---

## 6. RIG

`demo` org `zero_trust_mode` was switched `off → enforcing` for Legs 2 and 3 and is **reverted to `off`**,
verified by query.

> ## **A REVIEW STACK'S VALUE IS THAT IT MATCHES WHAT REVIEWERS HAVE SEEN BEFORE.** A register row does not
> ## undo a changed baseline; it only explains it afterwards.

Left as walk evidence: `walk-agent` / `walk-agent2` nodes, `walk-peer` / `walk-peer2` devices, two agent
rows, resources `walk-mcp-8931` / `walk-mcp-8932`, two machine credentials, and the containers. Grants
remain but the org is `off`, so they are inert.

⚠ **And test residue was found on this rig mid-walk** — 10 `kind='agent'` rows from an integration test,
which nearly produced a wrong Leg 4 reading. **A walk measures the rig, and the rig contains every test that
has ever run against it.** Cleaned org-scoped, FK graph read first, verified in-transaction before commit.

---

**EPIC 15 closes here.**
