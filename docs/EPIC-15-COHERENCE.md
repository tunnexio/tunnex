# EPIC 15 — is it correct, and does it make sense?

Asked by the founder after S15.3's surface landed. Two different questions, answered separately, then the
ledger of what is still open.

---

## 1. IS IT CORRECT? — yes, on the wire, for the core loop

Create → command → connect → grant → enforced → revoked. Proven with counter deltas and a packet capture,
**not with 200s** (`walk-artifacts/S15.3-agent-e2e.md`):

| claim | evidence |
| --- | --- |
| the agent reaches its granted resource | `wg0 In → eth0 Out → reply`, `{"mcp":"ok",…}` |
| **the GRANT is what allowed it** | grant rule `0 → 1`; adjacent port `default_drop 0 → 4`, grant unmoved |
| the deny is real, not inferred | 8932: **5 packets in on `wg0`, 0 out on `eth0`** |
| revoke is a full sweep | peer **gone from `wg0`**, rule gone, request dead |
| liveness is honest | 5 states; `unknown` outranks `offline`, proven with two live agents |

## 2. DOES IT MAKE SENSE? — the model does, and for a reason that cannot change

**An agent is a PEER homed on a gateway, not a gateway.** Traffic an agent originates *on* a gateway is
locally-originated: it never traverses `FORWARD`, so the policy chain never sees it and no grant could ever
fire. The first build had agents as gateways and was rebuilt for exactly this.

⚠ That rebuild is also the epic's biggest lesson: **the evidence was in hand at walk Leg 4 and was filed as
correct** — *"a property of being the gateway, not a gap in D15"* — until the founder's question exposed it.

---

## 3. ⛔ AND THE MODEL CHANGE ORPHANED A FOUNDER RULING

S15.2 built a marker to distinguish an agent **node** from a gateway **node**: `node_join_tokens.enrols_kind`
+ `nodes.enrolled_kind`, migration 0069. The founder personally ruled its third state —

> ⛔ **RULED: shape 3 — UNDETERMINED.** *Neither an agent nor not-an-agent; the fact was never recorded and
> cannot be recovered.*

**S15.3 then rebuilt agents as peers created through `POST /devices`. The marker describes a model the
product no longer uses.** Measured:

| | state |
| --- | --- |
| `enrolmentKind()` | **zero consumers** — not in the app, not in a test |
| `UNDETERMINED_LABEL` / `UNDETERMINED_DETAIL` | **zero consumers**; the ruled state renders **nowhere** |
| UI requesting `enrols_kind: "agent"` | **no caller** |
| write path | **live and reachable** (`node_handlers.go:125`), API-callable |

Data: 4 nodes `enrolled_kind='agent'` and 7 tokens `enrols_kind='agent'` — residue of the pre-rebuild model —
plus **676 nulls**, which are pre-marker gateways.

> ## **PRODUCER WITHOUT CONSUMER — the standing who-reads-this probe, third-plus instance this epic.** Not
> ## dead code: the write path works and anyone can call it. What is missing is a caller and a reader.

⚠ **This is not a bug I can quietly delete.** The founder ruled the state; retiring it needs their word.
**Recommendation: retire it.** The marker answers *"is this NODE an agent"*, and under the peer model no node
is ever an agent — the question has no referent. Record that S15.3's model change retired it, rather than
wiring a Nodes-page badge for a distinction the product stopped making.

---

## 4. WHAT IS NOT CORRECT — three defects that block the stated requirement

1. ⛔ **One agent per gateway, and a revoke bricks the slot permanently.** `devices_agent_node_key` is
   `UNIQUE(node_id) WHERE kind='agent' AND deleted_at IS NULL`; revoke sets `status='revoked'` and never sets
   `deleted_at`. The requirement is *plural* agents; the schema permits one, and after a revoke, none ever
   again.
2. ⛔ **`wg-quick` deletes the interface when `resolvconf` is absent.** The config carries `DNS =`, and
   rollback fires after four lines that look like success — on exactly the minimal hosts an agent runs on.
3. ⛔ **Exported ranges can overlap the agent host's own subnet.** The control plane cannot detect it, and the
   result is either `File exists` or the host's own network silently pulled into the tunnel.

### ⚠ AND THE FIX TO (1) OPENS A HOLE, WHICH IS A CONDITION ON IT, NOT A SEPARATE ITEM

Agent devices are **cap-exempt** (0067). The unique index is therefore the **only** thing bounding agent count
today. Dropping it with nothing in its place lets an admin exhaust the org pool through a door the cap
deliberately does not watch — **the exact DoS the index was written against.** Drop it *and* bound agents
org-level, or do neither.

---

## 5. TWO RULINGS OWED, AND THEY INTERACT

- **§4.4 — bounding.** Drop node-scoped uniqueness + bound agents org-level (recommended), or keep one per
  gateway and at minimum stop a revoke from bricking the slot.
- **The table split.** Recommendation: **no.** An agent must be a `devices` row wherever the data plane looks
  — ~16 queries — and forking them is the class that made a gateway configure zero peers. Separateness is
  delivered by `kind` on the human surfaces plus hard refusals like `posture_not_applicable`.

If agents get their own table, the bounding question changes shape — so both want deciding together.

---

## 6. STILL CARRIED, NONE STARTED

Everything in `EPIC-15-CLOSE.md` §5: D23 (deactivated-owner fail-open), D26 (`ON DELETE CASCADE`, still
untested on a wire — revoke does not delete the row), `machine_credentials.user_id` contraction, the org
question, `assigned_ip` ×3 presence-guarded, `users.deleted_at`'s 18 pre-armed predicates, register rows 7
and 8. Plus **§7's full-surface pass, which is UNRUN, not clear.**
