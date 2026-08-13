# EPIC 15 walk — LEG 3 ✅ PASS · LEG 5 ✅ PASS

## ⭐ LEG 3 — the instrument check found a real thing, and it was NOT "the pipeline is dead"

**Step 1 failed on the first attempt, exactly as the deck required it be run.** Zero events existed for the
walk's traffic — despite an ALLOW whose kernel counter read `packets 1` and three DENYs.

⛔ **BUT THE CAUSE WAS "OFF BY DESIGN", NOT "BROKEN", AND THE DIFFERENCE IS THE FINDING.**
`TUNNEX_FLOWLOG_GROUP` defaults to **0 = flow logging OFF** (S7.5.1 made it opt-in per gateway), and it was
**unset on both gateways — including the compose stack's `node-agent`.**

> ## **AN EMPTY LOG READS IDENTICALLY TO A QUIET NETWORK *AND* TO A DISABLED COLLECTOR.** Three states, one
> ## appearance. The deck's instrument-first rule is what separated them; without it, Leg 3 would have
> ## reported "attribution does not work" about a subsystem that was never switched on.

⚠ **AND THE DEFAULT IS THE COLLECTED FINDING:** a gateway ships with flow logging **off**, so an operator who
never sets `TUNNEX_FLOWLOG_GROUP` has an **Access Events screen that is permanently empty and correct**.
Nothing on the screen says "this gateway is not reporting". *Registered below.*

### With the collector armed — steps 1, 2 and 3 all pass

| step | observed |
| --- | --- |
| **1 — instrument alive** | `flowlog_started group=100`; **6 events** for the walk's own traffic |
| **2 — attribution** | port **8931 `allow`** and **8932 `deny`**, both resolving to device `walk-peer2` (`10.99.0.5`) → owner **`owner@demo.tunnex.local`** |
| **3 — the mechanism** | `src_device_id` is present on every row; the CP joins **device → user**, never `src_ip` |

**Both decisions are logged** — 1 allow, 6 deny. ⚠ Worth stating: a collector that logged only denies would
have passed a naive "is there an event" check while making every successful access invisible.

### ⚠ THE AGENT-AS-TRAFFIC-SOURCE CRITERION IS WITHDRAWN — same reason as Leg 4's

The deck asked for *"a flow from the agent producing an event naming the agent principal"*. **An agent's own
traffic is locally-originated on the gateway, so it never traverses `FORWARD` and never reaches the
forward-chain nflog.** There is nothing to observe, by construction.

⛔ **What IS proven, and is the substance of the claim:** the agent is a **first-class policy subject on the
wire**. Its `/32` carries its own accept rule with the flow-log clause, byte-identical in shape to the human
peer's:

```
ip saddr 10.99.0.4 ... tcp dport 8931 ... log prefix "tnx:<rule>" group 100 accept   ← the AGENT
ip saddr 10.99.0.5 ... tcp dport 8931 ... log prefix "tnx:<rule>" group 100 accept   ← a human device
```

**The agent is enforced and attributable identically to a human device.** What it is not is a *source of
forwarded packets* — which is a property of being the gateway, not a gap in D15.

---

## LEG 5 — `RoleAgent` cannot write policy, and the operator still can. **Both halves.**

| half | observed |
| --- | --- |
| the grant table | `TestAgentRoleCannotAuthorPolicy` + `TestAgentRoleIsNarrowerThanOperator` pass |
| ⛔ **the agent, on the wire** | **401** — an agent reaching the policy API from the gateway |
| ✅ **the operator, on the wire** | **201** — a real rule created with a machine-credential bearer |

⚠ **The operator half first returned 409 `conflict: an identical rule already exists`** — which is *not* a
refusal: it means the request passed authorization and reached business logic. It was re-run against a
**new** resource to get an unambiguous **201**. ⛔ A 409 would have been weak evidence of permission; a 201 is
not.

### What this closes, and what it does not

**Register item #1** said one role served two principal kinds. **The split is now real on the wire**, not only
in the grant table.

⚠ **But the agent's 401 comes from TWO mechanisms, and only one of them is `RoleAgent`:** the grant table
lacks `PermPolicyManage`, **and** an agent authenticates by mTLS on the agent channel and holds no bearer for
the public API at all. **The route is closed as well as the permission.** That is defence in depth and it is
also why this leg cannot isolate the role's contribution on the wire — the unit tests are what pin that half.

---

## ⚠ RIG STATE — REVERTED, not left as a line in a report

`demo` org `zero_trust_mode` was switched **`off` → `enforcing`** for Legs 2 and 3, and is now **back to
`off`**, verified by query.

> ## **A REVIEW STACK'S VALUE IS THAT IT MATCHES WHAT REVIEWERS HAVE SEEN BEFORE.** Leaving it enforcing
> ## would have meant the next person opening the demo org met a product behaving unlike every EPIC 14
> ## screenshot — and a register row does not undo that, it only explains it afterwards.

**Left in place deliberately as walk evidence:** containers `walk-agent`, `walk-peer`, `walk-mcp`; nodes
`walk-agent` / `walk-agent2`; devices `walk-peer`, `walk-peer2` and two agent rows; resources
`walk-mcp-8931`, `walk-mcp-8932`; two machine credentials from Leg 1. **Grants created during the walk
remain** — the demo org is `off`, so they are inert.
