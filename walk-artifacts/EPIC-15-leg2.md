# EPIC 15 walk — LEG 2 ✅ **PASS, all five steps.** The epic's central claim holds.

**Run 2026-08-04, enterprise stack, demo org switched to `zero_trust_mode = enforcing`.**

## Setup — real, not simulated

| piece | what it actually was |
| --- | --- |
| MCP-shaped server | a real HTTP server at `172.18.0.10`, serving **`{"mcp":"ok","tools":[]}`** on **:8931** and **:8932** |
| the resource | **port-scoped**: `cidr=172.18.0.10/32`, `protocol=tcp`, `port_low=port_high=8931` |
| the client | a **real WireGuard peer** (`10.99.0.3`), handshaked with the walk gateway |

⭐ **BOTH PORTS SERVE.** 8932 was opened deliberately: if the adjacent port were closed, its refusal would
prove nothing about the grant.

⛔ **AND THE ROUTE WAS FORCED CLIENT-SIDE** (`AllowedIPs` extended to `172.18.0.10/32`). Without that, "zero
grants → cannot reach" would only prove *there was no route* — the weak form. With the route present, the
packet reaches the gateway and the leg tests **permission**.

## The five steps

| # | step | observed |
| --- | --- | --- |
| **1** | enforcing, **zero grants**, route forced | ⛔ **`http_code=000`, 8s timeout — DROPPED** |
| **2** | add the grant | ✅ **`{"mcp":"ok","tools":[]}` · HTTP 200** — a request that **completed**, not a TCP connect |
| **3** | **adjacent port 8932**, same host, same grant, same run | ⛔ **`:8932` → 000 · `:8931` → 200** |
| **4** | revoke the grant | ⛔ **`http_code=000` — dead again** |
| **5** | did revocation reach **the wire**? | ✅ **0 nft rules naming the resource** |

> ## **ROUTING IS NOT PERMISSION — DEMONSTRATED, NOT ASSERTED.** In step 1 the tunnel was up, the peer had
> ## handshaked, and `ip route get` resolved the MCP host **via wg0**. The packet arrived at the gateway and
> ## policy dropped it. That is the distinction the whole product rests on, and it is the one a
> ## reachability test cannot see.

## ⭐ Step 5's evidence was better than the criterion asked for

**Before revoke**, the gateway's `ip tunnex` table carried:

```
ip saddr 10.99.0.2 ct original ip daddr 172.18.0.10 tcp dport 8931 counter packets 0 bytes 0 accept
ip saddr 10.99.0.3 ct original ip daddr 172.18.0.10 tcp dport 8931 counter packets 1 bytes 60 accept
```

- **`packets 1 bytes 60`** on the peer's rule — the kernel counter proves **this rule is what admitted the
  traffic**, not some broader accept elsewhere in the chain. ⚠ Step 2 could otherwise have passed via the
  existing split-tunnel egress rule, and nobody would have known.
- **`10.99.0.2` — THE AGENT'S OWN `/32` GOT A RULE TOO.** The grant was to the *user*, and the agent device
  is owned by that user, so **the agent is a policy subject in its own right.** ⭐ That is D15 working
  end-to-end: the agent is address-bearing and appears in the compiled allow-set **even though it is
  correctly not a WireGuard peer** (its placeholder key excludes it from `syncconf`, by design).

**After revoke: zero rules naming the resource.** The `204` and the wire agree.

## ⚠ Rig state changed by this leg — declared, not left for someone to find

- `demo` org is now **`zero_trust_mode = enforcing`** (was `off`).
- Left in place as walk evidence: containers `walk-agent`, `walk-peer`, `walk-mcp`; node `walk-agent`;
  devices `walk-peer` and the agent row; resource `walk-mcp-8931`. The grant is **revoked**.
