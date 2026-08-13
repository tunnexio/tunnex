# S8.4 cross-site DNS — box-walk record

**Date:** 2026-07-19. **Driver:** Pawan (founder-present). **Branch:** `story/S8.4-dns` @ `905beab`.
**Topology (live cross-cloud):** Azure West US ↔ AWS Sydney, 138ms.
- **CP** — Azure `Tunnex-dev-vm` 10.0.0.4 (public 40.65.63.141), enterprise, ZT **enforcing, 0 rules**.
- **azure-site / azure-gw** — Azure `AZURE-VM1` 10.0.0.5, wg0 10.99.0.1, subnet 10.0.0.0/16.
- **aws-site / aws-gw (HUB)** — AWS `ip-172-31-28-80` 172.31.28.80 (public 16.176.32.176), wg0 10.99.0.1, subnet 172.31.0.0/16.
- **Resolver** — dnsmasq on aws-gw, zone `corp.internal` → 172.31.28.80 (LAN-bound, no clash with the wg-scoped forwarder).
- **Forward declared** — aws-site: `corp.internal` → `172.31.28.80` (in the approved 172.31.0.0/16).

## Legs — 6/6 + liveness, ALL PASS

| Leg | Result | Evidence |
|-----|--------|----------|
| **1 — cross-site resolve** | ✅ | `dig @10.99.0.1 nas.corp.internal +short` → `172.31.28.80`. tcpdump shows the full path: query→forwarder, **relay out wg0 to 172.31.28.80:53**, reply back, forwarder answers. Org-wide table propagation proven (declared on aws-site → azure-gw's forwarder has it → compile→out-of-hash artifact→push→SetTable→relay). |
| **2 — negative-scope** | ✅ | `dig @10.99.0.1 www.google.com` → **status: REFUSED** (out-of-zone, split-horizon), while `nas.corp.internal` resolves. |
| **3 — fail-static (DNS-down ≠ tunnel-down)** | ✅ | Resolver stopped → `dig nas.corp.internal` = **SERVFAIL** (139ms, honest, no hang); `ping 172.31.28.80` = **0% loss** — tunnel survived the DNS outage. |
| **4 — stopped-gateway → OFFLINE (VERIFY-0 rider)** | ✅ | `docker stop tunnex-node` on aws-gw → aws-site card flips **`offline`** + "1m ago"; `docker start` → "2s ago", badge cleared. Dead gateway can't read healthy. (Screenshots.) |
| **5 — bind-scope (no open resolver)** | ✅ | `ss -ulpn \| grep :53` on both gateways → `tunnex-node` on `10.99.0.1:53` **only** — the wg address, never 0.0.0.0/public. The F1 bind-reconcile fix live. |
| **6 — config surface (typed refusals + sweep)** | ✅ | (a) resolver `10.0.0.99` outside subnet → verbatim **"the resolver 10.0.0.99 must be inside one of this site's approved subnets"**. (b) `corp.internal` on azure-site → verbatim **"corp.internal is already forwarded by another site; a domain forwards to one resolver"**. (c) ✕ on 172.31.0.0/16 → confirm names the dependent: **"1 DNS forward resolves via this subnet and will also be removed: corp.internal"** (F4 preview). All VERBATIM from the one validator — F8 fold live. |

## Observations (captured, no code change)

- **ZT transit enforcement CORRECT — the fixture-fidelity trap, understood.** Gateway↔gateway ping works (10.0.0.5↔172.31.28.80) = **locally-originated on the gateway → OUTPUT/INPUT, not the FORWARD chain** the ZT policy gates. The enforcement proof: **CP behind-host (10.0.0.4) → 172.31.28.80 = 100% loss** — forwarded transit through azure-gw → FORWARD policy → 0 rules → DENIED. Testing from the gateway (locally-originated) hides the enforcement; a genuinely-separate behind-host shows it. (Enforcement is FORWARD-only, so a gateway host itself reaches routed subnets ungated — inherent to gateway-as-enforcement-point; a compromised gateway is game-over regardless. Documented, accepted.)
- **Dup wg0 `10.99.0.1` on both gateways — EXONERATED, not a finding.** Predicted the relay would collapse; tcpdump proved the relay sources from the **LAN address** (`10.0.0.5`), distinct per gateway and routed back via the advertised subnet. The shared `.1` never enters the relay path; site-link routes on advertised subnets + endpoints, not the `.1` identity.
- **Behind-host DNS ergonomics — design feedback.** A behind-host must route the wg pool to its gateway + point resolv.conf at the gateway's wg address (the open-resolver-guard tradeoff: wg-only bind). Leg 1 ran from the gateway-local vantage (the forwarder+relay code path is identical regardless of query origin — DNS forwarding is gateway-local infra, NOT forward-chain-gated, so this is a valid forwarder proof). The fixture-fidelity behind-host ORIGIN (CP → forwarder) needs an Azure UDR for 10.99.0.0/24 + NIC IP-forwarding — offered, not run; the forwarder itself is proven on the wire.

## Verdict
**All 6 legs + the liveness rider PASS on a live cross-cloud pair, ZT enforcing.** Cross-site DNS forwards, refuses out-of-zone, fails static (tunnel survives), the liveness rider closes VERIFY-0, bind-scope holds (no open resolver), and the config-surface typed refusals + subnet-removal dependent-naming render verbatim from the one validator. Dup-`.1` exonerated. No new findings. **S8.4 is walk-proven.** Merge on the founder's word.

_Feeds the registered HUB behind-host forwarding VERIFY item: no manual iptables was observed needed for the DNS path (it's gateway-local infra), but the behind-host DATA-plane path (CP → remote subnet) is ZT-denied here; the hub-forwarding gap is about behind-hub → spoke transit under a GRANT, verified separately._
