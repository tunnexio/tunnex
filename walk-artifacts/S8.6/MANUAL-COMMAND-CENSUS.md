# Manual-command census — all EPIC 8 walk sessions (2026-07-23)

Founder directive (SMOOTH-WALK BAR): the epic walk must run with ZERO manual terminal
commands beyond (a) the emitted install paste per gateway, (b) entity-gated signing
workarounds. Every hand command from demo → Decks A/B/C/D enumerated below, classified.
**HELD for disposition — nothing folded from this census without a ruling.**

Classes: PRODUCT-DEFECT (product lacks it; fix) · BRANCH-WALK-FRICTION (dies at merge /
single-provenance deploy) · ENTITY-GATED (signing; named exception) — plus two proposed
EXCLUSION classes surfaced for confirmation, not silently assumed:
TEST-ACTION (fault injection that IS the proof's subject) · DIAGNOSTIC/FIXTURE
(read-only evidence capture, or walk-env scaffolding simulating the customer's LAN).

## PRODUCT-DEFECT (the fix-now class, pending ruling)

| # | Command (where) | Why it was needed | Owning fix |
|---|---|---|---|
| P1 | `iptables -I DOCKER-USER … -s/-d 10.99.0.0/16 ACCEPT` (aws-gw-1, azure-gw, aws-gw-2; Deck D Leg 10 + Test A pre-flight) | **RECLASSIFIED (founder-accepted): the device↔SITE portion is BRANCH-WALK-FRICTION** — branch-tip agent code (S8.6b relaxed route rules + S8.5 WF-4-local) already passes device transit at the Docker tier; the manual accepts compensated for the stale ghcr agent. Residual PRODUCT scope = the pool key class for device↔device only (PD-3, ruled (ii) relaxed) | **A3b D-A3b-3 (residual)** |
| P2 | `wg set wg0 peer <hub> allowed-ips …,10.99.0.0/16` (azure-gw, Leg 10 proof; reconcile reverted it) | pool CIDR never compiled into spoke hub-peer AllowedIPs — wg crypto-routing drops device transit | **WF-1 / A3b** |
| P3 | `nsenter … iptables -I FORWARD -i wg0 -o wg0 -j ACCEPT` (docs/gateway-device-to-device.md, demo era) | device→device wg0↔wg0 at hub = pool-daddr forward, same structural exclusion (S8.6b red #1 proves pool untouched) | **A3b family** |
| P4 | Cloud console: AWS route `10.99.0.0/16 → gw ENI` + Azure UDR `vpn-rt` (Leg 10) | console visits are sanctioned by the fabric panel — but the panel documents SITE ranges only; pool return-route is undocumented | **WF-1c: fabric teaching text** |

P1–P3 share one root (device-pool transit unowned end-to-end); P4 is its docs surface.
A3b ruling (FULL vs NARROW, framed separately) disposes all four.

## BRANCH-WALK-FRICTION (dies at merge + single-provenance deploy)

| # | Command (where) | Why |
|---|---|---|
| B1 | `docker pull <branch image>` / `docker rm -f tunnex-node` / `docker volume rm tunnex_node_state` (S8.2c walk-record, S8.4 runbook) | mid-walk agent upgrades to branch builds; stale identity across re-enrolls |
| B2 | `TUNNEX_BUILD_TAGS=enterprise docker compose up -d --build …` + migrate-log check (S8.4 runbook; repeated for this env @782d036) | CP rebuilt from branch checkout on the box |
| B3 | `ssh -L 8080:…` Vite port-forward (S8.3 walk-script) | web served from dev machine against box API |
| B4 | Stale-ghcr orientation rules on today's gateways (old `iifname/oifname` predicates observed live) | ghcr `:latest` predates the S8.6b fold; agents converge on next release — the drift-detection transition (D-transit-2 ruling) then proves itself on real substrate |

All die by construction at the smooth walk's fresh-from-main single-provenance deploy.

## ENTITY-GATED (named exceptions, founder-desk)

| # | Command (mac) | |
|---|---|---|
| E1 | `codesign --force --deep --sign -` + `xattr -dr com.apple.quarantine` on Tunnex.app | Gatekeeper unsigned-app block (S6.5b) |
| E2 | Manual helper install (LaunchDaemon plist + dev trust dir) + direct-binary / `TUNNEX_BUNDLE_DIR` dev launch | same chain — the .pkg path installs the helper itself once signing exists |

## TEST-ACTION (proposed exclusion — the command IS the test)

`docker stop/start tunnex-node` (S8.4 liveness rider; Deck B + REMATCH failover kills;
Test A) · `ip link del wg0` (REMATCH) · `systemctl stop/start dnsmasq` (S8.4 fail-static).
Fault injection; no product path can or should replace it.

## DIAGNOSTIC / FIXTURE (proposed exclusion)

Read-only evidence: tcpdump, `wg show`, `iptables -L/-S`, netstat/ss, dig/ping proofs,
docker logs/ps, `brew install wireguard-tools`. Fixture (simulating the customer LAN):
dnsmasq install + corp.conf zone (S8.4 — the site resolver the feature forwards TO),
behind-host `resolvectl dns` pointing (customer endpoint config, documented),
Windows endpoint firewall allows (docs/gateway-device-to-device.md — endpoint policy).

## Observation (no class)

Mac client re-pointed to the new CP via full state wipe (`rm -rf …/Application Support`)
— the product path EXISTS (Settings → change server); wipe was operator expedience.
Discoverability note only, not a defect entry.

## Census verdict (proposed)

The bar is met at merge IF: A3b disposes P1–P4, the smooth walk deploys fresh from main
(kills B1–B4), E1–E2 stay named exceptions, and TEST-ACTION + DIAGNOSTIC/FIXTURE are
confirmed as exclusions. Anything the smooth walk still demands beyond the two named
exceptions STOPS the walk and lands as a finding, per the directive.
