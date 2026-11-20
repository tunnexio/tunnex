# SSI-10 — box walk, AWS ↔ Google Cloud

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md).

Status: **partial. One walk on 2026-11-20 covering SSI-1, 2, 3, 4, 8 and 9 slice 1 on real gateways.**
Not yet walked: a refused range and a colliding range on a real gateway, range removal timing
(SSI-6), a second gateway on one site (SSI-7b), `preserve_source` on the new network, the reverse
direction.

## Environment

| | AWS | Google Cloud |
| --- | --- | --- |
| Control plane | `cp.tunnex.app`, branch commit `eaca5cf8` layered on release v0.1.43 | |
| Gateway | `aws-gateway`, public endpoint, hub | `gcp-gateway`, no public endpoint configured, dials the hub |
| Network | AWS private: `172.31.37.55/32`, `10.50.1.0/24` | GCP private: `10.70.0.10/32` |
| LAN egress | `preserve_source` | `gateway_address`, chosen by the wizard default |
| Private server | `backend-app` `172.31.37.55` | `gcp-app` `10.70.0.10`, HTTP on 8080 |
| Cloud routes | one, added during the walk (below) | **none** |
| Forwarding permission | source/destination check turned off during the walk | IP forwarding flag **not set** |
| Enforcement | on | |

## What was done in the product

1. Enrolled `gcp-gateway` from the dashboard. The run command already named the upgraded agent image.
2. Set up a network on it. Review showed "This links 10.70.0.10/32 to 1 other network", listed the AWS
   ranges, said nothing crosses until a rule allows it, and offered the routing mode with Gateway
   address selected. Created.
3. Added resource `gcp-app` (`10.70.0.10/32`, TCP 8080). Add rule opened with no destination and
   Review disabled until one was chosen (SSI-3).
4. Added two rules: Security team → gcp-app, and site AWS private → gcp-app.

## Observations

| # | Observation | Proves |
| --- | --- | --- |
| 1 | Both gateways handshake; the hub's peer for Google Cloud carries `10.70.0.10/32`; the spoke's peer carries the AWS ranges and the device pool. `gcp-gateway` reports policy version 15, `aws-gateway` 6. Neither reports `site_subnet_unreachable` or `site_link_stale`. | The link, and that only the opted-in site's gateway moved to v15 (SSI-8). |
| 2 | On `gcp-gateway`: `ip saddr 10.50.1.0/24 oifname != "wg0" masquerade` and the same for `172.31.37.55`, each commented `tunnex_site_lan_masquerade`. | The render on a real gateway (SSI-8). |
| 3 | Laptop (device, through the AWS hub) → `http://10.70.0.10:8080`: **200**. Port 22: no answer. No cloud route exists for this path on either side. | Device → remote site needs nothing in either cloud. |
| 4 | `gcp-app`'s own access log records the client as `10.70.0.5`, the gateway. `gcp-app` has only its default route. | The LAN host sees the gateway and answers it without a return route (SSI-8). |
| 5 | Both gateways hold `ip saddr 172.31.37.55 … daddr 10.70.0.10 … tcp … 8080 accept` and `ip saddr 10.50.1.0/24 …` likewise. | A site → resource rule is placed on the destination gateway too, port-scoped (SSI-2). On main the destination gateway would hold nothing. |
| 6 | `backend-app` → `http://10.70.0.10:8080`: **200**; port 22: no answer. On `aws-gateway` the rule's counter read 2 after two requests and the default-drop counter rose for the port-22 attempts. | A port-scoped site rule admits exactly its port, end to end, with a real server on each side. |

## What the walk found that the tests could not

**The initiating side is not free in Quick mode.** `backend-app` → `gcp-app` failed until three things
were done on AWS:

| # | Change | How it was found |
| --- | --- | --- |
| 1 | Route `10.70.0.10/32` → the gateway instance in the VPC route table | expected |
| 2 | Source/destination check off on the gateway instance | expected |
| 3 | Gateway security group: allow TCP 8080 from `172.31.37.55/32` | a capture on the gateway's LAN interface showed no packet arriving; the security group admitted only the gateway's own service ports |

Google Cloud needed nothing. So the gateway-address mode removes all cloud work on the network a
connection **arrives** at, and none on the network it **starts** from. The first wording, "No cloud
return route is needed", was true and read as "nothing to do in the cloud". It now says what is and
is not removed, and a note beside both modes lists the three outbound requirements, including the
firewall one. Fixed in the same change as this record.

The preflight in SSI-9 slice 2 should check the third item where it can: it is the one an operator
has no reason to suspect.

**Rule counters reset.** Counters read zero for rules that had just admitted traffic, then read
correctly when read immediately after a request. The ruleset is re-applied on reconcile and the
counters start again. Not a defect in enforcement; it does mean a counter is not evidence unless read
at once.

## Side effects of the walk to know about

- The AWS control plane's `compose up` tries to start the compose gateway service, which collides
  with the standalone gateway container on UDP 51820. The failed container was removed.
- The AWS gateway security group now admits TCP 8080 from `172.31.37.55/32`, the VPC route table has
  `10.70.0.10/32`, and the control-plane instance has its source/destination check off.

## Gateway failover walk (2026-11-20)

Setup: `aws-gateway` (primary, pin 1) and `aws-gateway-2` (standby, pin 2, another availability
zone) in the first network; `gcp-gateway` in the second network as the only observer. A probe from a
connected device requested the AWS app and the Google Cloud app every few seconds throughout.

| Step | Measured | Notes |
| --- | --- | --- |
| Primary container stopped | 07:10:28 | |
| Primary judged stale | at handshake age 4 min 05 s | stale window is 240 s |
| Standby promoted | 07:15:33, about 5 min 5 s after the stop | third stale tick (`stale_n=3`) |
| Device traffic back | at the next probe, within about 20 s of promotion | no client reconnect; the device re-homed from the routed-ranges poll |
| Primary started again | restored as primary about 148 s later | five fresh ticks; generation 4, `demoted` cleared |
| Traffic during failback | every probe 200 to both apps | no loss |

Findings:

1. **Five minutes is the outage a single gateway loss costs today.** Nearly all of it is the 240 s
   stale window, which is sized to a passive WireGuard handshake report. An active probe from the
   observer would allow a much shorter window. Not built; needs its own decision paper.
2. **The dashboard and the controller disagree about "stale".** The gateway list marks a gateway
   Stale after 90 s; the controller acts at 240 s plus three ticks. For about two and a half minutes
   the dashboard shows a stale primary and nothing happening. Not fixed.
3. **During the wait the Failover tab shows no pending state**, only the result once it has ruled.
4. **No observer, no failover.** Same-network gateways do not peer, so an organisation with one
   network has no witness and never fails over. The Failover tab now says so (`2ac849b4`); the
   structural fix is not built.
5. Not checked in this walk: whether a promotion writes an audit event or raises an alert.

## Second failover walk, on the SSI-11 build (2026-11-20)

Control plane at `6c261a23` (API) and `7ee38aa5` (dashboard). Same three gateways.

| Step | Measured |
| --- | --- |
| Primary stopped | 13:19:18 |
| Failover tab: Stale badge and the pending notice appear | at handshake age 4 minutes, not before |
| Standby promoted, device traffic back to both apps | 13:24:23 probe, about 5 min 5 s after the stop |
| Primary started | 13:30:44 |
| Failover tab: "answering again, returns after about 2.5 minutes" | within a minute of the start |
| Restored as primary (generation 6) | by 13:33:40, about 2 min 55 s after the start |

What SSI-11 changed, as seen on the box: a healthy hub at 3 minutes handshake age reads Recent (it
read Stale before); the tab states the pending takeover and the pending return; the tab updates by
itself; the topology draws the standby on a dotted line to its network and marks a passed-over
primary as demoted.

New findings:

1. **Failback is not always free.** One probe to the Google Cloud app failed at the moment the primary
   was restored (the AWS app answered throughout). The first walk saw none. Treat failback as "a pause
   of a few seconds is possible", not "no loss". Not investigated further.
2. **Failover audit events show "not recorded" as the actor**, in the warning colour, under a banner
   that calls it a recording gap. `hub_set.promotion` and `hub_set.failback` are written by the
   controller with no actor on purpose. The audit page has no way to say "the system did this". Not
   fixed.

## Failover walks on the SSI-12 build (2026-11-20)

Control plane at `ad9c23ea`. Gateways unchanged (agent `eaca5cf8`); the new 10 s site-link keepalive
arrived as ordinary desired state. A probe from a connected device requested both private apps about
every three seconds.

| Run | Observer report interval | Primary stopped → standby promoted | Device downtime |
| --- | --- | --- | --- |
| before SSI-12 | 30 s (default) | about 5 min 5 s | about 4 min 55 s |
| A | 30 s (default) | 97 s | about 1 min 50 s |
| B | 10 s (`TUNNEX_AGENT_STATUS_INTERVAL=10s` on the observing gateway) | 51 s | about 1 min 6 s |

Failback after each run: the primary returned to its place 160 to 190 s after it was started.
Between runs the controller logged no stale tick for either hub: the faster rule did not misjudge a
healthy link in this lab. That is a few minutes of one topology, not a soak.

After promotion, devices took about 15 s more to move (their routed-ranges poll). That poll is now
the largest remaining piece of the downtime in run B.

Seen on the dashboard: the pending notice ("has not answered for 36 seconds... a standby takes over
within a minute") appears about 40 s after the stop; failover audit rows read `failover-controller`
as the actor.

Left as is: the Failover tab still titles the column "Handshake" and counts "stale handshake
reports", though the verdict now comes from receive progress.

## Found while re-recording on the SSI-13 dashboard (2026-11-20)

**Deleting the only other network demoted both hubs.** With "GCP private" deleted, its gateway stopped
reporting the hubs and its last rows froze, exactly as a dead hub's would. Both hubs were ruled stale
and demoted within two minutes (generation 22), and with no witness left nothing could restore them.
Fixed in `e7bf68ee`: only gateways bound to a network testify (`witnessRows`). After the fix the
controller logged `no-observation` for both hubs, and they were restored once the network existed
again (generation 23, none demoted).

Left as is: the dashboard's embedded setup still says "site" in a few sentences ("Your site and
approved route are saved", "This creates a site"), the range form labels its field "LAN CIDR", the
range-approvals table has a "Site" column, and the confirm button of "Remove range" rendered with no
visible label.
