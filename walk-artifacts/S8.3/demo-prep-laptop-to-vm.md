# Demo prep — laptop-as-device → VM private IP (DEFERRED — device-path demo, founder-parked)

**PARKED (founder-directed): superseded by the cross-cloud site-to-site demo (`walk-artifacts/cross-cloud-demo/demo-script.md`).** Kept because its container→host-LAN routing honesty section is S8.5 input regardless. Not the active demo.

**Runs AFTER the S8.3 merge, on `main`.** Goal: your **laptop** (a Tunnex device) reaches the **VM's private IP `10.0.0.4`** through the tunnel, where the VM gateway advertises the VM host's `10.0.0.0/24` as a **site subnet** and a **Zero-Trust grant** permits device→site. This is client-to-site-resource using the S8 site machinery (NOT gateway↔gateway; S8.2 already wire-proved that).

**Honesty up front — this is exactly the gap S8.5 exists to close.** The gateway agent runs in a **docker container**; its advertised subnets today are dummy LANs, not the VM host's network. Making it route+NAT to `10.0.0.4` requires **hand-fiddling** at the container→host boundary. **LOG EVERY MANUAL STEP** below as S8.5 input — each command a real admin should NOT have to run is a line item for S8.5's "open-edition routed subnets" (Pritunl push-routes parity). The demo proves the *data path*; the friction proves *why S8.5*.

**Pawan confirms before we start:**
1. `10.0.0.4` is the VM's private IP, and from **inside the VM**: `ping -c1 10.0.0.4` succeeds.
2. `ip route get 10.0.0.4` on the VM host — note the interface (eth0?) + that it's the host's own/adjacent subnet.

---

## Leg 0 — prep (VM)
- Stack up on `main` (enterprise), the seed org + a gateway agent that CAN reach `10.0.0.4`. **Decision point (log it):** the containerized `node-agent` reaches the host `10.0.0.4` via its default route → host; confirm with `docker compose exec node-agent ping -c1 10.0.0.4`. If it can't, we either (a) run the agent with `network_mode: host`, or (b) add a container route + host forwarding — **whichever we do is an S8.5 line item** (an admin shouldn't hand-route a gateway to its own LAN).

## Leg 1 — register the VM's private subnet as a site
- Sites page (owner) → the VM gateway's site → **Advertise subnet** `10.0.0.0/24` → **Approve** (disjoint from the pool + other site subnets, or use `10.0.0.4/32` to scope to just the VM).
- Expected: approved, routes. Audit `site.subnet_approved · {"cidr":"10.0.0.0/24"}`.

## Leg 2 — gateway routes + NATs to the host LAN (the hand-fiddle — LOG IT)
- On the gateway (container or host), for traffic from the WG overlay → `10.0.0.4`:
  - forwarding on (`net.ipv4.ip_forward=1`),
  - **masquerade** out the host interface (`iptables/nft ... oifname != wg0 masquerade`, the S3.7 egress pattern — verify it covers `10.0.0.0/24`),
  - a route so the container reaches `10.0.0.4` (default route usually suffices).
- **Every command here = S8.5 input** (S8.5 compiles the routed range → forward rules automatically; today it's manual).

## Leg 3 — enroll the laptop as a device
- Install the Tunnex **desktop client** (macOS) on the laptop (built from the repo or a release), point it at the box origin, log in as a member/owner, **enroll** → the client brings up a WG tunnel to a gateway.
- Expected: device active; tunnel handshake to the gateway's public endpoint (`40.65.63.141:51820`).

## Leg 4 — Zero-Trust grant device→site
- Access page: create a group, put the laptop's device/user in it, add a rule **group → site** (`dst_kind=site` for the VM's site). Enforcing mode.
- Expected: the compiled policy permits the device to reach `10.0.0.0/24`; without the grant it's `default_drop` (routing ≠ permission — the S8.2 lesson).

## Leg 5 — the proof
- From the **laptop**: `ping 10.0.0.4` (and/or curl a service on it) **through the tunnel**.
- Expected: replies. Cross-check the gateway's forward-chain counters + `wg show` handshake/tx-rx.
- **Negative:** remove the grant → ping drops at the gateway forward chain (permission, not routing).

## Verdict + S8.5 input
- Record: did the laptop reach `10.0.0.4`? And the **list of manual steps** (Leg 0/2 especially) that S8.5 must automate — that list IS S8.5's scope evidence.
