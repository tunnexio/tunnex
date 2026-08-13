# S8.2c gateway zero-touch — WALK RECORD (demo-re-run, founder-present)

## PASS/FAIL LINE (Zero-Touch Gateway Law, `docs/laws.md`) — the single gate
**PASS** iff each gateway comes online by pasting the ONE dashboard-emitted install command, and the ONLY other manual actions are ONE guided cloud-console visit per side (Azure UDR / AWS route-table + src/dst-check). **FAIL** iff anything past the two pastes demands SSH to a gateway VM — any hand-added `--network host`, `TUNNEX_WG_BACKEND`, `src`-hint, forward rule, or `ip route` edit. **A FAIL leaves the story OPEN** (not merged). Guided cloud-console ≠ gateway-touch; the boundary is the gateway VM.

**This walk IS S8.2c's box-walk** and IS the **new-customer onboarding path**: it uses a FRESH SIGNUP for a clean org (the GAP-1 multi-org-switcher deferral means an existing owner can't spin a 2nd org in-session; fresh-signup is HIGHER fidelity than a switcher shortcut — it's exactly what a real new customer does). Re-runs the cross-cloud demo (`walk-artifacts/cross-cloud-demo/demo-record.md`) that took **6 manual gateway touches + 3 UI gaps** — proving every touch now collapses into a paste or the one guided console visit.

**Topology (re-use the demo's):** AWS Sydney `172.31.24.206` (VPC `172.31.0.0/16`) = hub · Azure West US `10.0.0.5` (VNet `10.0.0.0/24`) = spoke · a **separate Azure behind-host** `10.0.0.4` (the demo's `Tunnex-dev-vm`, same VNet) = the forwarded host · CP public `40.65.63.141`.

**FIXTURE-FIDELITY PRECONDITION (topology-sibling law, `docs/laws.md`) — binds Leg 2:** the cross-site ping MUST originate from a **genuinely separate FORWARDED host behind a gateway** (`10.0.0.4`), traversing the gateway's forward chain. **The `ping -I <gateway-host>` form the demo used does NOT count this run** — it's locally-originated, never forwarded, and hides the D1 forward-chain asymmetry (per our own law). If a separate behind-host isn't available, Leg 2 is INCOMPLETE, not passed.

---

## Legs (Pawan drives; fill expected-vs-observed inline)

### Leg 1 — ZERO-TOUCH JOIN + the metaLoaded gate proof
Enroll a gateway → copy the ONE emitted `docker run` → paste VERBATIM on a CLEAN cloud VM → `agent_ready` on real WireGuard, zero edits.
- **EXPECTED:** single-line command (no compose, no line breaks); bakes in `--network host`, `wgctrl`, `/dev/net/tun`+NET_ADMIN, the public CP URLs, servername, token, optional endpoint. Pasted verbatim → `agent_ready`, `wg show` fresh handshake, ZERO manual gateway edits.
- **EXPECTED (one-truth #5):** open the dashboard via an ALIAS/tunnel (not the raw public IP) and confirm the emitted command STILL carries the real configured CP public address (`meta.public_base_url`), NOT the alias origin.
- **EXPECTED (metaLoaded gate — the ONLY proof of this fix; it is component wiring, NOT unit-pinned):** on the enroll form, before `/api/v1/meta` resolves, the **"Generate join token" button reads "Checking control plane…" and is DISABLED**. There must be **NO flash of a mintable command before meta arrives** — no early-enabled Generate button, no placeholder/origin-based command, no half-formed token line. **ANY flicker of a mintable command in the in-flight window = a FINDING (WF-#), not cosmetics.** Watch the first render deliberately (hard-reload the page, eyes on the button).
- **OBSERVED (2026-07-18, enterprise CP redeployed from S8.2c source at 40.65.63.141):**
  - Command emitted (aws-gw): `docker run -d --name tunnex-node --restart unless-stopped --network host --cap-add NET_ADMIN --device /dev/net/tun -v tunnex_node_state:/var/lib/tunnex-node -e TUNNEX_JOIN_TOKEN=… -e TUNNEX_NODE_NAME="aws-gw" -e TUNNEX_NODE_ENDPOINT="15.134.231.13:51820" -e TUNNEX_API_URL="http://40.65.63.141" -e TUNNEX_AGENT_URL="https://40.65.63.141:8443" -e TUNNEX_AGENT_SERVERNAME="tunnex-control" -e TUNNEX_WG_BACKEND=wgctrl ghcr.io/iotunnex/tunnex-node-agent:latest`
  - ✅ single-line docker run (NOT compose — the D4 paste-mismatch shape is gone). ✅ host-net + wgctrl + tun + token baked in. ✅ review-#3 quoting LIVE: name, endpoint, api/agent url, servername all shell-quoted. ✅ one-truth #5: api/agent URLs derived from public_base_url (APP_BASE_URL=http://40.65.63.141), not window.location — mechanism correct (alias-divergence not stressed since browsing via the raw IP).
  - metaLoaded button state: _(pending explicit observation — the gate's only proof; re-check the button on a hard-reload)_
  - ✅ agent_ready on aws-gw (AWS `172.31.24.206`, ONE paste, zero other commands): `agent_backend_selected backend:wgctrl interface:wg0` → `agent_reconciling node_name:aws-gw` → `agent_wg_key_reported` → `agent_ready`. The Zero-Touch line held for aws-gw: the pasted docker run alone brought it online on real WireGuard.
  - ✅ agent_ready on azure-gw (Azure `10.0.0.5`, NAT'd spoke — the emitted command correctly had NO `TUNNEX_NODE_ENDPOINT`): `wgctrl` → `agent_reconciling node_name:azure-gw` → `agent_wg_key_reported` → `agent_ready`. One paste, zero other commands.
  - **Leg 1 = PASS for both gateways** — the two pasted docker-run commands are the ONLY terminal actions; both reached agent_ready on real WireGuard AND CP-registered into the fresh org (Devices → Gateways shows aws-gw + azure-gw, last seen 5-15s). The demo's per-gateway 6-touch friction (compose paste-fail, backend=mem, --network host, endpoint, urls, token) is fully collapsed into the one emitted command.
  - **STALE-VOLUME snag (walk-setup, NOT a product defect — but a doc gap worth a line):** first run reached agent_ready but did NOT appear in the fresh org. Cause: the emitted command mounts a FIXED named volume `tunnex_node_state`; these VMs hosted gateways in yesterday's cross-cloud demo, so the volume held the OLD demo identity — the agent booted cached, reconnected as the DEMO org's node (postgres_data persisted), agent_ready under the wrong org. Fix: `docker volume rm tunnex_node_state` then re-run → fresh enrollment into the current org, both appear. The zero-touch premise is a genuinely CLEAN VM; re-using a VM needs the volume wiped (or a re-image). Recommend a doc line + consider surfacing "this host already holds a gateway identity" on boot rather than silently reusing it. (Earlier mis-diagnosis as a :8443/NSG block RETRACTED — `curl` 000 on :8443 is just mTLS rejecting a certless curl, the channel is fine.)
  - **DEPLOY NOTE (not a leg finding, an infra prerequisite the walk exposed):** the CP at 40.65.63.141 was running a PRE-S8.2c OPEN-edition build; the walk required redeploying the S8.2c branch AS ENTERPRISE (the policy/rules surface Leg 5 needs is enterprise; sites/enroll/mesh are all-editions core). node-agent:latest was rebuilt+pushed to ghcr (the gateways pull it). A zsh `$1:latest` → `:l` modifier bug mis-tagged the first push (`*atest`); fixed with `${1}`.

### Leg 2 — FORWARDED behind-host reaches the remote site (D1 + D2, fixture-sibling)
From the separate Azure behind-host `10.0.0.4` (NOT the gateway) — plain `ping` (no `-I`), traversing the Azure gateway's forward chain.
- **EXPECTED:** `ping -c3 172.31.24.206` (or a host in the AWS VPC) from `10.0.0.4` succeeds — the first FORWARDED cross-site packet, mesh mode; the Azure gateway's nft LAN→tunnel forward counter INCREMENTS (D1 symmetric forward); the return path sources correctly (D2 src-hint), no overlay mis-source, and SURVIVES a reconcile tick.
- **PRECONDITION:** the `-I <gateway-host>` shortcut does NOT satisfy this leg (see the fixture-fidelity precondition above).
- **OBSERVED (D2 src-hint = PASS on the wire, 2026-07-18):**
  - aws-gw `ip route get 10.0.0.5 → src 172.31.24.206` (its LAN addr in 172.31.0.0/16), azure-gw `ip route get 172.31.24.206 → src 10.0.0.5` (its LAN addr in 10.0.0.0/24). Both source from the SITE LAN, NOT the overlay 10.99.0.1 — the exact demo bug (`src 10.99.0.1`) is FIXED. Site link up both ways (handshakes fresh, keepalive 25s, allowed-ips correct, route `proto static metric 8021`).
  - **D2 EXONERATED (was a false alarm):** first check showed `src 10.99.0.1` (no hint) — root-caused NOT to a D2 defect but to a STALE CACHED `node-agent:latest`. `docker run :latest` does not force-pull; the VMs ran yesterday's `main`-build agent (has S8.2 Routes → route landed, but NOT S8.2c D2 → no LocalSubnets/src). Verified the full D2 chain is correct in code (finalizeArtifact sets LocalSubnets alongside Routes · policyspec/nodepolicy json tags match · writeJSON encodes ds directly · reconcile reads ds.Policy.LocalSubnets · siteRouteSrc+ApplyRoutes apply src). `docker pull` the branch image + recreate → src-hint appears immediately. (3rd deploy sharp-edge, WF-2 family: `:latest`+`docker run` silently reuses a cached image; a re-used VM needs `docker pull`.)
  - **forwarded behind-host ping (D1) = MECHANICALLY PASS, but Zero-Touch FAIL (WF-4).** From the SEPARATE behind-host (CP VM `10.0.0.4`, not the gateway) → `172.31.24.206`: **142ms, 0% loss, ttl=63** (ttl decremented once = genuinely FORWARDED through azure-gw, satisfies fixture-fidelity). The azure-gw D1 rule (`iifname != "wg0" oifname "wg0" ip daddr 172.31.0.0/16 accept`) is present + correct. BUT it only worked after a manual `sudo iptables -I DOCKER-USER -j ACCEPT` on the gateway — see WF-4.

### Leg 3 — the ONE guided cloud-console visit, SURFACED IN THE UI
The un-codeable fabric (Azure UDR / AWS route-table + src/dst-check) is guided setup, ONE visit per side.
- **EXPECTED (D3/Slice-2 guided-setup scope):** the site/subnet UI **DISPLAYS the per-cloud "your fabric needs this route" instruction** on the page during the walk — detected/declared cloud, copy-paste snippet, doc link. **If Pawan has to REMEMBER the UDR/route-table step from the demo instead of READING it on the site page, that is a FINDING (WF-#) against D3/Slice-2's guided-setup scope** — the guided setup didn't ship its job.
- **EXPECTED:** adding the Azure UDR (one console visit) is what makes Leg 2 pass, and is the ONLY non-gateway manual step; NO SSH to the gateway VM after Leg-1 join.
- **OBSERVED:** _(the UI instruction screenshot + the console step)_

### Leg 4 — D3 the bridge-trap reassuring-green catch (loud, not silent)
Force a gateway advertising a subnet it isn't on (or bridge-trapped wg0) → `site_subnet_unreachable` fires LOUD even with a fresh link.
- **OBSERVED — SUBSTITUTE (live induction blocked by WF-5):** D3 fires only when ALL of a gateway's advertised subnets miss its host (siteRouteSrc returns on the FIRST match). azure-gw's real `10.0.0.0/24` matches host `10.0.0.5`, so adding a bogus `192.168.88.0/24` alongside it does NOT fire D3 — and the Sites UI has NO per-subnet removal (only Advertise / Unbind gateway / Delete site), so azure-gw can't be reduced to an all-miss set without deleting the site. **WF-5.** D3 wire-proof = named SUBSTITUTE (unit-tested: `TestSiteSubnetUnreachableSignal` + `TestRunOnceDerivesSrcHintAndUnreachableSignal`); trigger for the real proof = subnet-removal UI (WF-5) or a bridge-trapped-gateway rig.
- **Side-observation → WF-6 (investigating):** advertising the bogus subnet wedged azure-gw in `converging` ("syncing…", warn) for minutes. An out-of-hash `LocalSubnets`/`Routes` change should NOT move CanonicalHash → should not desync at all. If it stays converging / flips to silent_desync, it's a real finding (subnet-add wedges the gateway). [pending]

### Leg 5 — D5 site rules from the Access builder (GAP-2 closed) — PASS
Create a `site → site` grant from the Access Add-rule modal — through the API (validation + audit), NOT a raw DB insert.
- **OBSERVED (2026-07-18) = PASS:**
  - The Add-rule modal offers **Source type "Site (a LAN behind a gateway)"** AND **Destination type "Site …"** (D5). With no groups but sites present, it defaulted to `site` (the review #4 default-kind fix, live).
  - Created `azure-site → aws-site` via the modal → **audit log shows `policy.rule_created` · actor `tunnex` · `{"dst_kind":"site","src_kind":"site","src_site_id":…}`** — the API+audit path, NOT the demo's raw DB insert (GAP-2's whole point). Full walk audited: `org.created`, `node.token_issued`×2, `node.enrolled`×2 (system actor), `site.subnet_approved`×2, `org.zero_trust_enabled{mode:enforcing}`, `policy.rule_created`.
  - **Enforcing contrast (D1+D5) on the wire:** enforcing WITHOUT a grant → behind-host `10.0.0.4→172.31.24.206` = 100% loss (default-deny denies the ungranted forward); after the `azure-site→aws-site` grant → 0% loss, ttl-63. The grant re-permits the forward.
  - **Directional enforcement:** aws→azure (`172.31.24.206 → 10.0.0.4`) stayed DENIED until a reverse `aws-site→azure-site` grant was added → then 6/6, 0% loss. Two directional grants = bidirectional; each direction is independently gated (a clean routed-but-dropped contrast).

---

## FOLD STATUS (founder-dispositioned 2026-07-18: 6 fold, 2 defer)
- **WF-4 FOLDED** (`b6ca114`) — agent owns a Routes-scoped accept in DOCKER-USER; ForwardBlocked→siteSubnetUnreachable. Decision-first (`docs/S8.2c-decisions.md`). **Re-walk owed: delete the manual rule, behind-host ping survives on agent rules alone.**
- **WF-8 FOLDED** (`5db… WF-8 commit`) — site rules resolve to NAMES.
- **WF-6 CLOSED, no code** — out-of-hash exclusion holds (twin goldens); converging was the in-hash grant settling.
- **WF-2 / WF-3 / WF-5 FOLDED** (`07e40c3`) — pinnable image + boot log · in-UI cloud fabric · subnet removal.
- **WF-1 DEFERRED** → S8.5 L1-metrics rider (positive site-link health). **WF-7 DEFERRED** → first-request / epic-close UX harvest (site-rule editor).
- Gates green across the fold. Targeted re-review RAN (`wf_61dc1017`) → 5 CONFIRMED fold-induced defects → **re-review fold `79e6206`**: #1 DOCKER-USER /32 daddr churn (canonDaddr keys both sides as nft prints — host route bare), #2 transient `-a list` error → skip (no blind-insert duplicates), #3 Access banner includes `sr.ok`, #5 sweep-error logged; #4 GATEWAY_IMAGE :latest fallback kept as the honest floor. Reds added (/32 idempotent, list-error skip). **Leg-2 re-walk owed (Pawan) — the loop terminator, on live nft.**

## Findings (held WF-numbered for disposition — the founder brings dispositions back; fold only what's dispositioned)
| WF# | leg | finding | severity | disposition |
|-----|-----|---------|----------|-------------|
| WF-1 | Sites/2 | No POSITIVE site-link health on the Sites page — a healthy site-to-site link shows no "UP/linked/last-handshake" indicator, only degraded states badge (the "green=liveness-only" convention, inherited from device health). For site-to-site, liveness IS the product: a healthy link is visually indistinguishable from an idle/unconfigured one. Founder-noticed. | UX / design decide-item | HELD for founder — revisit green=liveness-only for the site surface (positive "linked · last handshake" vs convention) |
| WF-2 | setup/1 | Stale `tunnex_node_state` volume AND stale cached `:latest` image on a re-used VM → agent boots old identity/old code silently. `docker run :latest` does not force-pull; the zero-touch premise is a clean VM. Two instances hit this walk (wrong-org identity; missing-D2 code). | deploy/doc gap | HELD — doc line ("re-used VM: `docker pull` + wipe `tunnex_node_state`"); consider a boot-time notice + pinning the emitted image to a digest/`--pull=always` |
| WF-4 | Leg 2/3 | **ZERO-TOUCH LAW FAIL (headline).** Docker sets `filter FORWARD` policy `DROP` on the gateway host. The agent's D1 site-forward rule lives in its own `ip tunnex` table (accept), but Docker's separate FORWARD DROP is terminal — so site-to-site forwarding SILENTLY fails on every Docker-host gateway until the operator runs `iptables -I DOCKER-USER -j ACCEPT`. Proven: ping 100% loss → after the manual rule → 142ms/0% loss/ttl-63. This is the TRUE root of the demo's leg-(b) failure (blamed on Azure UDR alone; UDR necessary but Docker-FORWARD-DROP was the deeper blocker). A manual gateway SSH+iptables step is exactly what the law forbids. Also: the agent can't `sysctl` in-container (noted, but `ip_forward` was already 1 here). | Zero-Touch Law FAIL / correctness | **HALT + founder disposition.** Fix = the agent must insert an accept for its site-forward traffic into `DOCKER-USER` (or the system FORWARD path), scoped to `Routes` like the D1 rule — an agent-code fix slice, decision-first, re-reviewed. Then re-walk this leg. |
| WF-5 | Leg 4 | No per-subnet REMOVAL in the Sites UI — you can Advertise a subnet but never un-advertise/remove one; only Delete the whole site. Can't correct a mis-advertised/typo'd subnet, and blocks reducing a gateway to test D3. | UX / management gap | HELD — add subnet-removal (unadvertise) to the site card |
| WF-6 | Leg 4 | Advertising a subnet appeared to put azure-gw in `converging` for minutes; self-cleared. **DIAGNOSED — NO DEFECT.** Both CP + agent `projectForHash` are twin goldens (`Version/NodeID/Mode/Mesh/Allow` only — Routes + LocalSubnets EXCLUDED both sides); the desync-stamp (`service.go:706`) and health-kind (`policyhealth.go:159`) are purely hash-based → an out-of-hash subnet-add cannot move the hash, cannot converge. The converging traced to the in-hash GRANT changes (the enforcing site→site + reverse grants created moments earlier — `Allow` IS in-hash) settling through one report cycle: a correct push-settle, self-cleared. Multi-minute = report cadence + settle-window T, not a leak. | correctness (health) — CLOSED | NO CODE — exclusion holds; converging was the in-hash grant settling, not the subnet-add |
| WF-7 | Leg 5 | Site rules in the Rules list show only **Delete**, no **Edit**. By-design (`canEditRuleInModal` withholds edit for site rules — editing would rewrite them into group/resource rules), but it's a real UX limitation: changing a site grant (e.g. its expiry) means delete+recreate. | UX (by-design) | HELD — consider a proper site-rule editor, or make the delete-only nature explicit in the row |
| WF-8 | Leg 5 | Site rules render as `site 019f762b… → site 019f762b…` (raw truncated site UUID, not the site NAME). azure-site & aws-site are UUIDv7 created seconds apart → they SHARE the `019f762b…` prefix, so the two distinct rules look IDENTICAL. Should show `azure-site → aws-site`. (S8.3 `ruleRow` resolves site labels — the Access Rules list isn't feeding it the sites, or the resolution isn't wired here.) | UX / correctness (display) | HELD — resolve site rule endpoints to names in the Rules list |
| WF-3 | Leg 3 | Guided cloud-fabric setup (Azure UDR / AWS route-table + src/dst-check + IP-forwarding) is **docs-only** (`docs/deploy-cloud-gateway.md`), NOT surfaced on the site/subnet page. D3 RULED "the site/subnet UI surfaces per-cloud 'your fabric needs this route' instructions (detected/declared cloud, copy-paste snippets, doc links)." Slice 2 delivered the doc but not the in-UI surfacing — and the site page carries no link to it. Operator must find the doc, not read it in context. | scope gap vs D3 ruling | HELD for founder — was the in-UI guided-setup in scope for S8.2c or deferrable? At minimum, link the doc from the site page |

## RE-WALK SCRIPT (WF-4 loop terminator + fold spot-checks; Pawan drives)
The fold is in; this proves it on live nft (the loop terminator, not a 4th review round).
- **① Mac build+push** the WF-4 agent (`docker buildx … node.Dockerfile --push`). **RECORD the pushed digest** (`docker buildx imagetools inspect ghcr.io/iotunnex/tunnex-node-agent:latest` or the push output) — "the version the walk proved" must be a PINNABLE fact, not a moving `:latest` (WF-2's discipline applied to ourselves; the mild irony noted). **Digest (the WF-4 re-walk version): `ghcr.io/iotunnex/tunnex-node-agent@sha256:72eaab3849ae7a6d2f0cec353c4c1ea2dd0fab14d7470822e730b1bd7328bf50`** (multi-arch amd64+arm64; supersedes the pre-WF-4 `sha256:24efd269…`).
- **② CP VM** rebuild api+web+nginx from the branch (`git pull` + `TUNNEX_BUILD_TAGS=enterprise docker compose up -d --build`).
- **③ Both gateways** — DELETE the manual rule (`sudo iptables -D DOCKER-USER -j ACCEPT`), `docker pull` the agent, `docker rm -f tunnex-node`, re-run the same `docker run` (volume reuse = identity kept).
- **④ ZERO-TOUCH VERDICT — the ping + the IDEMPOTENCE handle-check (both required):**
  1. From the behind-host (CP VM `10.0.0.4`): `ping -c3 172.31.24.206` → want 0% loss with NO manual iptables present.
  2. On azure-gw: `sudo docker exec tunnex-node nft -a list chain ip filter DOCKER-USER` → note the `tunnex-site-fwd` rule's `# handle N`.
  3. **Wait ≥30s (≥1 reconcile tick), list again** → **SAME handle = idempotence proven on live nft** (the /32-churn class would pass a single ping but thrash the handle over ticks — this is the one gap between the red and reality). A CHANGED handle = the churn class survived → walk FAILS on it.
- **⑤ Spot-checks:** WF-8 (Rules show `azure-site → aws-site`) · WF-3 (site card "Cloud fabric setup" expander) · WF-5 (✕ on the bogus `192.168.88.0/24` — mini-proof + cleanup in one click).
- ④ passes → Zero-Touch Law SATISFIED → story flips to PASS → merge is Pawan's word.

## RE-WALK VERDICT (2026-07-19) — ZERO-TOUCH LAW SATISFIED → S8.2c PASSES
The WF-4 fold + its re-walk fix are PROVEN on live nft (cross-cloud AWS↔Azure), image `sha256:1b39c22e…`:
- **④ Forwarding works on AGENT-MANAGED rules alone — NO manual iptables.** Behind-host (CP VM `10.0.0.4`) → `172.31.24.206`: **3/3, 0% loss, 139ms, ttl-63** (forwarded). The agent placed BOTH Route-scoped accepts in DOCKER-USER — forward `iifname != wg0 oifname wg0 ip daddr 172.31.0.0/16` (handle 20) + return `iifname wg0 oifname != wg0 ip saddr 172.31.0.0/16` (handle 21), each `counter packets 3`. The manual `DOCKER-USER -j ACCEPT` was DELETED before the test — the forward survives on the agent's own rules. That is the Zero-Touch Law met for the forwarding path.
- **Idempotent on live nft** — same handles (20, 21) across a ≥30s reconcile tick: no thrash (the /32-churn class the re-review caught is dead).
- **Re-walk found + fixed one gap:** a forward-only accept passed the echo-request but Docker's FORWARD DROP killed the reply; fixed with the per-route RETURN accept (still Route-scoped, `db4425f`).
- **WF-2 boot log fired** (`agent_reusing_stored_identity`); image digest recorded (pinnable fact).
- **Spot-checks PASS:** WF-8 (Rules show `site azure-site → site aws-site`, names not UUIDs) · WF-3 (site card "Cloud fabric setup" expander) · WF-5 (`✕` on subnet chips).

**VERDICT: Zero-Touch Law SATISFIED. Story PASSES. Merge is the founder's word.**

---

## Original verdict (2026-07-18, first walk — superseded by the re-walk PASS above)

**ZERO-TOUCH LAW: FAIL → the story STAYS OPEN.**

What PASSED:
- **Leg 1 — zero-touch JOIN: PASS.** Both gateways came online from the ONE pasted `docker run` (single line, host-net + wgctrl + tun + token + CP urls baked in). The demo's per-gateway 6-touch friction is gone. Multiple folds proven live: review-#3 quoting (all env values quoted), one-truth-#5 (`public_base_url`, not window.location).
- **D2 src-hint: PASS (exonerated).** Both gateways source remote traffic from the site LAN, not the overlay. The initial "broken" reading was a stale cached image, not a defect.
- **Leg 5 — D5 site rules from the Access builder: PASS.** Site src/dst in the modal, created through the API with `policy.rule_created` audited (GAP-2's raw-DB-insert anti-pattern closed). Enforcing contrast on the wire: no-grant → 100% loss; grant → 0% loss; directional (reverse grant needed for the reverse flow). The review-#4 default-kind fix worked live.

Why it FAILS the bar:
- **WF-4 (headline): site-to-site FORWARDING requires a manual `iptables` on the gateway** (`DOCKER-USER -j ACCEPT`) — Docker's `filter FORWARD DROP` terminally drops the forwarded packet, which the agent's `ip tunnex` accept never overrides. Proven: 100% loss → after the manual rule → 142ms/0% loss/ttl-63. A gateway SSH+iptables step is EXACTLY what the Zero-Touch Law forbids. This is the true root of the demo's leg-(b) failure. **Until the agent inserts its own scoped accept into `DOCKER-USER`, the core value prop (a behind-host reaching a far site) is not zero-touch.**

Deferred / substitute:
- **Leg 4 — D3 `site_subnet_unreachable`: unit-tested SUBSTITUTE** (live induction blocked by WF-5, no subnet-removal). Trigger = subnet-removal UI or a bridge-trap rig.
- **Guided cloud-fabric (Leg 3): docs-only (WF-3)** — the Azure UDR / IP-forwarding was applied from `docs/deploy-cloud-gateway.md`, not surfaced in-UI as D3 ruled. This IS the one allowed guided console visit per side (boundary clause), so it doesn't itself fail the law — but the in-UI surfacing wasn't built.

**Disposition owed (founder):** WF-4 is the blocker (fix = agent inserts a Routes-scoped accept into DOCKER-USER, decision-first + re-review, then re-walk Leg 2). WF-1/3/5/7/8 are UX/scope gaps; WF-2 a deploy-doc gap; WF-6 a minor health-surface question. Full table above.

Cleanup pending: the bogus `192.168.88.0/24` on azure-site can't be removed via UI (WF-5) — clear via delete+recreate of azure-site or a DB row delete.

## Deferred / substitutes
- GAP-1 (in-session multi-org creation) DEFERRED — rides the org-switcher follow-on; the walk uses fresh-signup (the new-customer onboarding path), so it is NOT blocked.
- #7 (duplicate precedence ladders) DEFERRED from the fold — mechanical, no behavioral risk.
- The `metaLoaded` gate (re-review round-3) is component wiring, not unit-pinned — **Leg 1's button-state observation is its ONLY proof.**
