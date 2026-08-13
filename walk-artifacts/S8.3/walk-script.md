# S8.3 site-management UI — box-walk script (founder-grade, Pawan drives)

**Nature:** a UI-heavy render-truth walk. Every badge / count / list on screen is TRACED to its wire source (the D6 ruling): the UI must render what the API says and nothing it doesn't. This is ALSO the dress rehearsal for the EPIC-8-close integrated walk after S8.5 — the script's quality pays twice.

**Branch:** `story/S8.3-site-ui` @ HEAD (post-fold + re-review-clean). **Convention:** each leg has **Steps → Expected → Observed (fill live) → Evidence (screenshot name)**. Capture a screenshot per leg into `walk-artifacts/S8.3/` with the named filename. A leg PASSES only when Observed == Expected AND the wire source is cross-checked (the API/health JSON behind the pixel).

---

## Environment prep (establish before Leg 1)

The walk reuses the **S8.2 three-agent topology** (see `walk-artifacts/S8.2/box-walk.md` for the recipe) plus a v4-pinned gateway for the CW confirm:

- **Hub** = `demo-gw` (endpoint-bearing → `is_site_hub`), bound to `site-hub`.
- **Spoke A** = `gw-a`, `site-a`, subnet `10.1.0.0/24`.
- **Spoke B** = `gw-b`, `site-b`, subnet `10.2.0.0/24`.
- **v4 gateway** = `gw-d` (`tunnex-node-v4`, `MaxSupportedVersion` pinned to 4), bound to a **second site** for the CW leg (Leg 6).
- **Enterprise org** with an **owner** (drives mutations) AND a **member** user (Leg 2 read-only). Seed both.

**Serve the SPA against the box API** — pick one:
- **(a) local vite + SSH tunnel (simplest):** `ssh -L 8080:localhost:8080 ubuntu@Tunnex-dev-vm` (forward the box API), then locally `pnpm --filter @tunnex/web dev` → browse `http://localhost:5173` (its `/api` proxy → tunnel → box).
- **(b) box-served:** build the bundle and serve it beside the API on the box; browse the box origin.

**Pre-flight (paste output):**
```bash
# on the box: stack up, migrations clean, the four agents reporting
docker compose ps            # api + postgres + the 4 node agents Up
# confirm gw-d reports max_policy_version = 4 (the CW input) and the hub is elected
curl -s localhost:8080/api/v1/organizations/$ORG/nodes -H "Cookie: $SESS" | \
  jq '.[] | {name, is_site_hub, max_policy_version, policy_degraded_kind, site_id}'
```
Expected pre-flight: one node `is_site_hub:true` (demo-gw); `gw-d.max_policy_version == 4`; site-bound nodes carry `site_id`. **If the dirty flag / migration state is off, STOP and paste — fix the marker, never walk through it.**

---

## Leg 1 — Topology renders wire-truth
**Steps:** Log in as the **owner**. Open **Sites**.
**Expected:**
- One card per site; each gateway rendered as a **list row** (list-of-one), never a scalar.
- The **hub** badge appears on `demo-gw` ONLY (from `is_site_hub`, backend-elected — cross-check it matches the `/nodes` JSON).
- Healthy gateways show **no** health badge; subnets show their **real** status (approved vs `· pending`), pending visually distinct.
- Each gateway row shows agent version + `· policy vN` where reported.
- No animation, no implied telemetry — every element traces to a field.
**Observed:** _(fill)_
**Evidence:** `leg1-topology.png`

## Leg 2 — Member sees read-only topology, NO queue, NO mutations (D5 + #2 fold live)
**Steps:** Log out; log in as the **member**. Open **Sites**.
**Expected:**
- The topology **renders** (member reads via `org:view` — the #2 fold; a 403/`load_retry` here would be the pre-fold bug).
- **No** "Register site" button, **no** per-card mutation buttons (advertise/bind/unbind/delete), **no** pending-approval queue section (absent, not disabled).
- Cross-check: the member's `GET /sites` + `/sites/{id}/subnets` return 200 (org:view), while any mutation would 403.
**Observed:** _(fill)_
**Evidence:** `leg2-member-readonly.png`

## Leg 3 — `site_link_down` badge flips live (Slice-1 enum-path fold, on the wire)
**Steps:** Back as owner. On the box, stop the hub (or a spoke link). Wait past the staleness window (~180s; keepalive keeps healthy links warm — the reason this reads true). Refresh **Sites**.
**Expected:** the affected gateway's health badge flips to **"site hub unreachable"** (`site_hub_down`) or **"site link down"** (`site_link_down`) — the S8.2 kinds now surviving API → TS union → badge. A dead bridge is NOT green. Restore the link → badge clears on the next refresh.
**Observed:** _(fill)_
**Evidence:** `leg3-linkdown-badge.png` (+ the `/nodes` JSON showing the kind)

## Leg 4 — Pending queue → approve → audit → routes (mutation via the audited path)
**Steps:** Advertise a subnet on a site (owner), or use an existing pending one. Open the **pending queue**; **Approve** it.
**Expected:** the queue lists the pending CIDR; Approve succeeds; the subnet flips to **approved** in the card and now routes; an audit row `site.subnet_approved` exists (cross-check the audit log). No mutation routed around the audited endpoint.
**Observed:** _(fill)_
**Evidence:** `leg4-approve-audit.png`

## Leg 5 — Refusal renders VERBATIM (D3)
**Steps:** Advertise a subnet that OVERLAPS an already-approved range (or the pool). Try to **Approve** it.
**Expected:** the UI shows the API's typed message **verbatim** — *"this subnet overlaps the {class} range {CIDR}; approval refused"* — naming the overlap class (site / pool / reserved) + the colliding range. No client-side disjointness re-check; the subnet stays pending, re-approvable.
**Observed:** _(fill)_
**Evidence:** `leg5-refusal-verbatim.png`

## Leg 6 — CW v5-upgrade confirm NAMES the sub-v5 gateway (the centerpiece)
**Steps:** Ensure the org is currently single-site-routable (only one site has an approved subnet) and `gw-d` (v4) is a bound gateway. Approve the **first subnet on the SECOND site** — the multi-site crossing.
**Expected:** a **blocking confirm** fires: *"Approving this subnet enables site-to-site routing, which requires policy version 5. These gateways cannot apply it and will deny all traffic until upgraded:"* and **names `gw-d`** (from its reported `max_policy_version:4` — absence would also count as below). The ceiling "5" comes from `meta.protocol_version`, not a hardcode. **Negative:** approving a subnet on the FIRST site never shows the confirm; an all-v5 fleet shows a clean confirm with no gateway list.
**Observed:** _(fill)_
**Evidence:** `leg6-cw-confirm.png`

## Leg 7 — Delete-site name-typed + present-tense cascade + audit real counts (D4)
**Steps:** On a site that has subnets AND at least one `dst_site`/`src_site` rule, click **Delete site**.
**Expected:**
- The cascade preview is **present-tense**: *"…cascades what currently references it: N rules and M subnets; the gateway is unbound."* (advisory, not a promise) — counts match `getSiteReferences`.
- The **Delete button stays dead** until the typed value EXACTLY matches the site name (try a near-miss first — stays disabled).
- On delete: the site + its subnets + the referencing rules are gone, the gateway is unbound, and the audit row `site.deleted` records the **actual** cascade counts (cross-check the audit log — they equal the preview absent a concurrent change).
**Observed:** _(fill)_
**Evidence:** `leg7-delete-cascade.png`

## Leg 8 — Access-page polish (the folded scope)
**Steps:** Open **Access**. Toggle Zero Trust mode across states; inspect the rules list + the Add-rule modal.
**Expected:**
- **Summary line** states: enforcing + N → *"N rules — default-deny active"*; enforcing + 0 → *"0 rules — ALL traffic denied"* rendered **LOUD** (bordered danger, not a caption); off → *"policy not enforced — open mesh"*. A failed rules load reads *"unavailable"*, never the 0-rules message.
- Rule **rows** show the user-subject (a per-user grant names the user) and expiry (a temporary grant shows its window; an expired one shows distinctly).
- The Add-rule modal shows **Source** and **Destination** as two labeled panels (fieldsets) — layout only, create/edit behavior unchanged.
**Observed:** _(fill)_
**Evidence:** `leg8-access-polish.png` (+ `leg8-zero-state-loud.png` for the enforcing+0 state)

---

## Deck-final leg list (the walk in one line)
topology render-truth · member read-only (no queue) · `site_link_down` badge flips · queue-approve→audit→routes · refusal verbatim · **CW confirm names gw-d** · delete name-typed + cascade + audit-real-counts · Access polish (loud zero-state).

## Verdict (fill at end)
Every on-screen badge/count/list traced to its wire source; the #2 member-read-only fold and the Slice-1 enum path both proven live; the CW confirm named the pinned-old gateway. _(PASS/notes)_
