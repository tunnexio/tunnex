# LS-UX-2 — Local Sharing reviewer experience and the member console

Branch `story/ls-ux-2` (from `origin/main` 80cd04d2 = v0.1.49). Local only until the founder
says otherwise. Internal code name of the feature is **Beam**; customers only see **Local Sharing**.

Trigger: the founder walked the demo (v0.1.49) as `reviewer@tunnex.io` (organization role
**member**) and opened a share someone else published, then the Shared with me list, then the
Review feedback section. This paper is the full-feature audit the founder rule asks for: every
Local Sharing page and state for each role, plus the member's whole console navigation. Every
finding is listed with its disposition. Nothing is left open unless section E says why.

Read end to end for this paper: `apps/web/src/pages/Beam.tsx`, `components/BeamFeedback.tsx`,
`components/BeamShareMobile.tsx`, `lib/beam.ts`, `lib/beam-rooms.ts`, `components/AppShell.tsx`,
`components/CommandPalette.tsx`, `components/DevicesTabRail.tsx`, `pages/Dashboard.tsx`,
`pages/Alerts.tsx`, `pages/AccessEvents.tsx`, `pages/DeviceApprovals.tsx`,
`pages/DevicePosture.tsx`, `pages/AgentsMCP.tsx`, `pages/AuditLog.tsx`, `lib/rbac.ts` and the
generated `lib/rbac-policy.json`, and on the API side `internal/beam/{resources,authority,feedback,
notifications,model}.go` plus the HTTP permission gates for every sidebar destination.

---

## A. Roles walked

| Role | How it reaches Local Sharing |
|---|---|
| Publisher | Publishes from CLI/desktop; owns My shares, can pause/resume/stop/extend and change reviewers. |
| Invited reviewer | Organization member granted on a share (user or group grant), lands on Shared with me or on `/beam/launch` from the link. |
| Organization admin/owner | `beam:manage_all` + `beam:policy_manage`: may manage any share, sets the sharing policy, reads Events. Not automatically a reviewer. |
| Server administrator | `cp_admin`: owns installation serving setup (domain, readiness). |
| Member not invited | Same organization, no grant. |
| Invited reviewer, share paused / expired / stopped / ended by policy | Grant still present, share not openable. |
| Link opened while signed out | `/beam/launch?...` behind `RequireAuth`. |
| Link opened by the wrong account | Signed in to another organization, or to the right organization without a grant. |

---

## B. Local Sharing findings (one row per issue)

Status: **Fixed** = fixed in this branch. **Kept** = checked, deliberately unchanged, with reason.

| # | Page / state / role | Finding | Disposition |
|---|---|---|---|
| L1 | Share detail, reviewer | Breadcrumb always says **My shares / name**, even for someone who does not own the share. | **Fixed.** Breadcrumb follows the viewer: publisher → *My shares*, reviewer → *Shared with me*, organization manager looking at someone else's share → *Local Sharing*. |
| L2 | Share detail, reviewer | A **Sharing status** card says *"You do not have permission to manage this share."* — a negative dead end for someone who was never meant to manage. | **Fixed.** Removed. Reviewers get a **Shared app** card: *Shared with you by Name (email)*, browser link, created, expires with remaining time, status sentence, and Open app, Open on phone, Copy link, Review feedback. The **Manage sharing** card renders only when `can_manage`. |
| L3 | Share detail + Shared with me | Nothing says **who shared the app**; the list column shows the name only ("Control Plane Admin"). | **Fixed.** API adds `publisher_email` to the share projection; the console shows `Name (email)` everywhere (list column, detail). See C for why this leaks nothing. |
| L4 | Share detail, organization manager on someone else's share | No indication that the share belongs to someone else. | **Fixed.** *Published by Name (email)* fact. Ended status sentence says only its publisher can share again (the old text told the manager to publish from the CLI). If the manager is not a reviewer, the page says why Open app is unavailable. |
| L5 | Share detail, reviewer, paused / offline / local app down / starting | Status pill only (*Paused*, *Publisher offline*); Open app area says the same word. No explanation of what to do. | **Fixed.** One plain sentence per status for the viewer (`beamStatusHint`): reviewer is told who can change it (*"Pat (pat@x) has paused this share. You can open it again when they resume it."*), publisher is told what to do. |
| L6 | Share detail, reviewer, ended (stopped / expired / revoked) | Text said *"Create a new share using the CLI or desktop client"* — reviewer cannot. Copy link and Open on phone still offered for a dead link. | **Fixed.** Reviewer: *"This share has ended. Ask Name (email) for a new link…"*. Copy link / Open on phone hidden once ended. *Expires* reads *Ended or expired* with no countdown. The **Manage sharing** card is not shown for an ended share (nothing left to manage); the status sentence carries the next step for every viewer, so the page never repeats it twice. |
| L7 | Share detail, reviewer, ended share — feedback section | Server closes the review room when the share ends (`feedbackAuthority` → `source`), so the feedback panel showed the raw **"Share not found"** under a share that had just loaded. | **Fixed.** A non-publisher on an ended share is told *"Feedback closed when this share ended."* and no request is made. A not-found from the feedback API for a non-publisher is shown as the same plain sentence, never the raw message. Server rule unchanged (pinned by a new Go test). |
| L8 | Share detail, organization manager who is not a reviewer — feedback | Same raw **"Share not found"** in the feedback section (managers may manage, but the review room is publisher + reviewers only). | **Fixed.** *"Feedback is visible to the publisher and the share's reviewers."* Rule unchanged. |
| L9 | Share detail, member not invited / share does not exist / access withdrawn | Raw **"Share not found"**, breadcrumb *My shares*, no way forward. | **Fixed.** One uniform sentence for all three (the server already answers them identically): *"This shared app isn't available to your account. The share may have ended, or the person who shared it hasn't given your account access. Ask them to check the link and who it is shared with."* plus *Go to Shared with me* and *Check again*. |
| L10 | Share detail, reviewer whose grant is removed while the page is open | The 5-second poll appended the raw error to *"Current share access could not be checked…"*. | **Fixed.** A not-found during polling replaces the page with the uniform sentence (L9). Other poll failures keep the existing "refresh before another change" safety text. |
| L11 | Share detail, reviewer, Copy link | Notice said *"Reviewers still need current access…"* — written for the publisher. | **Fixed.** Reviewer: *"Link copied. Anyone you send it to needs their own access and sign-in."* |
| L12 | Shared with me | Connectivity filter **"All connectivity"** (Online / Offline or reconnecting / Local app unavailable) is publisher jargon; reviewers already see status per row. | **Fixed.** Removed for reviewers. Publishers keep it, renamed **Connection: Any connection / Connected / Your client offline or reconnecting / Local app not responding**. |
| L13 | My shares + Shared with me | Search box **and** a separate **Search** button **and** a refresh icon; filters only applied when Search was pressed. Other console lists (App Access) filter as you type. | **Fixed.** Search filters as you type (300 ms), selects apply on change, the Search button is gone. Refresh stays (it re-reads live status, which typing does not). *Clear share search* renamed *Clear filters*. |
| L14 | Both lists, bell **"Preview updates"** | Meaning unclear to a reviewer. | **Fixed.** Renamed **Sharing updates**; the panel says what it holds for this person: *"Apps shared with you that are ready to open, shares about to expire, and new review feedback, on your shares and on apps shared with you."* |
| L15 | Lists, app tile initials ("CP") | Could be mistaken for a person's initials. | **Kept.** App tiles are rounded squares in the sharing palette; people avatars are circles in the accent colour. Recorded, no change. |
| L16 | Review feedback, layout | A large *No feedback yet / Open the preview and share your review here* empty state sits above, and the form is below another divider: the reviewer scrolls past an empty box to find where to write. | **Fixed.** Form first, then *Earlier feedback*. Empty state is one compact line that matches the page: reviewer *"No feedback yet. Yours will be the first."*, publisher *"No feedback yet. Reviewers' comments appear here."* |
| L17 | Review feedback, decision select | Select showed a crimson border that read like an error. Cause: it is the console-wide **focus** colour (`--tnx-focus` #C2444F, shared token), not validation. The options *Comment / Approved / Changes requested* did not say what they mean. | **Fixed.** Replaced the select with three labelled choices with one-line meanings: **Comment** (*a note without a decision*), **Approve** (*tell the publisher it looks good*), **Request changes** (*ask the publisher to change something*). The focus token itself is a console-wide design decision and stays. |
| L18 | Review feedback, screenshot | Unstyled native *Choose file / No file chosen*. | **Fixed.** Console-style **Attach screenshot** button (same pattern as Server Access *Import recording*), shows the chosen file name and *Remove screenshot*. PNG/JPEG ≤ 10 MB rule and the secrets warning kept. |
| L19 | Review feedback, Send button | Grey with no hint why. | **Fixed.** Disabled state explains itself: *"Write feedback, attach a screenshot or choose Approve or Request changes to send."* |
| L20 | Review feedback, who sees it | Not said. | **Fixed.** *"The publisher and the share's other reviewers see your name, email, decision, comment and screenshot."* |
| L21 | Review feedback, after sending | Checked: confirmation notice, list reloads to page 1, form clears. Publisher sees it in the share's feedback list and as *New feedback on <name>* in Sharing updates (in-console only; there is no email). Author shown as name only. | **Fixed (naming).** Authors shown as `Name (email)` (API adds `author_email`, visible only to participants who can already read the feedback). Confirmation reworded *"Feedback sent. The publisher sees it on this page and in Sharing updates."* |
| L22 | `/beam/launch`, link opened while signed out | `RequireAuth` keeps the full `/beam/launch?...` in `next`; sign-in returns there. | **Kept** (correct). |
| L23 | `/beam/launch`, wrong account — other organization | *"Switch to its organization"* even when the account is not a member of it (cannot switch). | **Fixed.** If you belong to that organization: **Switch organization** button. Otherwise: *"You're signed in as you@x, which isn't in the organization that shared this app. Sign out and sign in with the account the link was sent to."* with **Sign out**. Only states facts about the signed-in account. |
| L24 | `/beam/launch`, right organization, not invited | Raw **"Share not found"**. | **Fixed.** Uniform sentence (L9) naming the signed-in email, plus Sign out (to switch accounts) and Check again. |
| L25 | `/beam/launch`, paused / ended / offline | Disabled *Continue to …* with only a status pill — dead end. | **Fixed.** Status sentence (L5/L6) and **Check again**. |
| L26 | `/beam/launch` | *Review feedback* link shown before (and even if) the share loads. | **Fixed.** Only after the share loads. |
| L27 | Shared with me, ended shares | Ended shares are not listed for reviewers (server filters before pagination). | **Kept** (correct; history belongs to the publisher). |
| L28 | My shares for a former publisher, Events for non-managers, setup notices per role | Checked: former publisher keeps history; Events tab only with `can_manage_policy`; setup notice names who to ask (server admin vs organization admin). | **Kept.** |
| L29 | Notifications for a reviewer of an ended share | Server skips shares whose review room is closed. | **Kept.** |

---

## C. Security analysis (unchanged posture)

* **Publisher email.** Added to `decorate()`, which runs only after the share was read by its
  publisher, an organization manager (`beam:manage_all`), or a current grantee (`reviewer()`
  passed in `Get`, or the grant-filtered `listProjectQuery`). A member who is not invited still
  gets the same 404 `beam_share_not_found` as for a share that does not exist; a new Go test pins
  that the two refusals are byte-identical and that the outsider list is empty. Every organization
  member already holds `member:list` (names and emails of all members), so the email is not new
  information to anyone who can see the share.
* **Feedback author email.** Added to the feedback projection, which is served only after
  `feedbackAuthority` (publisher or current reviewer with an open review room). Same reasoning.
* **Refusal pages stay uniform.** The console maps `beam_share_not_found` to one sentence and
  never distinguishes "never invited", "withdrawn", "ended and not yours" or "does not exist".
* **Wrong-account page** only uses facts about the signed-in account (its email, its own
  organization list). It never names the other organization.
* **Navigation hiding is UX only.** Every API keeps its own permission check; the role-aware nav
  and the "ask an admin" states change nothing on the server.
* **No contract field marked `format: email`** for the two new strings: the generated CLI type
  would validate on decode and could fail to parse a share for an unusual address.

---

## D. Member console audit (organization role **member**)

Member permissions (generated `rbac-policy.json`): `ai_model:use, app_access:use, beam:create,
beam:manage_own, beam:use, connectivity:use, member:list, org:view, sandbox:create,
sandbox:manage, sandbox:view, server_access:replay, server_access:use, vault:use`.

| # | Destination | Server answer to a member | Before | Disposition |
|---|---|---|---|---|
| M1 | Overview `/dashboard` | `org:view` reads succeed; `devices/pending` and `policies` 403 (tiles silently dropped). | The admin fleet view: org-wide gateway/site/member counts, *Waiting for you* admin items, *Get started* setup cards, *Setup guide* link — all pointing at pages a member cannot act on. | **Fixed.** People without network administration (`org:update` or `policy:view`) get **Your workspace**: their own devices with *Add a device*, and cards for the areas they can use (App Access, Server Access, Local Sharing, Vault, AI Gateway playground, Sandboxes when enabled), with *"For anything else, ask Name (email)"*. Admins keep the fleet view unchanged. |
| M2 | Gateways | `org:view` read-only inventory. | Shown. | **Hidden** for roles without `org:update`/`site:manage`. Direct URL keeps the existing read-only page (no error). |
| M3 | Site-to-site | Read-only topology; dns-forwards 403 per site. | Shown. | **Hidden** without `site:manage`/`ipsec:manage`. Direct URL unchanged (already role-gated, failures named). |
| M4 | Kubernetes | Read-only. | Shown. | **Hidden** without `k8s:manage`/`k8s_scope:view`/`k8s_ha:view` (operators keep it). |
| M5 | AI Gateway | `ai_model:use` → Playground. | Shown, already scoped. | **Kept** (any of `ai_model:use`, `ai_gateway:view`). |
| M6 | AI Agents | Read-only inventory. | Shown. | **Hidden** without an agent management/grant/request permission. |
| M7 | MCP | 403; friendly card exists. When the org feature is off, it showed *Open feature settings* to people who cannot open them. | Shown. | **Hidden** without `agent_template:manage`. Feature-off link shown only to people who can manage; others read *"Ask an organization admin to turn on MCP management."* |
| M8 | Access Policies | 403; friendly member gate exists. | Shown. | **Hidden** without `policy:view`. |
| M9 | Devices | Own devices only (server-filtered) + Add device. | Shown; **Approvals** and **Posture** tabs always visible and show the raw permission message. | **Kept**; Approvals/Posture tabs only with `device:approve`, decided from the roster the Devices page already reads (no extra request); a failed roster keeps both tabs. Direct URL shows the admin-only notice (M20). |
| M10 | Users & Groups | `member:list` roster, read-only; groups 403. | Shown. | **Hidden** without `member:manage`/`member:invite`. Direct URL unchanged (read-only roster, invitations already say no permission). |
| M11 | App Access | `app_access:use`; already redirects to My applications. | Shown. | **Kept.** |
| M12 | Server Access | `server_access:use`; *My servers*, names admins to ask. | Shown. | **Kept.** |
| M13 | Local Sharing | `beam:use`. | Shown. | **Kept** (this paper, B). |
| M14 | Tunnex Vault | `vault:use`, personal entries. | Shown. | **Kept.** |
| M15 | Alerts | 403 on Active/History. | Shown; raw *"you do not have permission to perform this action"* with Retry. | **Hidden** without `alerting:manage`; direct URL shows the admin-only notice. |
| M16 | Access Events | 403 (`policy:view`; App Access source needs `app_access:event_view`, Local Sharing source `beam:audit_view`). | Shown; raw message with Retry. | **Hidden** without any of those; direct URL shows the admin-only notice. |
| M17 | Audit Log | Own actions only, page already says so. | Shown as *Audit Log*. | **Kept, relabelled** *My activity* for people without organization-wide audit (owner/admin), so the nav matches what the page shows. |
| M18 | Settings | Authentication (MFA, SSO self-link) and Licence & plan. | Shown. | **Kept.** |
| M19 | Command palette (⌘K) | Listed every destination for everyone. | | **Fixed.** Same role filter as the sidebar. Entity search unchanged (reads a member may already make). |
| M20 | Admin-only page reached by URL | Mixed: raw messages (Alerts, Access Events, Device Approvals/Posture), friendly cards elsewhere. | | **Fixed.** One shared **AdminOnlyNotice**: *"<Page> is managed by organization admins. Your account can't open it. If you need something here, ask Name (email)."* with a link back to Overview. No codes, no alarm styling. |

Role resolution: one hook `useMyOrgRoles` reads the member list (`member:list` is held by every
human role) and uses `roles ?? [role]`, so multi-role users are right (the older
`roleFromMembers` reads only the primary role; left as is for the pages that use it, out of
scope). While roles load, gated items are not shown; if the read fails, **every** destination is
shown (a failed read must never remove a destination — the server still decides). The
destination set is the same at every width (responsive contract) for a given role.

Other membership roles checked against the same table: **ai-admin / ai-view** keep AI Gateway and
get the workspace overview; **owner / admin** keep every destination. (The `operator` grant set
exists in `rbac.go` for machine identities; it is not a membership role in the Member schema, but
the rules would keep its Kubernetes, Agents, Access Policies and Access Events.)

Build notes (folded during the build):

* The role read shares one in-flight request but never reuses a settled answer, so a role change
  shows on the next page without a reload.
* Shared chrome that renders without a signed-in person (isolated pages, the palette in tests)
  treats roles as unknown and withholds nothing.
* Routes gated by URL: `/alerts`, `/access-events`, `/devices/approvals`, `/devices/posture`,
  `/mcp`, `/users/groups`. Pages that already answer a member with a friendly state or with
  read-only data (Access Policies, Users, Gateways, Sites, Kubernetes, Agents) keep their own
  behaviour by URL.

---

## E. Open findings

None. Two notes that are decisions, not open work:

* The crimson focus edge (L17) is the console-wide `--tnx-focus` token; changing it is a design
  system decision outside this story. The feedback form no longer uses a select there.
* Read-only admin inventories (Gateways, Sites, Kubernetes, Agents, Users) still answer a member
  by URL, because the API serves them under `org:view`/`member:list`. Hiding them from navigation
  is UX; narrowing what the API serves is a security/product change, not part of this story.

---

## F. Verification plan

* Go (both editions, throwaway Postgres + Redis): `TestBeamReviewerSeesPublisherIdentityOnlyWhenPermitted`
  plus the full API suite (the share projection changed).
* `make generate-check` equivalent: beam contract regenerated (web types + CLI models).
* Web: typecheck, full vitest suite (`LANG/LC_ALL=en_US.UTF-8`, `TZ=UTC`), build. New tests for
  every B and D row marked Fixed.
