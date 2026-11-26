# LS-UX-4 — Local Sharing publisher and admin polish

Branch `story/ls-ux-4` from `origin/main` (includes LS-UX-3). Local only until the founder says
otherwise. Internal code name **Beam**; customers see **Local Sharing**.

Trigger: live walk on v0.1.51 of the share page (`/beam/shares/:id`) as the **publisher, who is
also the organization admin**, followed by the founder rule: audit every Local Sharing page, state
and role in the web console and fix what is found in one branch. Follows
`docs/LS-UX-2-reviewer-and-member-experience.md` and `docs/LS-UX-3-reviewer-polish.md`.

Security is unchanged. No API, policy or freshness change; the server still enforces the 5-minute
MFA freshness (`internal/beam/authority.go`), the lifetime ceiling (`resources.go` `extend`) and
the reviewer allowlist (`validateSubjects`). `check:beam` must stay clean and `make generate-check`
is not needed. Wording follows the desktop client: *"Reviewers: Alice, Developers group"*,
*"1 hour"*, *"Already at your organization's maximum lifetime of 1 hour."*

Read for this paper: `pages/Beam.tsx`, `components/Beam*.tsx`, `components/InlineTerminalMfa.tsx`,
`components/AppAccessMfaChallenge.tsx`, `lib/beam.ts`, `lib/beam-rooms.ts`, `lib/beam-clock.ts`,
API `internal/beam/{resources,feedback}.go`.

## Server facts the decisions rely on

- **Publisher's own grant.** Share creation always inserts `{user, publisher_id}` into
  `beam_grants` (`resources.go` `grants := append([]Grant{{"user", a.ID}}, in.Grants...)`), so
  `share.grants` always contains the publisher. The grants `PUT` *replaces* the whole set and
  does not re-add it, and the reviewer choices (`Audience`) list the publisher too. The desktop
  client hides this entry.
- **Extend.** Refused unless the new expiry is after the current one and not after
  `created_at + policy.max_duration_seconds` (current policy, not the one at creation). The
  picker works in whole minutes.
- **Publisher feedback.** The publisher passes the feedback gate (`feedback.go` `r.PublisherID == a.ID`)
  and may write any status.

## Decisions

| # | Page / state / role | Finding | Decision |
|---|---|---|---|
| P1 | Manage sharing (publisher, manager) | *"Maximum lifetime is 1 hours from creation."* Hours computed as a float (90 min → *1.5 hours*). | **Fix.** One formatter `beamDuration(seconds)` in `lib/beam.ts`: whole minutes, *"1 hour"*, *"2 hours"*, *"1 hour 30 minutes"*, *"1 minute"*, *"45 minutes"*; plus `beamCount(n, "share")` for *"1 share" / "2 shares"*. Sentence: *"Your organization allows a share to last up to 1 hour from when it was created. Reconnecting never extends it."* |
| P2 | Everywhere in Local Sharing web | Other unpluralized or float counts: CLI dialog *"Maximum lifetime: N minutes"*, saved project *"60 minute default · 2 reviewer selections"*, reviewer change dialog *"1 grants removed; 1 reviewers…; 1 current reviewer sessions"*, policy change dialog *"1 active shares; 1 shares and 1 current reviewer sessions"*, domain change dialog *"1 active shares across all organizations"*, *"1 saved reviewer choices are no longer permitted"*. | **Fix.** All use `beamDuration` / `beamCount`. Policy lifetime field (minutes) shows the formatted value under it (*"Shares can last up to 1 hour."*). |
| P3 | Share settings card (publisher, manager) | *"Audience: 2 selected users or groups"*: jargon, and the count includes the publisher's own implicit grant. | **Fix.** Fact is **Reviewers**, listing names as the desktop client does: *"reviewer (reviewer@tunnex.io), Developers group · 1 member"*, people as `Name (email)`, groups as *"Name group · N members"* (from LS-UX-3 `member_count`), at most 3 then *"+N more"*. The publisher's own grant is never shown or counted. None selected: *"No reviewers yet. Add them under Reviewers."* If the reviewer choices could not be loaded (names unknown), counts: *"1 person and 1 group"*. A grant whose subject is no longer in the reviewer choices is counted in *"+N more"*. |
| P4 | My shares list, Reviewers column | *"N selections"* (includes the publisher); *"Not reported"* when absent. | **Fix.** Counts without the publisher: *"1 person"*, *"2 people and 1 group"*, *"None yet"*; absent stays *"Not reported"* (the console bans the em dash as a placeholder, `placeholderglyph.test.ts`). Names are not available in the list (no reviewer directory is loaded there; loading it per list would add a request per page for every publisher). Names stay on the share page. |
| P5 | Reviewers card, share page (publisher, manager) | The reviewer picker offers the publisher's own account; unticking it silently removes the publisher's own access. Copy says *"Removing the last matching grant ends that reviewer's access"*; button *"Review reviewer access"* is always enabled, even with nothing changed. | **Fix.** The publisher's own entry is hidden from the picker and always kept in what is saved (the server needs it to let the publisher open their own app). Copy: *"Choose who can open this app. Anyone you remove loses access straight away, unless a selected group still includes them."* Button **Save reviewer changes**, disabled while nothing changed with the visible reason *"Select or clear a reviewer to make a change."* Dialog **Confirm reviewer changes**: plural sentences (*"1 reviewer choice removed. 1 person loses access. 2 open sessions end."*), checkbox *"Remove these reviewers and end their access"*, confirm **Save reviewers**. The CLI dialog and saved-project editor pickers also hide the signed-in publisher (the server adds them anyway). |
| P6 | Manage sharing, Extend expiry, share already at the policy maximum | Grey disabled **Extend expiry** with no reason; date picker still shown. | **Fix.** When `created_at + max lifetime` is less than a minute after the current expiry, the picker and button are replaced by *"Already at your organization's maximum lifetime of 1 hour."* (also covers a policy lowered after the share was created). Otherwise the button explains its other disabled states in a line under it: *"Choose a new expiry first."*, *"Local Sharing is turned off for this organization."*, *"Local Sharing isn't available on this server right now."*, *"Refresh the share before another change."* |
| P7 | Manage sharing, Resume share | Disabled with no reason when the feature is off or the server is not ready. | **Fix.** Same reason line as P6 under the buttons. |
| P8 | Review feedback, publisher | Form (Comment / Approve / Request changes + textarea) first; reviewers' feedback under *"Earlier feedback"*. For the publisher the received feedback is the content; approving one's own share means nothing. | **Fix.** For the publisher the list comes first under **Feedback from reviewers**, each item with a decision badge (*Approved* green, *Changes requested* amber, *Comment* neutral). The publisher keeps a way to answer: a **Reply to reviewers** button under the list opens a comment-only form (no decision radios, textarea *"Your reply"*, optional screenshot, **Send reply**); after sending it closes. Replies show *"· Publisher"* after the author, for everyone. Reviewers keep LS-UX-2's order (their form first) with the list titled **Feedback so far** and the same badges. Managers who are not reviewers keep LS-UX-2's closed message. |
| P9 | Review feedback, while loading | *"Feedback can be added while this share is available to your account."* flashes before the list loads. | **Fix.** Nothing is shown while loading except the loading line. The sentence is only used when the feedback could not be loaded for another reason. |
| P10 | MFA-required panels after verifying elsewhere | The feedback section kept *Verify MFA* after the user verified in another section or tab, until a manual refresh. | **Fix.** New `lib/mfa-events.ts`: `announceMfaVerified()` is called after every successful step-up in the console (`InlineTerminalMfa`, `AppAccessMfaChallenge`, the Open shared app code box). It fires a same-tab window event and a `BroadcastChannel("tnx-mfa")` message to other tabs (no data, just a ping; no code or session detail). `useMfaRecheck(active, recheck)` listens to that event, window `focus` and `visibilitychange` → visible **only while a panel is in its MFA state**, so normal views make no extra requests. Feedback (read), Sharing updates and the screenshot viewer re-read; if the server still refuses, the prompt stays (an open code box is not closed). A waiting draft (*send*) is never sent automatically: the prompt is cleared on a verified event so **Send** works again, draft kept. The Open shared app page re-offers **Continue** only on a verified event (not on focus), because the launch is a click the reviewer makes. |
| P11 | Share page, *Diagnostics & event history* (publisher, manager) | Jargon: summary title; *"Share diagnostics"*, *"redacted support snapshot…serving health"*, *Connectivity*, *Serving checks: Current*, *Saved version*, *"publisher authority checks"*, *"connector credential"*, *"Its owner can resume"*, *"Sign in to the correct control plane"*. | **Fix.** Disclosure **Share health and history**. Card **Share health**, button *Check again*, download *Download support file*, description *"The support file has the share's status and server checks only: no local app address, credentials, certificates, reviewer names, app content or cookies."* Facts *Status*, *Connection*, *Server checks* (*Passing* / *Failing*), *Revision*. Reason sentences rewritten in plain words (see code). History card keeps *Share history* with *"Who changed or opened this share, and whether it was allowed. App content, cookies and query strings are never recorded."* |
| P12 | Manage sharing and Publishing help, *Web app compatibility help* | Title vague; body: *"numeric loopback address"*, *"verified HTTPS"*, *"unavailable authority"*, *"connector credentials"*; mentions only the desktop client. | **Fix.** Title **If your app doesn't load for reviewers**. First paragraph: *"Share an app running on this computer at 127.0.0.1 or ::1, over HTTP or HTTPS with a trusted certificate. Keep the CLI or desktop client and your app running."* Last: *"Pausing, expiry or a lost permission ends reviewers' access, including open streams."*; *"publisher credentials"*. Vite example unchanged. |
| P13 | Events tab and share history table (admin) | *Share* column shows 8 UUID characters; filter *"Share ID / Exact share UUID"*; *Reason* *"None recorded"* for every routine event; empty state *"…match these filters in this page."* even with no filters; no-permission text in red. | **Fix.** Share column links to the share page (*"Open share"*, ID kept in its accessible name/title); filter placeholder *"Paste a share ID"*; empty reason shows *"None"* instead of *"None recorded"*; empty state *"No Local Sharing events yet."* without filters, *"No events match these filters."* with; no-permission text neutral (it is not an error the user can fix by retrying). |
| P14 | Access events, Local Sharing record (admin) | *Action* shows the raw code (`beam.access.allowed`); *"Safe reason"* label. | **Fix.** *Action* uses `beamActionLabel`; label *Reason* using `beamWords`. |
| P15 | Sharing policy (admin) | *"Require recent reviewer MFA"* with no explanation; *"Allowed reviewer audience"*; lifetime only in minutes. | **Fix.** Checkbox text *"Require a recent MFA check"* with *"People verify MFA within the last 5 minutes before opening a shared app, reading or sending feedback, or seeing Sharing updates."* Heading **Who publishers can choose as reviewers**. Lifetime shows P2's formatted value. Disabled **Review policy changes** gets a reason line when the values are out of range (*"Lifetime must be 1 to 1440 minutes and shares per publisher 1 to 25."*). |
| P16 | My shares, Saved projects, History (publisher; former publisher) | Disabled **Share a local app**, **Publish X**, **Save a project** have no reason. Mixed nouns *"ended sessions / previews"*. | **Fix.** A reason line next to the toolbar when publishing is not possible: *"Publishing is off: Local Sharing is turned off for this organization."*, *"…isn't available on this server right now."*, *"Your account isn't allowed to publish. An organization admin can change the sharing policy."* History empty state *"No ended shares yet."* / *"Ended shares stay here for reference."* Saved project line *"Local port 3000 · Lasts 1 hour · 1 person and 1 group"* (same counts as P4, publisher excluded). |
| P17 | CLI publish dialog | **Generate command** disabled with no reason until a reviewer is chosen. | **Fix.** Reason line *"Select at least one reviewer to generate the command."* |
| P18 | Domain settings (server admin) | Modal count unpluralized (*"1 active shares across all organizations"*); the *"Verify your email…"* line uses the warning colour. | **Fix** the count (P2). **Kept** the warning colour: it is the reason the whole form is disabled, and warning (not error) is the right tone. Operator vocabulary (DNS, TLS, connector endpoint) is **kept**: the page is for server administrators who run `tunnex-local-sharing` and the terms match its output. |
| P19 | Share states live / paused / offline / expired / stopped / revoked, status pills and sentences | Checked again for all three viewers. | **Kept** (LS-UX-2 L9–L12, LS-UX-3 U7/U8): sentences are neutral, only *Local app unavailable* is red. Filter option *Revoked* is renamed *Ended by a policy change* to match the state label. |
| P20 | Sharing updates panel | Wording fine; MFA recovery covered by P10. | **Kept** apart from P10. |
| P21 | *"N of M share slots in use"* | Understood by publishers; the tooltip explains it. | **Kept.** |

## Deferred

- **Reviewer names in list rows (P4):** needs the reviewer directory per list page or a server
  field with names; counts are enough to scan the list. Revisit if the desktop client's list
  shows names.
- **Desktop-client wording source:** the desktop repo on `main` does not carry these strings; the
  quoted ones from the story were used exactly.

## Tests

`apps/web/test/lsux4beam.test.tsx`: P1/P2 formatter and counts, P3 reviewer summary (publisher
hidden, names, +N more, no-directory counts), P4 list counts, P5 picker hides the publisher and
saves keep their grant, unchanged → disabled with reason, P6 max-lifetime reason replaces the
picker, P7 resume reason, P8 publisher order/badges/reply form, P9 no flash, P10 event / other
tab / focus recheck (and draft never auto-sent), P11–P17 wording. Existing LS-UX-1..3 tests are
updated where they asserted the old wording or toggled the publisher's own grant.
